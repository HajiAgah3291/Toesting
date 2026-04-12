"""
VPN Client

Connects to a VPN server via UDP, performs the handshake, opens a TUN
interface, and forwards packets between the TUN device and the server.

Architecture:
  - Thread A: UDP → TUN  (decrypt inbound, inject to kernel)
  - Thread B: TUN → UDP  (read from kernel, encrypt, send to server)
  - Thread C: Keepalive  (send a heartbeat every KEEPALIVE_INTERVAL seconds)
"""
import logging
import os
import select
import socket
import struct
import threading
import time

from cryptography.exceptions import InvalidTag

from .constants import (
    DATA_HDR_FMT,
    DEFAULT_NETMASK,
    DEFAULT_SERVER_PORT,
    HANDSHAKE_TIMEOUT,
    KEEPALIVE_INTERVAL,
    MSG_CONFIG,
    MSG_DATA,
    MTU,
    VPN_DEVICE_NAME,
)
from .crypto import (
    KeyPair,
    decrypt_packet,
    encrypt_packet,
    derive_session_keys,
    verify_confirmation,
)
from .protocol import (
    build_data_packet,
    build_disconnect,
    build_handshake_init,
    build_keepalive,
    parse_config_payload,
    parse_data_packet,
    parse_handshake_resp,
)
from .session import Session
from .tun import configure_interface, open_tun

log = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when handshake verification fails (possible MITM)."""


class VPNClient:
    def __init__(
        self,
        server_host: str,
        server_port: int = DEFAULT_SERVER_PORT,
        full_tunnel: bool = False,
    ) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.full_tunnel = full_tunnel

        self._server_addr: tuple[str, int] | None = None
        self._session: Session | None = None
        self._tun_fd: int | None = None
        self._tun_name: str = VPN_DEVICE_NAME
        self._udp_sock: socket.socket | None = None
        self._running = False
        self._original_gateway: str | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Resolve server, perform handshake, configure TUN, run threads."""
        # Resolve server hostname once
        server_ip = socket.gethostbyname(self.server_host)
        self._server_addr = (server_ip, self.server_port)
        log.info('Connecting to %s:%d', server_ip, self.server_port)

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.settimeout(HANDSHAKE_TIMEOUT)

        self._connect()

        self._running = True
        threads = [
            threading.Thread(target=self._udp_to_tun_loop, name='udp-rx', daemon=True),
            threading.Thread(target=self._tun_to_udp_loop, name='tun-rx', daemon=True),
            threading.Thread(target=self._keepalive_loop, name='keepalive', daemon=True),
        ]
        for t in threads:
            t.start()
        log.info('VPN tunnel established. Press Ctrl-C to disconnect.')
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        self._running = False
        if self._udp_sock and self._session:
            try:
                self._udp_sock.sendto(build_disconnect(), self._server_addr)
            except OSError:
                pass
        if self._udp_sock:
            self._udp_sock.close()
        if self._tun_fd is not None:
            os.close(self._tun_fd)
        if self.full_tunnel and self._original_gateway:
            try:
                from .routing import restore_default_route
                restore_default_route(self.server_host, self._original_gateway)
            except Exception:
                pass
        log.info('Client stopped')

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        """
        Perform the three-step connection setup:
          1. Send HandshakeInit
          2. Receive HandshakeResp, verify confirmation
          3. Receive CONFIG (assigned VIP), configure TUN
        """
        kp = KeyPair()
        client_nonce = os.urandom(32)

        init_pkt = build_handshake_init(kp.public_bytes, client_nonce)
        self._udp_sock.sendto(init_pkt, self._server_addr)
        log.debug('HandshakeInit sent')

        # Receive HandshakeResp
        data, _ = self._udp_sock.recvfrom(256)
        server_pub, ct_confirm = parse_handshake_resp(data)
        log.debug('HandshakeResp received')

        shared = kp.exchange(server_pub)
        c2s_key, s2c_key = derive_session_keys(shared, client_nonce)

        if not verify_confirmation(s2c_key, ct_confirm, kp.public_bytes, server_pub):
            raise SecurityError(
                'Handshake verification failed — possible man-in-the-middle attack'
            )
        log.debug('Handshake confirmed')

        # Receive CONFIG packet (encrypted DATA with MSG_CONFIG type, seq=0)
        data, _ = self._udp_sock.recvfrom(256)
        msg_type_byte = data[0]
        if msg_type_byte != MSG_CONFIG:
            raise ValueError(f'Expected CONFIG packet, got type 0x{msg_type_byte:02x}')

        seq, config_ct, _ = parse_data_packet(data)
        config_plain = decrypt_packet(s2c_key, seq, config_ct)
        client_vip, server_vip = parse_config_payload(config_plain)
        log.info('Assigned VIP: %s  Server VIP: %s', client_vip, server_vip)

        self._session = Session(
            peer_addr=self._server_addr,
            virtual_ip=client_vip,
            c2s_key=c2s_key,
            s2c_key=s2c_key,
        )
        # seq=0 was the CONFIG, mark it as seen
        self._session.check_replay(0)

        # Switch socket to blocking (infinite timeout) for normal operation
        self._udp_sock.settimeout(None)

        # Open and configure TUN interface
        self._tun_fd, self._tun_name = open_tun(VPN_DEVICE_NAME)
        configure_interface(self._tun_name, client_vip, DEFAULT_NETMASK, MTU)
        log.info('TUN interface %s configured with IP %s', self._tun_name, client_vip)

        # Full tunnel: route all traffic through VPN
        if self.full_tunnel:
            try:
                from .routing import get_default_gateway, set_full_tunnel
                self._original_gateway = get_default_gateway()
                if self._original_gateway:
                    set_full_tunnel(
                        self.server_host,
                        self._original_gateway,
                        server_vip,
                    )
                else:
                    log.warning('Could not determine default gateway; full-tunnel skipped')
            except Exception as exc:
                log.warning('Full-tunnel routing setup failed: %s', exc)

    # ------------------------------------------------------------------
    # Thread A: UDP → TUN
    # ------------------------------------------------------------------

    def _udp_to_tun_loop(self) -> None:
        log.debug('udp-rx thread started')
        while self._running:
            try:
                data, _ = self._udp_sock.recvfrom(65535)
            except OSError:
                break
            if not data:
                continue

            msg_type = data[0]
            if msg_type != MSG_DATA:
                continue

            try:
                seq, ciphertext, _ = parse_data_packet(data)
            except ValueError as exc:
                log.debug('Malformed DATA: %s', exc)
                continue

            if not self._session.check_replay(seq):
                log.debug('Dropped replay seq=%d', seq)
                continue

            try:
                plaintext = decrypt_packet(self._session.s2c_key, seq, ciphertext)
            except InvalidTag:
                log.warning('Authentication failure on received packet')
                continue

            self._session.touch()
            try:
                os.write(self._tun_fd, plaintext)
            except OSError as exc:
                log.error('TUN write error: %s', exc)

    # ------------------------------------------------------------------
    # Thread B: TUN → UDP
    # ------------------------------------------------------------------

    def _tun_to_udp_loop(self) -> None:
        log.debug('tun-rx thread started')
        while self._running:
            try:
                r, _, _ = select.select([self._tun_fd], [], [], 1.0)
            except (ValueError, OSError):
                break
            if not r:
                continue
            try:
                ip_packet = os.read(self._tun_fd, MTU + 100)
            except OSError:
                break

            seq = self._session.next_send_seq()
            try:
                ct = encrypt_packet(self._session.c2s_key, seq, ip_packet)
            except Exception:
                log.exception('Encryption error')
                continue

            pkt = build_data_packet(seq, ct)
            try:
                self._udp_sock.sendto(pkt, self._server_addr)
            except OSError as exc:
                log.warning('UDP send error: %s', exc)

    # ------------------------------------------------------------------
    # Thread C: Keepalive
    # ------------------------------------------------------------------

    def _keepalive_loop(self) -> None:
        log.debug('keepalive thread started')
        while self._running:
            time.sleep(KEEPALIVE_INTERVAL)
            if not self._running:
                break
            try:
                self._udp_sock.sendto(build_keepalive(), self._server_addr)
                log.debug('Keepalive sent')
            except OSError:
                break
