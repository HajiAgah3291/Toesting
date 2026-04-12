"""
VPN Server

Accepts UDP connections from clients, performs the handshake, assigns
virtual IPs, and forwards encrypted packets between the TUN interface
and connected peers.

Architecture:
  - Thread A: UDP → TUN  (decrypt inbound, inject to kernel)
  - Thread B: TUN → UDP  (read from kernel, encrypt, forward to peer)
  - Thread C: Session reaper (evict idle sessions, reclaim VIPs)
"""
import ipaddress
import logging
import os
import select
import signal
import socket
import threading
import time

from cryptography.exceptions import InvalidTag

from .constants import (
    DEFAULT_NETMASK,
    DEFAULT_PREFIX_LEN,
    DEFAULT_SERVER_PORT,
    DEFAULT_SUBNET,
    KEEPALIVE_INTERVAL,
    MSG_CONFIG,
    MSG_DATA,
    MSG_DISCONNECT,
    MSG_HANDSHAKE_INIT,
    MSG_KEEPALIVE,
    MTU,
    REAPER_INTERVAL,
    SERVER_VIP,
    SESSION_IDLE_CUTOFF,
    VPN_DEVICE_NAME,
)
from .crypto import (
    KeyPair,
    decrypt_packet,
    encrypt_confirmation,
    encrypt_packet,
    derive_session_keys,
)
from .protocol import (
    build_config_payload,
    build_data_packet,
    build_handshake_resp,
    parse_data_packet,
    parse_handshake_init,
)
from .session import Session
from .tun import configure_interface, open_tun

log = logging.getLogger(__name__)


class IPAddressPool:
    """Hands out host addresses from a subnet, reserving .1 for the server."""

    def __init__(self, base: str = DEFAULT_SUBNET, prefix: int = DEFAULT_PREFIX_LEN) -> None:
        network = ipaddress.IPv4Network(f'{base}/{prefix}', strict=False)
        # hosts() excludes network and broadcast; skip .1 (server VIP)
        all_hosts = [str(h) for h in network.hosts()]
        self._available: list[str] = [h for h in all_hosts if h != SERVER_VIP]
        self._allocated: set[str] = set()
        self._lock = threading.Lock()

    def allocate(self) -> str:
        with self._lock:
            if not self._available:
                raise RuntimeError('VIP pool exhausted')
            ip = self._available.pop(0)
            self._allocated.add(ip)
            return ip

    def release(self, ip: str) -> None:
        with self._lock:
            if ip in self._allocated:
                self._allocated.discard(ip)
                self._available.append(ip)


class VPNServer:
    def __init__(
        self,
        bind_addr: str = '0.0.0.0',
        port: int = DEFAULT_SERVER_PORT,
        subnet: str = DEFAULT_SUBNET,
        prefix: int = DEFAULT_PREFIX_LEN,
        wan_iface: str = 'eth0',
        enable_nat: bool = True,
    ) -> None:
        self.bind_addr   = bind_addr
        self.port        = port
        self.subnet      = subnet
        self.prefix      = prefix
        self.wan_iface   = wan_iface
        self.enable_nat  = enable_nat
        self.subnet_cidr = f'{subnet}/{prefix}'

        self._sessions:   dict[tuple, Session] = {}   # peer_addr → Session
        self._vip_to_peer: dict[str, tuple]    = {}   # virtual_ip → peer_addr
        self._lock = threading.Lock()

        self._ip_pool = IPAddressPool(subnet, prefix)
        self._running = False
        self._tun_fd: int | None = None
        self._udp_sock: socket.socket | None = None
        self._tun_name: str = VPN_DEVICE_NAME

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Open TUN, bind UDP socket, configure networking, start threads."""
        log.info('Opening TUN device...')
        self._tun_fd, self._tun_name = open_tun(VPN_DEVICE_NAME)
        configure_interface(self._tun_name, SERVER_VIP, DEFAULT_NETMASK, MTU)
        log.info('TUN interface %s configured with IP %s', self._tun_name, SERVER_VIP)

        if self.enable_nat:
            try:
                from .routing import enable_ip_forwarding, setup_nat
                enable_ip_forwarding()
                setup_nat(self._tun_name, self.wan_iface, self.subnet_cidr)
            except Exception as exc:
                log.warning('NAT setup failed (continuing anyway): %s', exc)

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_sock.bind((self.bind_addr, self.port))
        log.info('Listening on UDP %s:%d', self.bind_addr, self.port)

        self._running = True
        threads = [
            threading.Thread(target=self._udp_to_tun_loop, name='udp-rx', daemon=True),
            threading.Thread(target=self._tun_to_udp_loop, name='tun-rx', daemon=True),
            threading.Thread(target=self._reaper_loop, name='reaper', daemon=True),
        ]
        for t in threads:
            t.start()
        log.info('Server running. Press Ctrl-C to stop.')
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        self._running = False
        if self._udp_sock:
            self._udp_sock.close()
        if self._tun_fd is not None:
            os.close(self._tun_fd)
        if self.enable_nat:
            try:
                from .routing import teardown_nat, disable_ip_forwarding
                teardown_nat(self._tun_name, self.wan_iface, self.subnet_cidr)
                disable_ip_forwarding()
            except Exception:
                pass
        log.info('Server stopped')

    # ------------------------------------------------------------------
    # Thread A: UDP → TUN
    # ------------------------------------------------------------------

    def _udp_to_tun_loop(self) -> None:
        log.debug('udp-rx thread started')
        while self._running:
            try:
                data, addr = self._udp_sock.recvfrom(65535)
            except OSError:
                break
            if not data:
                continue

            msg_type = data[0]
            try:
                if msg_type == MSG_HANDSHAKE_INIT:
                    self._handle_handshake_init(data, addr)
                elif msg_type == MSG_DATA:
                    self._handle_data_inbound(data, addr)
                elif msg_type == MSG_KEEPALIVE:
                    self._handle_keepalive(addr)
                elif msg_type == MSG_DISCONNECT:
                    self._teardown_session(addr)
                else:
                    log.debug('Unknown message type 0x%02x from %s', msg_type, addr)
            except Exception:
                log.exception('Error processing packet from %s', addr)

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
            if len(ip_packet) < 20:
                continue

            # Extract destination IP from IP header bytes 16-20
            dst_ip = socket.inet_ntoa(ip_packet[16:20])

            with self._lock:
                peer_addr = self._vip_to_peer.get(dst_ip)
                if peer_addr is None:
                    continue
                session = self._sessions.get(peer_addr)
                if session is None:
                    continue

            seq = session.next_send_seq()
            try:
                ct = encrypt_packet(session.s2c_key, seq, ip_packet)
            except Exception:
                log.exception('Encryption error')
                continue

            pkt = build_data_packet(seq, ct)
            try:
                self._udp_sock.sendto(pkt, peer_addr)
            except OSError:
                log.warning('Failed to send to %s', peer_addr)

    # ------------------------------------------------------------------
    # Thread C: Session reaper
    # ------------------------------------------------------------------

    def _reaper_loop(self) -> None:
        log.debug('reaper thread started')
        while self._running:
            time.sleep(REAPER_INTERVAL)
            now = time.monotonic()
            evict = []
            with self._lock:
                for addr, session in self._sessions.items():
                    if now - session.last_seen > SESSION_IDLE_CUTOFF:
                        evict.append(addr)
            for addr in evict:
                log.info('Reaping idle session %s', addr)
                self._teardown_session(addr)

    # ------------------------------------------------------------------
    # Handshake handling
    # ------------------------------------------------------------------

    def _handle_handshake_init(self, data: bytes, addr: tuple) -> None:
        try:
            client_pub, client_nonce = parse_handshake_init(data)
        except ValueError as exc:
            log.warning('Bad HandshakeInit from %s: %s', addr, exc)
            return

        kp = KeyPair()
        shared = kp.exchange(client_pub)
        c2s_key, s2c_key = derive_session_keys(shared, client_nonce)

        ct_confirm = encrypt_confirmation(s2c_key, kp.public_bytes, client_pub)
        resp = build_handshake_resp(kp.public_bytes, ct_confirm)

        try:
            vip = self._ip_pool.allocate()
        except RuntimeError:
            log.error('VIP pool exhausted, rejecting %s', addr)
            return

        session = Session(
            peer_addr=addr,
            virtual_ip=vip,
            c2s_key=c2s_key,
            s2c_key=s2c_key,
        )
        with self._lock:
            # Clean up any previous session from this address
            if addr in self._sessions:
                old_vip = self._sessions[addr].virtual_ip
                self._vip_to_peer.pop(old_vip, None)
                self._ip_pool.release(old_vip)
            self._sessions[addr] = session
            self._vip_to_peer[vip] = addr

        # Send HandshakeResp
        self._udp_sock.sendto(resp, addr)

        # Send CONFIG: assigned VIP and server VIP, encrypted with seq=0
        config_plain = build_config_payload(vip, SERVER_VIP)
        config_ct = encrypt_packet(s2c_key, 0, config_plain)
        # Use MSG_CONFIG type
        import struct
        from .constants import DATA_HDR_FMT, MSG_CONFIG
        config_pkt = struct.pack(DATA_HDR_FMT, MSG_CONFIG, len(config_ct), 0) + config_ct
        self._udp_sock.sendto(config_pkt, addr)

        log.info('New session: %s ↔ VIP %s', addr, vip)

    def _handle_data_inbound(self, data: bytes, addr: tuple) -> None:
        with self._lock:
            session = self._sessions.get(addr)
        if session is None:
            log.debug('DATA from unknown peer %s', addr)
            return

        try:
            seq, ciphertext, _ = parse_data_packet(data)
        except ValueError as exc:
            log.debug('Malformed DATA from %s: %s', addr, exc)
            return

        if not session.check_replay(seq):
            log.debug('Dropped replay seq=%d from %s', seq, addr)
            return

        try:
            plaintext = decrypt_packet(session.c2s_key, seq, ciphertext)
        except InvalidTag:
            log.warning('Authentication failure for packet from %s', addr)
            return

        session.touch()
        try:
            os.write(self._tun_fd, plaintext)
        except OSError as exc:
            log.error('TUN write error: %s', exc)

    def _handle_keepalive(self, addr: tuple) -> None:
        with self._lock:
            session = self._sessions.get(addr)
        if session:
            session.touch()
            log.debug('Keepalive from %s', addr)

    def _teardown_session(self, addr: tuple) -> None:
        with self._lock:
            session = self._sessions.pop(addr, None)
            if session:
                self._vip_to_peer.pop(session.virtual_ip, None)
                self._ip_pool.release(session.virtual_ip)
        if session:
            log.info('Session torn down: %s (VIP %s)', addr, session.virtual_ip)
