"""
Wire format: pack and unpack for all VPN message types.

All functions are pure bytes operations — no I/O, no crypto.
Raises ValueError on malformed input.

Message layout recap:
  HandshakeInit  (67 bytes): type(1) + len(2)[=64] + client_pub(32) + nonce(32)
  HandshakeResp  (83 bytes): type(1) + len(2)[=80] + server_pub(32) + confirm(48)
  DataPacket     (11+N bytes): type(1) + ct_len(2) + seq(8) + ciphertext(N)
  Config         (11+8 bytes): encoded as DataPacket with seq=0, plaintext=8 bytes
  Keepalive      (3 bytes):  type(1) + len(2)[=0]
  Disconnect     (3 bytes):  type(1) + len(2)[=0]
"""
import socket
import struct

from .constants import (
    DATA_HDR_FMT,
    DATA_HDR_SIZE,
    HEADER_FMT,
    HEADER_SIZE,
    MSG_DATA,
    MSG_DISCONNECT,
    MSG_HANDSHAKE_INIT,
    MSG_HANDSHAKE_RESP,
    MSG_KEEPALIVE,
    MSG_CONFIG,
)

# ---------------------------------------------------------------------------
# HandshakeInit
# ---------------------------------------------------------------------------

def build_handshake_init(client_pub: bytes, client_nonce: bytes) -> bytes:
    """
    Build a 67-byte HandshakeInit packet.

    Args:
        client_pub:   32-byte X25519 public key
        client_nonce: 32-byte random salt (used in HKDF)
    """
    if len(client_pub) != 32:
        raise ValueError(f'client_pub must be 32 bytes, got {len(client_pub)}')
    if len(client_nonce) != 32:
        raise ValueError(f'client_nonce must be 32 bytes, got {len(client_nonce)}')
    return struct.pack(HEADER_FMT, MSG_HANDSHAKE_INIT, 64) + client_pub + client_nonce


def parse_handshake_init(data: bytes) -> tuple[bytes, bytes]:
    """
    Parse a HandshakeInit packet.

    Returns:
        (client_pub, client_nonce) — each 32 bytes.

    Raises:
        ValueError: on wrong length or wrong message type.
    """
    if len(data) != 67:
        raise ValueError(f'HandshakeInit must be 67 bytes, got {len(data)}')
    msg_type, payload_len = struct.unpack_from(HEADER_FMT, data, 0)
    if msg_type != MSG_HANDSHAKE_INIT:
        raise ValueError(f'Expected MSG_HANDSHAKE_INIT (0x01), got 0x{msg_type:02x}')
    if payload_len != 64:
        raise ValueError(f'HandshakeInit payload_len must be 64, got {payload_len}')
    return data[HEADER_SIZE:HEADER_SIZE + 32], data[HEADER_SIZE + 32:HEADER_SIZE + 64]


# ---------------------------------------------------------------------------
# HandshakeResp
# ---------------------------------------------------------------------------

def build_handshake_resp(server_pub: bytes, ct_confirmation: bytes) -> bytes:
    """
    Build an 83-byte HandshakeResp packet.

    Args:
        server_pub:       32-byte X25519 public key
        ct_confirmation:  48-byte encrypted confirmation (from crypto.encrypt_confirmation)
    """
    if len(server_pub) != 32:
        raise ValueError(f'server_pub must be 32 bytes, got {len(server_pub)}')
    if len(ct_confirmation) != 48:
        raise ValueError(f'ct_confirmation must be 48 bytes, got {len(ct_confirmation)}')
    return struct.pack(HEADER_FMT, MSG_HANDSHAKE_RESP, 80) + server_pub + ct_confirmation


def parse_handshake_resp(data: bytes) -> tuple[bytes, bytes]:
    """
    Parse a HandshakeResp packet.

    Returns:
        (server_pub, ct_confirmation) — 32 and 48 bytes.

    Raises:
        ValueError: on wrong length or wrong message type.
    """
    if len(data) != 83:
        raise ValueError(f'HandshakeResp must be 83 bytes, got {len(data)}')
    msg_type, payload_len = struct.unpack_from(HEADER_FMT, data, 0)
    if msg_type != MSG_HANDSHAKE_RESP:
        raise ValueError(f'Expected MSG_HANDSHAKE_RESP (0x02), got 0x{msg_type:02x}')
    if payload_len != 80:
        raise ValueError(f'HandshakeResp payload_len must be 80, got {payload_len}')
    return data[HEADER_SIZE:HEADER_SIZE + 32], data[HEADER_SIZE + 32:HEADER_SIZE + 80]


# ---------------------------------------------------------------------------
# DataPacket  (also used for MSG_CONFIG with seq=0)
# ---------------------------------------------------------------------------

def build_data_packet(seq: int, ciphertext: bytes, msg_type: int = MSG_DATA) -> bytes:
    """
    Build a DATA (or CONFIG) packet.

    Args:
        seq:        uint64 sequence number
        ciphertext: encrypted payload (plaintext + 16-byte Poly1305 tag)
        msg_type:   MSG_DATA (default) or MSG_CONFIG

    Returns:
        11 + len(ciphertext) bytes.
    """
    ct_len = len(ciphertext)
    return struct.pack(DATA_HDR_FMT, msg_type, ct_len, seq) + ciphertext


def parse_data_packet(data: bytes) -> tuple[int, bytes, int]:
    """
    Parse a DATA or CONFIG packet.

    Returns:
        (seq, ciphertext, msg_type)

    Raises:
        ValueError: on truncation, length mismatch, or wrong message type.
    """
    if len(data) < DATA_HDR_SIZE:
        raise ValueError(f'Packet too short: {len(data)} bytes (min {DATA_HDR_SIZE})')
    msg_type, ct_len, seq = struct.unpack_from(DATA_HDR_FMT, data, 0)
    if msg_type not in (MSG_DATA, MSG_CONFIG):
        raise ValueError(f'Expected MSG_DATA/MSG_CONFIG, got 0x{msg_type:02x}')
    expected_total = DATA_HDR_SIZE + ct_len
    if len(data) != expected_total:
        raise ValueError(
            f'Length mismatch: header says {expected_total}, got {len(data)}'
        )
    return seq, data[DATA_HDR_SIZE:], msg_type


# ---------------------------------------------------------------------------
# Config payload (sent as an encrypted DataPacket with seq=0)
# ---------------------------------------------------------------------------

def build_config_payload(client_vip: str, server_vip: str) -> bytes:
    """
    Build the 8-byte plaintext for a CONFIG message.

    Args:
        client_vip: IP string assigned to this client (e.g. '10.8.0.2')
        server_vip: Server's VPN IP (e.g. '10.8.0.1')
    """
    return socket.inet_aton(client_vip) + socket.inet_aton(server_vip)


def parse_config_payload(payload: bytes) -> tuple[str, str]:
    """
    Parse the 8-byte CONFIG plaintext.

    Returns:
        (client_vip, server_vip) as dotted-decimal strings.
    """
    if len(payload) != 8:
        raise ValueError(f'Config payload must be 8 bytes, got {len(payload)}')
    client_vip = socket.inet_ntoa(payload[:4])
    server_vip = socket.inet_ntoa(payload[4:])
    return client_vip, server_vip


# ---------------------------------------------------------------------------
# Keepalive / Disconnect
# ---------------------------------------------------------------------------

def build_keepalive() -> bytes:
    """Build a 3-byte keepalive packet."""
    return struct.pack(HEADER_FMT, MSG_KEEPALIVE, 0)


def build_disconnect() -> bytes:
    """Build a 3-byte disconnect packet."""
    return struct.pack(HEADER_FMT, MSG_DISCONNECT, 0)
