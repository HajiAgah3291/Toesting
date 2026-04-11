"""
Unit tests for vpn/protocol.py — no root, no network, no TUN required.
"""
import os
import struct

import pytest

from vpn.protocol import (
    build_config_payload,
    build_data_packet,
    build_disconnect,
    build_handshake_init,
    build_handshake_resp,
    build_keepalive,
    parse_config_payload,
    parse_data_packet,
    parse_handshake_init,
    parse_handshake_resp,
)
from vpn.constants import (
    MSG_HANDSHAKE_INIT,
    MSG_HANDSHAKE_RESP,
    MSG_DATA,
    MSG_KEEPALIVE,
    MSG_DISCONNECT,
)


class TestHandshakeInit:
    def test_size_is_67(self):
        pkt = build_handshake_init(b'A' * 32, b'B' * 32)
        assert len(pkt) == 67

    def test_first_byte_is_type(self):
        pkt = build_handshake_init(b'A' * 32, b'B' * 32)
        assert pkt[0] == MSG_HANDSHAKE_INIT

    def test_roundtrip(self):
        pub   = os.urandom(32)
        nonce = os.urandom(32)
        pkt   = build_handshake_init(pub, nonce)
        got_pub, got_nonce = parse_handshake_init(pkt)
        assert got_pub   == pub
        assert got_nonce == nonce

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError):
            parse_handshake_init(b'\x01' * 66)

    def test_wrong_type_raises(self):
        pkt = bytearray(build_handshake_init(b'A' * 32, b'B' * 32))
        pkt[0] = 0x99
        with pytest.raises(ValueError):
            parse_handshake_init(bytes(pkt))

    def test_wrong_pub_size_raises(self):
        with pytest.raises(ValueError):
            build_handshake_init(b'short', b'B' * 32)


class TestHandshakeResp:
    def test_size_is_83(self):
        pkt = build_handshake_resp(b'S' * 32, b'C' * 48)
        assert len(pkt) == 83

    def test_first_byte_is_type(self):
        pkt = build_handshake_resp(b'S' * 32, b'C' * 48)
        assert pkt[0] == MSG_HANDSHAKE_RESP

    def test_roundtrip(self):
        pub    = os.urandom(32)
        ct_cfm = os.urandom(48)
        pkt    = build_handshake_resp(pub, ct_cfm)
        got_pub, got_ct = parse_handshake_resp(pkt)
        assert got_pub == pub
        assert got_ct  == ct_cfm

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError):
            parse_handshake_resp(b'\x02' * 82)

    def test_wrong_confirm_size_raises(self):
        with pytest.raises(ValueError):
            build_handshake_resp(b'S' * 32, b'C' * 47)


class TestDataPacket:
    def test_roundtrip(self):
        ct = os.urandom(100)
        pkt = build_data_packet(seq=42, ciphertext=ct)
        seq, got_ct, msg_type = parse_data_packet(pkt)
        assert seq    == 42
        assert got_ct == ct
        assert msg_type == MSG_DATA

    def test_header_size(self):
        pkt = build_data_packet(seq=0, ciphertext=b'X' * 50)
        assert len(pkt) == 11 + 50

    def test_seq_zero(self):
        ct = os.urandom(16)
        pkt = build_data_packet(seq=0, ciphertext=ct)
        seq, got_ct, _ = parse_data_packet(pkt)
        assert seq == 0

    def test_large_seq(self):
        ct = os.urandom(16)
        big_seq = 2**63
        pkt = build_data_packet(seq=big_seq, ciphertext=ct)
        seq, got_ct, _ = parse_data_packet(pkt)
        assert seq == big_seq

    def test_truncated_raises(self):
        with pytest.raises(ValueError):
            parse_data_packet(b'\x03\x00\x10')  # too short for 11-byte header

    def test_length_mismatch_raises(self):
        # Build a valid packet then truncate it
        pkt = build_data_packet(seq=1, ciphertext=b'X' * 20)
        with pytest.raises(ValueError):
            parse_data_packet(pkt[:-1])

    def test_wrong_type_raises(self):
        # Keepalive packet passed to parse_data_packet
        with pytest.raises(ValueError):
            parse_data_packet(build_keepalive())


class TestConfigPayload:
    def test_roundtrip(self):
        client_vip = '10.8.0.5'
        server_vip = '10.8.0.1'
        payload = build_config_payload(client_vip, server_vip)
        assert len(payload) == 8
        got_client, got_server = parse_config_payload(payload)
        assert got_client == client_vip
        assert got_server == server_vip

    def test_wrong_size_raises(self):
        with pytest.raises(ValueError):
            parse_config_payload(b'\x00' * 7)


class TestKeepaliveDisconnect:
    def test_keepalive_size_and_type(self):
        pkt = build_keepalive()
        assert len(pkt) == 3
        assert pkt[0] == MSG_KEEPALIVE

    def test_disconnect_size_and_type(self):
        pkt = build_disconnect()
        assert len(pkt) == 3
        assert pkt[0] == MSG_DISCONNECT
