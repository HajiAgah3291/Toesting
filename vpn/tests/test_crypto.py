"""
Unit tests for vpn/crypto.py — no root, no network, no TUN required.
"""
import os
import struct

import pytest
from cryptography.exceptions import InvalidTag

from vpn.crypto import (
    KeyPair,
    decrypt_packet,
    encrypt_confirmation,
    encrypt_packet,
    derive_session_keys,
    verify_confirmation,
)
from vpn.session import Session


class TestKeyPair:
    def test_generates_32_byte_public_key(self):
        kp = KeyPair()
        assert len(kp.public_bytes) == 32

    def test_exchange_produces_same_shared_secret(self):
        kp_a = KeyPair()
        kp_b = KeyPair()
        shared_ab = kp_a.exchange(kp_b.public_bytes)
        shared_ba = kp_b.exchange(kp_a.public_bytes)
        assert shared_ab == shared_ba

    def test_shared_secret_is_32_bytes(self):
        kp_a = KeyPair()
        kp_b = KeyPair()
        assert len(kp_a.exchange(kp_b.public_bytes)) == 32

    def test_different_keypairs_produce_different_secrets(self):
        kp_a = KeyPair()
        kp_b = KeyPair()
        kp_c = KeyPair()
        assert kp_a.exchange(kp_b.public_bytes) != kp_a.exchange(kp_c.public_bytes)


class TestDeriveSessionKeys:
    def test_both_sides_derive_same_keys(self):
        kp_client = KeyPair()
        kp_server = KeyPair()
        salt = os.urandom(32)

        shared_c = kp_client.exchange(kp_server.public_bytes)
        shared_s = kp_server.exchange(kp_client.public_bytes)

        c2s_c, s2c_c = derive_session_keys(shared_c, salt)
        c2s_s, s2c_s = derive_session_keys(shared_s, salt)

        assert c2s_c == c2s_s
        assert s2c_c == s2c_s

    def test_keys_are_32_bytes(self):
        kp_a = KeyPair()
        kp_b = KeyPair()
        shared = kp_a.exchange(kp_b.public_bytes)
        c2s, s2c = derive_session_keys(shared, os.urandom(32))
        assert len(c2s) == 32
        assert len(s2c) == 32

    def test_different_salts_produce_different_keys(self):
        kp_a = KeyPair()
        kp_b = KeyPair()
        shared = kp_a.exchange(kp_b.public_bytes)
        c2s_1, _ = derive_session_keys(shared, os.urandom(32))
        c2s_2, _ = derive_session_keys(shared, os.urandom(32))
        assert c2s_1 != c2s_2


class TestEncryptDecrypt:
    def setup_method(self):
        self.key = os.urandom(32)

    def test_roundtrip_small_payload(self):
        plain = b'Hello, VPN!'
        ct = encrypt_packet(self.key, seq=1, plaintext=plain)
        assert decrypt_packet(self.key, seq=1, ciphertext=ct) == plain

    def test_roundtrip_empty_payload(self):
        ct = encrypt_packet(self.key, seq=0, plaintext=b'')
        assert decrypt_packet(self.key, seq=0, ciphertext=ct) == b''

    def test_roundtrip_mtu_sized_payload(self):
        plain = os.urandom(1420)
        ct = encrypt_packet(self.key, seq=999, plaintext=plain)
        assert decrypt_packet(self.key, seq=999, ciphertext=ct) == plain

    def test_ciphertext_is_16_bytes_longer(self):
        plain = os.urandom(100)
        ct = encrypt_packet(self.key, seq=1, plaintext=plain)
        assert len(ct) == len(plain) + 16

    def test_wrong_seq_fails_auth(self):
        plain = b'test'
        ct = encrypt_packet(self.key, seq=5, plaintext=plain)
        with pytest.raises(InvalidTag):
            decrypt_packet(self.key, seq=6, ciphertext=ct)

    def test_wrong_key_fails_auth(self):
        plain = b'test'
        ct = encrypt_packet(self.key, seq=1, plaintext=plain)
        with pytest.raises(InvalidTag):
            decrypt_packet(os.urandom(32), seq=1, ciphertext=ct)

    def test_tampered_ciphertext_fails_auth(self):
        plain = b'test data'
        ct = bytearray(encrypt_packet(self.key, seq=1, plaintext=plain))
        ct[0] ^= 0xFF  # flip first byte
        with pytest.raises(InvalidTag):
            decrypt_packet(self.key, seq=1, ciphertext=bytes(ct))

    def test_multiple_sequence_numbers(self):
        for seq in [0, 1, 100, 2**32, 2**63]:
            plain = os.urandom(50)
            ct = encrypt_packet(self.key, seq=seq, plaintext=plain)
            assert decrypt_packet(self.key, seq=seq, ciphertext=ct) == plain


class TestHandshakeConfirmation:
    def test_verify_confirmation_roundtrip(self):
        kp_server = KeyPair()
        kp_client = KeyPair()
        key = os.urandom(32)
        aad = kp_client.public_bytes

        ct = encrypt_confirmation(key, kp_server.public_bytes, aad)
        assert len(ct) == 48
        assert verify_confirmation(key, ct, aad, kp_server.public_bytes)

    def test_wrong_key_fails(self):
        kp = KeyPair()
        key = os.urandom(32)
        ct = encrypt_confirmation(key, kp.public_bytes, b'\x00' * 32)
        assert not verify_confirmation(os.urandom(32), ct, b'\x00' * 32, kp.public_bytes)

    def test_wrong_expected_pub_fails(self):
        kp = KeyPair()
        key = os.urandom(32)
        aad = b'\x00' * 32
        ct = encrypt_confirmation(key, kp.public_bytes, aad)
        assert not verify_confirmation(key, ct, aad, os.urandom(32))


class TestReplayWindow:
    def _make_session(self) -> Session:
        return Session(
            peer_addr=('127.0.0.1', 1234),
            virtual_ip='10.8.0.2',
            c2s_key=os.urandom(32),
            s2c_key=os.urandom(32),
        )

    def test_first_packet_accepted(self):
        s = self._make_session()
        assert s.check_replay(0) is True

    def test_same_seq_rejected(self):
        s = self._make_session()
        s.check_replay(5)
        assert s.check_replay(5) is False

    def test_old_seq_outside_window_rejected(self):
        s = self._make_session()
        s.check_replay(100)
        assert s.check_replay(0) is False  # 100 away, outside window of 64

    def test_seq_within_window_accepted(self):
        s = self._make_session()
        s.check_replay(10)
        assert s.check_replay(5) is True   # 5 away, inside window

    def test_out_of_order_accepted(self):
        s = self._make_session()
        s.check_replay(3)
        s.check_replay(1)
        s.check_replay(2)
        # All unique, all within window
        assert s.check_replay(3) is False  # already seen
        assert s.check_replay(1) is False  # already seen

    def test_advancing_window(self):
        s = self._make_session()
        for i in range(200):
            assert s.check_replay(i) is True
        # Old packet now outside window
        assert s.check_replay(0) is False
