"""
All cryptographic operations for the VPN.

Provides:
  - KeyPair          : X25519 ephemeral keypair generation and DH exchange
  - derive_session_keys : HKDF-SHA256 to produce c2s and s2c symmetric keys
  - encrypt_packet / decrypt_packet : ChaCha20-Poly1305 for DATA packets
  - encrypt_confirmation / verify_confirmation : handshake authentication
"""
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import (
    CONFIRM_NONCE,
    HKDF_INFO,
    HKDF_KEY_LEN,
    NONCE_PREFIX,
)


class KeyPair:
    """Ephemeral X25519 keypair. Generate once per session."""

    def __init__(self) -> None:
        self._priv: X25519PrivateKey = X25519PrivateKey.generate()
        self.public_bytes: bytes = self._priv.public_key().public_bytes_raw()

    def exchange(self, peer_pub_bytes: bytes) -> bytes:
        """
        Perform Diffie-Hellman with the peer's raw 32-byte public key.
        Returns the 32-byte shared secret.
        """
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        return self._priv.exchange(peer_pub)


def derive_session_keys(
    shared_secret: bytes, salt: bytes
) -> tuple[bytes, bytes]:
    """
    Derive two 32-byte session keys from the DH shared secret.

    Args:
        shared_secret: 32-byte output of X25519 DH exchange
        salt:          32-byte client_nonce from HandshakeInit

    Returns:
        (c2s_key, s2c_key) — each 32 bytes.
        c2s_key encrypts traffic from client → server.
        s2c_key encrypts traffic from server → client.
    """
    key_material = HKDF(
        algorithm=SHA256(),
        length=HKDF_KEY_LEN,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)
    return key_material[:32], key_material[32:]


def _make_nonce(seq: int) -> bytes:
    """Build a 12-byte ChaCha20-Poly1305 nonce from a sequence number."""
    return NONCE_PREFIX + struct.pack('!Q', seq)


def encrypt_packet(key: bytes, seq: int, plaintext: bytes) -> bytes:
    """
    Encrypt an IP packet for transmission.

    Args:
        key:       32-byte symmetric key (c2s or s2c)
        seq:       Monotonically increasing sequence number (used as nonce)
        plaintext: Raw IP packet bytes

    Returns:
        Ciphertext: len(plaintext) + 16 bytes (Poly1305 authentication tag)
    """
    return ChaCha20Poly1305(key).encrypt(_make_nonce(seq), plaintext, None)


def decrypt_packet(key: bytes, seq: int, ciphertext: bytes) -> bytes:
    """
    Decrypt a received DATA ciphertext.

    Args:
        key:        32-byte symmetric key (c2s or s2c)
        seq:        Sequence number from packet header
        ciphertext: Raw ciphertext (including 16-byte tag)

    Returns:
        Plaintext IP packet bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    return ChaCha20Poly1305(key).decrypt(_make_nonce(seq), ciphertext, None)


def encrypt_confirmation(
    s2c_key: bytes, server_pub: bytes, aad: bytes
) -> bytes:
    """
    Produce the 48-byte encrypted confirmation in HandshakeResp.

    Encrypts server_pub (32 bytes) → ciphertext (48 bytes = 32 + 16 tag).
    The client verifies that the decrypted plaintext equals server_pub,
    proving the server holds the corresponding private key.

    Args:
        s2c_key:    Derived server→client key
        server_pub: Server's ephemeral public key (32 bytes)
        aad:        Additional authenticated data = client_pub (32 bytes)
    """
    return ChaCha20Poly1305(s2c_key).encrypt(CONFIRM_NONCE, server_pub, aad)


def verify_confirmation(
    s2c_key: bytes,
    ciphertext: bytes,
    aad: bytes,
    expected_pub: bytes,
) -> bool:
    """
    Verify the server's handshake confirmation on the client side.

    Returns True if the ciphertext decrypts to expected_pub, False otherwise.
    Never raises — authentication failures return False.
    """
    try:
        plaintext = ChaCha20Poly1305(s2c_key).decrypt(
            CONFIRM_NONCE, ciphertext, aad
        )
        return plaintext == expected_pub
    except Exception:
        return False
