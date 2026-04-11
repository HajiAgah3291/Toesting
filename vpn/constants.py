"""
All numeric constants for the VPN: protocol bytes, ioctl values, network defaults.
"""
import struct

# ---------------------------------------------------------------------------
# Protocol message types
# ---------------------------------------------------------------------------
MSG_HANDSHAKE_INIT = 0x01
MSG_HANDSHAKE_RESP = 0x02
MSG_DATA           = 0x03
MSG_KEEPALIVE      = 0x04
MSG_DISCONNECT     = 0x05
MSG_CONFIG         = 0x06

# Wire format helpers
HEADER_FMT    = '!BH'   # type(1) + payload_len(2)
HEADER_SIZE   = 3
DATA_HDR_FMT  = '!BHQ'  # type(1) + ciphertext_len(2) + seq(8)
DATA_HDR_SIZE = 11

# ---------------------------------------------------------------------------
# Linux TUN ioctl constants (x86-64)
# ---------------------------------------------------------------------------
TUNSETIFF     = 0x400454ca
TUNSETPERSIST = 0x400454cb
IFF_TUN       = 0x0001
IFF_NO_PI     = 0x1000   # no packet information prefix

# ---------------------------------------------------------------------------
# Socket ioctl constants for interface configuration
# ---------------------------------------------------------------------------
SIOCSIFADDR    = 0x8916   # set interface address
SIOCSIFNETMASK = 0x891c   # set interface netmask
SIOCSIFFLAGS   = 0x8914   # set interface flags
SIOCGIFFLAGS   = 0x8913   # get interface flags
SIOCSIFMTU     = 0x8922   # set interface MTU
SIOCADDRT      = 0x890B   # add kernel route
SIOCDELRT      = 0x890C   # delete kernel route

# Interface flags
IFF_UP      = 0x0001
IFF_RUNNING = 0x0040

# Route flags
RTF_UP      = 0x0001
RTF_GATEWAY = 0x0002

# ---------------------------------------------------------------------------
# Network defaults
# ---------------------------------------------------------------------------
DEFAULT_SERVER_PORT = 51820
DEFAULT_SUBNET      = '10.8.0.0'
DEFAULT_PREFIX_LEN  = 24
DEFAULT_NETMASK     = '255.255.255.0'
SERVER_VIP          = '10.8.0.1'
VPN_DEVICE_NAME     = 'vpn0'

# Inner MTU: 1500 - 20 (outer IP) - 8 (UDP) - 11 (DATA header) - 16 (Poly1305 tag)
MTU = 1420

# ---------------------------------------------------------------------------
# Session / timing
# ---------------------------------------------------------------------------
KEEPALIVE_INTERVAL  = 15    # seconds between client keepalive packets
HANDSHAKE_TIMEOUT   = 10    # seconds to wait for handshake response
SESSION_IDLE_CUTOFF = 120   # seconds before a silent session is reaped
REAPER_INTERVAL     = 30    # seconds between server reaper runs
REPLAY_WINDOW       = 64    # reject packets older than this many seq numbers

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------
HKDF_INFO      = b'vpn-v1-session-keys'
HKDF_KEY_LEN   = 64    # 32 bytes c2s + 32 bytes s2c
NONCE_PREFIX   = b'\x00\x00\x00\x00'   # 4 zero bytes; nonce = prefix + uint64 seq
CONFIRM_NONCE  = b'\x00' * 12          # fixed nonce for handshake confirmation
