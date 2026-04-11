"""
Session state for a single VPN peer.

Tracks crypto keys, sequence numbers, and an anti-replay sliding window.
"""
import time
from dataclasses import dataclass, field
from enum import Enum, auto

from .constants import REPLAY_WINDOW


class SessionState(Enum):
    IDLE         = auto()
    HANDSHAKING  = auto()
    ESTABLISHED  = auto()
    DEAD         = auto()


@dataclass
class Session:
    """All runtime state for one VPN peer connection."""

    peer_addr:    tuple        # (ip_str, port) of the remote UDP endpoint
    virtual_ip:   str          # assigned VPN IP, e.g. '10.8.0.2'
    c2s_key:      bytes        # 32-byte key: client → server direction
    s2c_key:      bytes        # 32-byte key: server → client direction
    state:        SessionState = SessionState.ESTABLISHED

    # Transmit side
    send_seq:     int = 0      # next sequence number to use when sending

    # Receive side — sliding window anti-replay
    recv_seq_max:    int = -1  # highest seq number seen so far (-1 = nothing seen)
    replay_window:   int = 0   # bitmask: bit i means (recv_seq_max - i) was received

    # Health tracking
    last_seen: float = field(default_factory=time.monotonic)

    # ------------------------------------------------------------------
    # Anti-replay sliding window
    # ------------------------------------------------------------------

    def check_replay(self, seq: int) -> bool:
        """
        Check whether seq is a new, acceptable packet.

        Uses a REPLAY_WINDOW-wide bitmask. Returns True and updates the
        window if the packet should be accepted; returns False if it is a
        replay or is too old.
        """
        if self.recv_seq_max == -1:
            # First packet ever
            self.recv_seq_max = seq
            self.replay_window = 1
            return True

        if seq > self.recv_seq_max:
            # New highest sequence: slide the window forward
            shift = seq - self.recv_seq_max
            if shift >= REPLAY_WINDOW:
                # Jump so large the old window is completely displaced
                self.replay_window = 1
            else:
                self.replay_window = ((self.replay_window << shift) & ((1 << REPLAY_WINDOW) - 1)) | 1
            self.recv_seq_max = seq
            return True

        diff = self.recv_seq_max - seq
        if diff >= REPLAY_WINDOW:
            # Too old — outside the window
            return False

        bit = 1 << diff
        if self.replay_window & bit:
            # Already received — replay
            return False

        # Within window, not yet seen
        self.replay_window |= bit
        return True

    # ------------------------------------------------------------------
    # Sequence number management
    # ------------------------------------------------------------------

    def next_send_seq(self) -> int:
        """Return and increment the transmit sequence counter."""
        seq = self.send_seq
        self.send_seq += 1
        return seq

    def touch(self) -> None:
        """Update the last-seen timestamp to now."""
        self.last_seen = time.monotonic()
