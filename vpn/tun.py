"""
TUN interface management via Linux ioctls.

Opens /dev/net/tun and configures the interface without requiring the
`ip` command (iproute2 is not available in all environments).
Requires root privileges.
"""
import fcntl
import os
import socket
import struct

from .constants import (
    IFF_NO_PI,
    IFF_RUNNING,
    IFF_TUN,
    IFF_UP,
    SIOCGIFFLAGS,
    SIOCSIFADDR,
    SIOCSIFFLAGS,
    SIOCSIFMTU,
    SIOCSIFNETMASK,
    TUNSETIFF,
)

# ifreq struct: 16-byte name + 16 bytes of union = 32 bytes (padded to 40)
_IFREQ_SIZE = 40


def _ifreq(ifname: str, data: bytes = b'') -> bytes:
    """
    Build a struct ifreq with the given interface name and union data.
    Total size is _IFREQ_SIZE bytes.
    """
    name_bytes = ifname.encode()[:15].ljust(16, b'\x00')
    data_padded = data.ljust(24, b'\x00')
    return name_bytes + data_padded


def _pack_sockaddr_in(ip_str: str) -> bytes:
    """
    Pack an IPv4 address into a 16-byte struct sockaddr_in.
    Layout: sa_family(H/2) + sin_port(H/2) + sin_addr(4s) + pad(8s)
    """
    return struct.pack('!HH4s8s',
                       socket.AF_INET,
                       0,
                       socket.inet_aton(ip_str),
                       b'\x00' * 8)


def open_tun(name: str = 'vpn0') -> tuple[int, str]:
    """
    Open /dev/net/tun and register a TUN interface.

    Args:
        name: Desired interface name. The kernel may append a suffix;
              the actual name is returned.

    Returns:
        (fd, actual_interface_name)

    Raises:
        PermissionError: if not running as root.
        OSError: if /dev/net/tun cannot be opened.
    """
    fd = os.open('/dev/net/tun', os.O_RDWR)
    # IFF_TUN: layer-3 (IP) packets; IFF_NO_PI: no 4-byte packet-info prefix
    flags = IFF_TUN | IFF_NO_PI
    ifr = _ifreq(name, struct.pack('H', flags))
    fcntl.ioctl(fd, TUNSETIFF, ifr)

    # Read back the actual interface name assigned by the kernel
    actual_name = ifr[:16].rstrip(b'\x00').decode(errors='replace')
    return fd, actual_name


def configure_interface(
    ifname: str,
    local_ip: str,
    netmask: str,
    mtu: int,
) -> None:
    """
    Set IP address, netmask, MTU, and bring the TUN interface UP.

    Uses raw AF_INET socket ioctls so that iproute2 (`ip` command) is
    not required.

    Args:
        ifname:   Interface name, e.g. 'vpn0'
        local_ip: IPv4 address to assign, e.g. '10.8.0.1'
        netmask:  Subnet mask, e.g. '255.255.255.0'
        mtu:      MTU in bytes, e.g. 1420
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Set IP address
        ifr_addr = _ifreq(ifname, _pack_sockaddr_in(local_ip))
        fcntl.ioctl(sock.fileno(), SIOCSIFADDR, ifr_addr)

        # Set netmask
        ifr_mask = _ifreq(ifname, _pack_sockaddr_in(netmask))
        fcntl.ioctl(sock.fileno(), SIOCSIFNETMASK, ifr_mask)

        # Set MTU
        ifr_mtu = _ifreq(ifname, struct.pack('I', mtu))
        fcntl.ioctl(sock.fileno(), SIOCSIFMTU, ifr_mtu)

        # Read current flags, then set IFF_UP | IFF_RUNNING
        ifr_flags = _ifreq(ifname)
        result = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, bytearray(ifr_flags))
        current_flags = struct.unpack_from('H', result, 16)[0]
        new_flags = current_flags | IFF_UP | IFF_RUNNING
        ifr_up = _ifreq(ifname, struct.pack('H', new_flags))
        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr_up)
    finally:
        sock.close()
