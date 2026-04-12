"""
Linux routing and NAT configuration helpers.

All functions require root privileges and use subprocess to call
iptables-legacy and ip route commands.
"""
import logging
import subprocess

log = logging.getLogger(__name__)

# Use iptables-legacy — the standard iptables wrapper may fail in some
# environments (e.g. inside containers that use nftables under the hood).
_IPTABLES = '/usr/sbin/iptables-legacy'
_IP       = 'ip'


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command, logging it first."""
    log.debug('Running: %s', ' '.join(cmd))
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


# ---------------------------------------------------------------------------
# IP forwarding
# ---------------------------------------------------------------------------

def enable_ip_forwarding() -> None:
    """Enable IPv4 packet forwarding in the kernel."""
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1\n')
    log.info('IP forwarding enabled')


def disable_ip_forwarding() -> None:
    """Restore IPv4 forwarding to disabled."""
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('0\n')
    log.info('IP forwarding disabled')


# ---------------------------------------------------------------------------
# NAT (server side)
# ---------------------------------------------------------------------------

def setup_nat(vpn_iface: str, wan_iface: str, subnet: str) -> None:
    """
    Configure iptables so VPN clients can reach the internet.

    Adds:
      - MASQUERADE rule in the nat POSTROUTING chain
      - FORWARD ACCEPT rules for vpn_iface traffic

    Args:
        vpn_iface: TUN interface name, e.g. 'vpn0'
        wan_iface: Outbound interface, e.g. 'eth0'
        subnet:    VPN subnet in CIDR, e.g. '10.8.0.0/24'
    """
    _run([_IPTABLES, '-t', 'nat', '-A', 'POSTROUTING',
          '-s', subnet, '-o', wan_iface, '-j', 'MASQUERADE'])
    _run([_IPTABLES, '-A', 'FORWARD', '-i', vpn_iface, '-j', 'ACCEPT'])
    _run([_IPTABLES, '-A', 'FORWARD', '-o', vpn_iface,
          '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
    log.info('NAT set up: %s → %s (%s)', vpn_iface, wan_iface, subnet)


def teardown_nat(vpn_iface: str, wan_iface: str, subnet: str) -> None:
    """Remove the iptables rules added by setup_nat (best-effort)."""
    _run([_IPTABLES, '-t', 'nat', '-D', 'POSTROUTING',
          '-s', subnet, '-o', wan_iface, '-j', 'MASQUERADE'], check=False)
    _run([_IPTABLES, '-D', 'FORWARD', '-i', vpn_iface, '-j', 'ACCEPT'], check=False)
    _run([_IPTABLES, '-D', 'FORWARD', '-o', vpn_iface,
          '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=False)
    log.info('NAT torn down')


# ---------------------------------------------------------------------------
# Route management
# ---------------------------------------------------------------------------

def add_host_route(host_ip: str, dev: str) -> None:
    """
    Add a /32 host route through the VPN interface.

    Used by the server to route packets back to a specific client VIP.
    """
    _run([_IP, 'route', 'add', f'{host_ip}/32', 'dev', dev], check=False)
    log.debug('Route added: %s/32 dev %s', host_ip, dev)


def del_host_route(host_ip: str, dev: str) -> None:
    """Remove a /32 host route (best-effort)."""
    _run([_IP, 'route', 'del', f'{host_ip}/32', 'dev', dev], check=False)


def add_subnet_route(subnet: str, dev: str) -> None:
    """
    Add a subnet route through the VPN interface.

    Example: add_subnet_route('10.8.0.0/24', 'vpn0')
    """
    _run([_IP, 'route', 'add', subnet, 'dev', dev], check=False)
    log.debug('Subnet route added: %s dev %s', subnet, dev)


def get_default_gateway() -> str | None:
    """
    Return the current default gateway IP, or None if not found.
    Parses `ip route show default`.
    """
    result = _run([_IP, 'route', 'show', 'default'], check=False)
    for line in result.stdout.splitlines():
        parts = line.split()
        if 'via' in parts:
            idx = parts.index('via')
            return parts[idx + 1]
    return None


def set_full_tunnel(server_real_ip: str, original_gateway: str, vpn_gateway: str) -> None:
    """
    Configure a full-tunnel: route all traffic through the VPN.

    Steps:
      1. Keep the real server IP reachable via the original gateway
         (so the UDP tunnel itself doesn't go through the VPN).
      2. Delete the current default route.
      3. Add a new default via the VPN gateway VIP.

    Args:
        server_real_ip:   The VPN server's public IP (not the VIP)
        original_gateway: The gateway that was used before VPN connected
        vpn_gateway:      Server VIP, e.g. '10.8.0.1'
    """
    _run([_IP, 'route', 'add', f'{server_real_ip}/32', 'via', original_gateway], check=False)
    _run([_IP, 'route', 'del', 'default'], check=False)
    _run([_IP, 'route', 'add', 'default', 'via', vpn_gateway])
    log.info('Full tunnel activated via %s', vpn_gateway)


def restore_default_route(server_real_ip: str, original_gateway: str) -> None:
    """Undo set_full_tunnel (best-effort)."""
    _run([_IP, 'route', 'del', f'{server_real_ip}/32'], check=False)
    _run([_IP, 'route', 'del', 'default'], check=False)
    _run([_IP, 'route', 'add', 'default', 'via', original_gateway], check=False)
    log.info('Default route restored via %s', original_gateway)
