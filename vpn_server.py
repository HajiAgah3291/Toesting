#!/usr/bin/env python3
"""
VPN Server entry point.

Usage:
    sudo python3 vpn_server.py [options]

Options:
    --bind ADDR     IP address to listen on (default: 0.0.0.0)
    --port PORT     UDP port (default: 51820)
    --subnet CIDR   VPN subnet (default: 10.8.0.0/24)
    --wan-iface IF  WAN interface for NAT (default: eth0)
    --no-nat        Skip iptables NAT setup
    --verbose       Enable debug logging
"""
import argparse
import logging
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description='VPN Server — run as root',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--bind', default='0.0.0.0', metavar='ADDR',
                        help='IP to listen on (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=51820, metavar='PORT',
                        help='UDP port (default: 51820)')
    parser.add_argument('--subnet', default='10.8.0.0/24', metavar='CIDR',
                        help='VPN subnet (default: 10.8.0.0/24)')
    parser.add_argument('--wan-iface', default='eth0', metavar='IF',
                        help='WAN interface for NAT (default: eth0)')
    parser.add_argument('--no-nat', action='store_true',
                        help='Skip iptables NAT setup')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable debug logging')
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )

    # Parse subnet
    import ipaddress
    try:
        net = ipaddress.IPv4Network(args.subnet, strict=False)
    except ValueError as exc:
        print(f'Invalid subnet: {exc}', file=sys.stderr)
        sys.exit(1)

    from vpn.server import VPNServer
    server = VPNServer(
        bind_addr=args.bind,
        port=args.port,
        subnet=str(net.network_address),
        prefix=net.prefixlen,
        wan_iface=args.wan_iface,
        enable_nat=not args.no_nat,
    )
    server.start()


if __name__ == '__main__':
    main()
