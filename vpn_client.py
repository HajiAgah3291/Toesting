#!/usr/bin/env python3
"""
VPN Client entry point.

Usage:
    sudo python3 vpn_client.py --server SERVER_IP [options]

Options:
    --server HOST   VPN server IP or hostname (required)
    --port PORT     UDP port (default: 51820)
    --full-tunnel   Route all internet traffic through VPN
    --verbose       Enable debug logging
"""
import argparse
import logging
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description='VPN Client — run as root',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--server', required=True, metavar='HOST',
                        help='VPN server IP address or hostname')
    parser.add_argument('--port', type=int, default=51820, metavar='PORT',
                        help='UDP port (default: 51820)')
    parser.add_argument('--full-tunnel', action='store_true',
                        help='Route all traffic through the VPN')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable debug logging')
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )

    from vpn.client import VPNClient
    client = VPNClient(
        server_host=args.server,
        server_port=args.port,
        full_tunnel=args.full_tunnel,
    )
    client.start()


if __name__ == '__main__':
    main()
