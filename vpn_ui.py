#!/usr/bin/env python3
"""
VPN Web UI

Serves a local control panel at http://localhost:8080
Click Connect to start the VPN tunnel; click Disconnect to stop it.

Must be run as root (the VPN client needs root for TUN and routing).

Usage:
    sudo python3 vpn_ui.py [--port 8080]
"""
import argparse
import logging
import os
import sys
import threading
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# State shared between the Flask thread and the VPN client thread
# ---------------------------------------------------------------------------

class VPNState:
    def __init__(self):
        self._lock    = threading.Lock()
        self.state    = 'disconnected'  # 'disconnected' | 'connecting' | 'connected' | 'error'
        self.vip      = ''
        self.error    = ''
        self._client  = None
        self._thread  = None

    def get(self):
        with self._lock:
            return {'state': self.state, 'vip': self.vip, 'error': self.error}

    def set(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                setattr(self, k, v)


_state = VPNState()


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder=None)
_UI_DIR = Path(__file__).parent / 'vpn' / 'ui'


@app.route('/')
def index():
    return send_from_directory(_UI_DIR, 'index.html')


@app.route('/api/status')
def api_status():
    return jsonify(_state.get())


@app.route('/api/connect', methods=['POST'])
def api_connect():
    body = request.get_json(force=True)
    server     = body.get('server', '').strip()
    port       = int(body.get('port', 51820))
    full_tunnel = bool(body.get('full_tunnel', False))

    if not server:
        return jsonify({'ok': False, 'error': 'server address required'}), 400

    cur = _state.get()
    if cur['state'] in ('connected', 'connecting'):
        return jsonify({'ok': False, 'error': 'already connected'}), 409

    _state.set(state='connecting', error='', vip='')

    # Run the VPN client in a background thread so Flask stays responsive.
    # The client's connect() call blocks until the handshake finishes.
    t = threading.Thread(target=_run_client, args=(server, port, full_tunnel), daemon=True)
    _state._thread = t
    t.start()

    # Wait up to 12 seconds for the handshake to complete
    t.join(timeout=12)

    result = _state.get()
    if result['state'] == 'connected':
        return jsonify({'ok': True, 'vip': result['vip']})
    else:
        err = result['error'] or 'Connection timed out or failed'
        _state.set(state='error', error=err)
        return jsonify({'ok': False, 'error': err}), 500


@app.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    client = _state._client
    if client:
        client.stop()
        _state._client = None
    _state.set(state='disconnected', vip='', error='')
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# VPN client runner
# ---------------------------------------------------------------------------

def _run_client(server: str, port: int, full_tunnel: bool) -> None:
    """Runs in a daemon thread. Blocks for the lifetime of the VPN session."""
    try:
        from vpn.client import VPNClient

        client = VPNClient(server_host=server, server_port=port, full_tunnel=full_tunnel)

        # Monkey-patch client._connect so we can capture the assigned VIP
        # and signal 'connected' before the forwarding threads block forever.
        original_connect = client._connect

        def patched_connect():
            original_connect()
            vip = client._session.virtual_ip if client._session else ''
            _state.set(state='connected', vip=vip)
            _state._client = client

        client._connect = patched_connect

        client.start()   # blocks until disconnect / error

    except Exception as exc:
        log.exception('VPN client error')
        _state.set(state='error', error=str(exc))
    finally:
        if _state.get()['state'] not in ('disconnected',):
            _state.set(state='disconnected', vip='', error='')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='VPN Web UI — run as root')
    parser.add_argument('--port', type=int, default=8080,
                        help='Web UI port (default: 8080)')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Host to bind (default: 127.0.0.1)')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )

    print(f'\n  VPN Control Panel → http://{args.host}:{args.port}\n')
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()
