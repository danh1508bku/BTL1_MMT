#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the "MIT License Agreement". Please see the LICENSE
# file that should have been included as part of this package.
#
# WeApRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#


"""
start_tracker
~~~~~~~~~~~~~~~~~

This module provides a sample RESTful web application using the WeApRous framework.

It defines basic route handlers and launches a TCP-based backend server to serve
HTTP requests. The application includes a login endpoint and a greeting endpoint,
and can be configured via command-line arguments.
"""

import json
import socket
import argparse
import threading 
import time

from daemon.utils import handle_options
from daemon.weaprous import WeApRous

PORT = 8000  # Default port

app = WeApRous()

# A dictionary storing peer info: { "ip:port": { "ip": ip, "port": port, "timestamp": ... } }
peers = {}
active_peers_list = []
# Prevent race conditions when multiple requests update peer list
peers_lock = threading.Lock()

@app.route('/submit-info', methods=['POST'])
def submit_info(headers=None, body=None, cookies=None, client_addr=None):
    global active_peers_list
    try:
        data = json.loads(body)
        username = data.get('username')
        port_val = data.get('port')
        declared_ip = data.get('ip')

        if not username or port_val is None or not declared_ip:
            raise ValueError("Missing username, ip, or port")

        p2p_port = int(port_val)
        real_ip = client_addr[0] if client_addr else None

        # Determine IP to store
        if declared_ip and declared_ip not in ('127.0.0.1', 'localhost'):
            peer_ip = declared_ip
            ip_source = "client-declared"
        else:
            peer_ip = real_ip
            ip_source = "socket-source"

        add_or_update_peer(username, peer_ip, p2p_port)

        return {
            'status': 200,
            'body': json.dumps({
                "message": "Registered successfully",
                "username": username,
                "ip": peer_ip,
                "port": p2p_port
            }),
            'content_type': 'application/json'
        }

    except (json.JSONDecodeError, ValueError, TypeError) as e:
        return {
            'status': 400,
            'body': json.dumps({"Error": "Invalid data format", "Details": str(e)})
        }
    except Exception:
        return {
            'status': 500,
            'body': json.dumps({"Error": "Internal Server Error"})
        }


@app.route('/add-list', methods=['POST'])
def add_list(headers=None, body=None, cookies=None, client_addr=None):
    try:
        data = json.loads(body)
        username = data.get('username')
        port_val = data.get('port')
        peer_ip = data.get('ip')

        if not username or port_val is None or not peer_ip:
            raise ValueError("Missing username, ip, or port")

        p2p_port = int(port_val)
        add_or_update_peer(username, peer_ip, p2p_port)

        return {
            'status': 200,
            'body': '{"message": "Registered successfully"}',
            'content_type': 'application/json'
        }

    except (json.JSONDecodeError, ValueError, TypeError) as e:
        return {
            'status': 400,
            'body': json.dumps({"Error": "Invalid data format", "Details": str(e)})
        }


@app.route('/get-list', methods=['GET'])
def get_list(headers=None, body=None, cookies=None, client_addr=None):
    with peers_lock:
        peers_copy = list(active_peers_list)
    try:
        list_json = json.dumps(peers_copy)

        return {
            'status': 200,
            'body': list_json,
            'content_type': 'application/json'
        }
    except TypeError:
        return {
            'status': 500
        }
@app.route('/logout-tracker', methods=['POST'])
def logout_tracker(headers=None, body=None, cookies=None, client_addr=None):
    """
    Remove a peer from the tracker when it logs out.
    """
    try:
        data = json.loads(body)
        ip = data.get("ip")
        port = data.get("port")

        if not ip or port is None:
            raise ValueError("Missing ip or port")

        peer_key = f"{ip}:{port}"

        with peers_lock:
            # Remove from peers dict
            removed = peers.pop(peer_key, None)

            # Remove from active_peers_list if existed
            global active_peers_list
            active_peers_list = [
                p for p in active_peers_list
                if not (p.get("ip") == ip and p.get("port") == port)
            ]

        if removed:
            print(f"[Tracker] Peer logged out: {peer_key}")
            return {
                'status': 200,
                'body': json.dumps({"message": "Logged out", "ip": ip, "port": port}),
                'content_type': 'application/json'
            }
        else:
            return {
                'status': 404,
                'body': json.dumps({"message": "Peer not found"}),
                'content_type': 'application/json'
            }

    except (json.JSONDecodeError, ValueError, TypeError) as e:
        return {
            'status': 400,
            'body': json.dumps({"Error": "Invalid data format", "Details": str(e)}),
            'content_type': 'application/json'
        }
    except Exception as e:
        return {
            'status': 500,
            'body': json.dumps({"Error": "Internal Server Error", "Details": str(e)}),
            'content_type': 'application/json'
        }
    
options_routes = ['/submit-info', '/add-list', '/get-list', '/logout-tracker']

for route in options_routes:
    app.route(route, methods=['OPTIONS'])(handle_options)

def add_or_update_peer(username, ip, port):  # ← Thêm username
    """
    Add a new peer or update an existing peer's status in the global peer list.
    Safe under concurrency due to peers_lock.
    """
    peer_key = f"{ip}:{port}"
    now = time.time()

    with peers_lock:
        peers[peer_key] = {
            "username": username,  # ← Lưu username
            "ip": ip,
            "port": port,
            "timestamp": now
        }
        
        # Cập nhật active_peers_list
        global active_peers_list
        # Xóa peer cũ nếu trùng ip:port
        active_peers_list = [
            p for p in active_peers_list 
            if not (p.get("ip") == ip and p.get("port") == port)
        ]
        # Thêm peer mới
        active_peers_list.append({
            "username": username,
            "ip": ip,
            "port": port
        })
    
    print(f"[Tracker] Peer updated: {username} at {peer_key}")
    return peers[peer_key]

if __name__ == "__main__":
    # Parse command-line arguments to configure server IP and port
    parser = argparse.ArgumentParser(prog='Backend', description='', epilog='Beckend daemon')
    parser.add_argument('--server-ip', default='0.0.0.0')
    parser.add_argument('--server-port', type=int, default=PORT)
 
    args = parser.parse_args()
    ip = args.server_ip
    port = args.server_port

    # Prepare and launch the RESTful application
    app.prepare_address(ip, port)
    app.run()