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
start_sampleapp
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

from daemon.utils import handle_options
from daemon.weaprous import WeApRous

PORT = 8000  # Default port

app = WeApRous()

peers_lock = threading.Lock()
my_connect_peers = {}

INBOX = []
inbox_lock = threading.Lock()

@app.route('/login', methods=['POST'])
def login(headers="guest", body="anonymous"):
    """
    Handle user login via POST request.

    This route simulates a login process and prints the provided headers and body
    to the console.

    :param headers (str): The request headers or user identifier.
    :param body (str): The request body or login payload.
    """
    print( "[SampleApp] Logging in {} to {}").format(headers, body)

@app.route('/hello', methods=['PUT'])
def hello(headers, body):
    """
    Handle greeting via PUT request.

    This route prints a greeting message to the console using the provided headers
    and body.

    :param headers (str): The request headers or user identifier.
    :param body (str): The request body or message payload.
    """
    print("[SampleApp] ['PUT'] Hello in {} to {}").format(headers, body)

@app.route('/connect-peer', methods=['POST'])
def connect_peer(headers=None, body=None, cookies=None, client_addr=None):
    try:
        data = json.loads(body)
        username = data.get('username')
        p2p_port = int(data.get('port'))
        peer_ip = data.get('ip')
    except json.JSONDecodeError:
        return {
            'status': 400,
            'body': '{"Error": "Invalid JSON body"}'
        }

    is_local_request = not data.get("from_user")
    my_username = cookies.get('username')

    if is_local_request:
        handshake = json.dumps({
            "username": my_username,
            "ip": app.ip,
            "port": app.port,
            "from_user": True
        })

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, p2p_port))
                request = (
                    "POST /connect-peer HTTP/1.1\r\n"
                    f"Host: {peer_ip}:{p2p_port}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(handshake)}\r\n\r\n"
                    f"{handshake}"
                )
                s.sendall(request.encode())
                resp = s.recv(1024)

            with peers_lock:
                my_connect_peers[username] = (peer_ip, p2p_port)

            return {
                'status': 200,
                'body': '{"Message": "Outbound handshake done"}'
            }
        except Exception as e:
            return {
                'status': 500,
                'body': '{"Error": "Connection failed"}'
            }

    with peers_lock:
        my_connect_peers[username] = (peer_ip, p2p_port)

    return {
        'status': 200,
        'body': '{"Message": "Peer registered"}'
    }

@app.route('/send-private', methods=['POST'])
def send_private(headers=None, body=None, cookies=None, client_addr=None):
    try:
        from_user = cookies.get('username')
        if not from_user:
            return {'status': 401, 'body': '{"Error": "Not authenticated"}'}

        data = json.loads(body)
        target_user = data.get('target_user')
        message = data.get('message')

        if not target_user or not message:
            return {
                'status': 400,
                'body': '{"Error": "Missing target_user or message"}'
            }

        with peers_lock:
            if target_user in my_connect_peers:
                peer_ip, peer_port = my_connect_peers[target_user]

                success = send_to_peer(from_user, peer_ip, peer_port,
                                       target_user, message)

                if success:
                    return {'status': 200, 'body': '{"Message": "Sent"}'}
                else:
                    return {
                        'status': 503,
                        'body': '{"Error": "Peer is offline"}'
                    }
            else:
                return {
                    'status': 404,
                    'body': '{"Error": "Peer not connected"}'
                }

    except json.JSONDecodeError:
        return {'status': 400, 'body': '{"Error": "Invalid JSON"}'}
    except Exception:
        return {
            'status': 500,
            'body': '{"Error": "Internal Server Error"}'
        }


@app.route('/send-peer', methods=['POST'])
def send_peer(headers=None, body=None, cookies=None, client_addr=None):
    try:
        data = json.loads(body)
        from_user = data.get("from_user")
        message = data.get("message")
    except json.JSONDecodeError:
        return {'status': 400, 'body': '{"Error": "Invalid JSON"}'}

    if from_user and message:
        with inbox_lock:
            # Kiểm tra có phải broadcast hay không
            if from_user == message.split(':')[0].strip('[BROADCAST]'):
                message = f"[BROADCAST] {message}"

            INBOX.append({"from": from_user, "message": message})
            store_message("in", from_user, message)

        return {'status': 200, 'body': '{"Message": "received"}'}

    return {'status': 400, 'body': '{"Error": "Missing field"}'}

@app.route('/get-messages', methods=['GET'])
def get_messages(headers=None, body=None, cookies=None, client_addr=None):
    global INBOX
    messages_to_send = []

    with inbox_lock:
        messages_to_send = INBOX
        INBOX = []

    try:
        message_json = json.dumps(messages_to_send)
        return {
            'status': 200,
            'body': message_json,
            'content_type': 'application/json'
        }
    except TypeError:
        return {'status': 500}

@app.route('/broadcast-peer', methods=['POST'])
def broadcast_peer(headers=None, body=None, cookies=None, client_addr=None):
    try:
        data = json.loads(body)
        message = data.get('message')
        from_user = data.get('username')

        if message and from_user:
            peers_to_remove = []
            broadcast_message = f"[BROADCAST] {message}"

            with peers_lock:
                for username, (peer_ip, peer_port) in list(my_connect_peers.items()):
                    success = send_to_peer(
                        from_user, peer_ip, peer_port, username, broadcast_message
                    )

                    if not success:
                        peers_to_remove.append(username)

            return {'status': 200, 'body': '{"Message": "Broadcast sent"}'}

        return {'status': 400, 'body': '{"Error": "Missing sender or message"}'}

    except json.JSONDecodeError:
        return {'status': 400, 'body': '{"Error": "Invalid JSON"}'}


def send_to_peer(from_user, peer_ip, peer_port, target_user, message):
    """
    Send a P2P message to another peer using a direct TCP socket.
    Returns True if the message was delivered, False if peer offline.
    """

    try:
        payload = json.dumps({
            "from_user": from_user,
            "target_user": target_user,
            "message": message
        })

        request = (
            "POST /send-peer HTTP/1.1\r\n"
            f"Host: {peer_ip}:{peer_port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
            f"{payload}"
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((peer_ip, peer_port))
            s.sendall(request.encode())

            # Only needs simple ack
            s.recv(1024)

        store_message("out", from_user, message)
        return True

    except Exception:
        return False

def store_message(direction, from_user, message):
    """
    Store message into a local log file.
    direction: 'in' or 'out'
    """
    filename = "message_log.txt"
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"[{direction.upper()}] {from_user}: {message}\n")

options_routes = ['/login', '/hello','/connect-peer','/send-private',
                  '/send-peer','/get-messages','/broadcast_peer']

for route in options_routes:
    app.route(route, methods=['OPTIONS'])(handle_options)

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