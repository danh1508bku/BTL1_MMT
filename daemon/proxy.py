#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# WeApRous release
#

"""
daemon.proxy
~~~~~~~~~~~~~~~~~

This module implements a simple proxy server using Python's socket and threading libraries.
It routes incoming HTTP requests to backend services based on hostname mappings and returns
the corresponding responses to clients.
"""
import socket
import threading
from .response import *
from .httpadapter import HttpAdapter
from .dictionary import CaseInsensitiveDict


def forward_request(host, port, request):
    """
    Forwards an HTTP request to a backend server and retrieves the response.

    :params host (str): IP address of the backend server.
    :params port (int): port number of the backend server.
    :params request (str): incoming HTTP request.

    :rtype bytes: Raw HTTP response from the backend server. If the connection
                  fails, returns a 404 Not Found response.
    """

    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        backend.connect((host, port))
        backend.sendall(request.encode())
        response = b""
        while True:
            chunk = backend.recv(4096)
            if not chunk:
                break
            response += chunk
        return response
    except socket.error as e:
        print("Socket error: {}".format(e))
        return (
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 15\r\n"
            "Connection: close\r\n"
            "\r\n"
            "502 Bad Gateway"
        ).encode('utf-8')
    finally:
        backend.close()


def resolve_routing_policy(hostname, routes):
    """
    Handles an routing policy to return the matching proxy_pass.
    It determines the target backend to forward the request to.

    :params hostname (str): hostname from the request Host header
    :params routes (dict): dictionary mapping hostnames and location.
    """

    print("[Proxy] Resolving route for hostname: {}".format(hostname))
    proxy_map, policy = routes.get(hostname, ('127.0.0.1:9000', 'round-robin'))
    print("[Proxy] proxy_map: {}".format(proxy_map))
    print("[Proxy] policy: {}".format(policy))

    proxy_host = '127.0.0.1'
    proxy_port = '9000'
    
    if isinstance(proxy_map, list):
        if len(proxy_map) == 0:
            print("[Proxy] Empty resolved routing of hostname {}".format(hostname))
            # Use default fallback
            proxy_host = '127.0.0.1'
            proxy_port = '9000'
            
        elif len(proxy_map) == 1:  #  was 'value'
            proxy_host, proxy_port = proxy_map[0].split(":", 1)
        else:
            # TODO: implement round-robin or other policies
            # For now, just use the first backend
            print("[Proxy] Multiple backends found, using first one")
            proxy_host, proxy_port = proxy_map[0].split(":", 1)
    else:
        print("[Proxy] Single backend route for hostname {}".format(hostname))
        proxy_host, proxy_port = proxy_map.split(":", 1)

    return proxy_host, proxy_port


def handle_client(ip, port, conn, addr, routes):
    """
    Handles an individual client connection by parsing the request,
    determining the target backend, and forwarding the request.

    :params ip (str): IP address of the proxy server.
    :params port (int): port number of the proxy server.
    :params conn (socket.socket): client connection socket.
    :params addr (tuple): client address (IP, port).
    :params routes (dict): dictionary mapping hostnames and location.
    """
    try:
        request = conn.recv(4096).decode()
        
        if not request:
            print("[Proxy] Empty request from {}".format(addr))
            conn.close()
            return

        # Extract hostname
        hostname = None
        for line in request.splitlines():
            if line.lower().startswith('host:'):
                hostname = line.split(':', 1)[1].strip()
                break

        if not hostname:
            print("[Proxy] No Host header found in request from {}".format(addr))
            conn.close()
            return

        print("[Proxy] Request from {} for Host: {}".format(addr, hostname))

        # Resolve the matching destination in routes
        resolved_host, resolved_port = resolve_routing_policy(hostname, routes)
        
        try:
            resolved_port = int(resolved_port)
        except ValueError:
            print("[Proxy] Invalid port number: {}".format(resolved_port))
            resolved_port = 9000

        print("[Proxy] Forwarding {} to {}:{}".format(hostname, resolved_host, resolved_port))
        response = forward_request(resolved_host, resolved_port, request)
        
        conn.sendall(response)
        
    except Exception as e:
        print("[Proxy] Error handling client {}: {}".format(addr, e))
        try:
            error_response = (
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 25\r\n"
                "Connection: close\r\n"
                "\r\n"
                "500 Internal Server Error"
            ).encode('utf-8')
            conn.sendall(error_response)
        except:
            pass
    finally:
        conn.close()


def run_proxy(ip, port, routes):
    """
    Starts the proxy server and listens for incoming connections. 

    :params ip (str): IP address to bind the proxy server.
    :params port (int): port number to listen on.
    :params routes (dict): dictionary mapping hostnames and location.
    """

    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        proxy.bind((ip, port))
        proxy.listen(50)
        print("[Proxy] Listening on IP {} port {}".format(ip, port))
        
        while True:
            conn, addr = proxy.accept()
            #  Implement multi-threading
            client_thread = threading.Thread(
                target=handle_client,
                args=(ip, port, conn, addr, routes)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n[Proxy] Shutting down...")
    except socket.error as e:
        print("Socket error: {}".format(e))
    finally:
        proxy.close()


def create_proxy(ip, port, routes):
    """
    Entry point for launching the proxy server.

    :params ip (str): IP address to bind the proxy server.
    :params port (int): port number to listen on.
    :params routes (dict): dictionary mapping hostnames and location.
    """
    run_proxy(ip, port, routes)