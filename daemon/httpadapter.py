#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# WeApRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
daemon.httpadapter
~~~~~~~~~~~~~~~~~

This module provides a http adapter object to manage and persist 
http settings (headers, bodies). The adapter supports both
raw URL paths and RESTful route definitions, and integrates with
Request and Response objects to handle client-server communication.
"""

from .request import Request
from .response import Response
from .dictionary import CaseInsensitiveDict
from urllib.parse import unquote
import json
class HttpAdapter:
    """
    A mutable :class:`HTTP adapter <HTTP adapter>` for managing client connections
    and routing requests.

    The `HttpAdapter` class encapsulates the logic for receiving HTTP requests,
    dispatching them to appropriate route handlers, and constructing responses.
    It supports RESTful routing via hooks and integrates with :class:`Request <Request>` 
    and :class:`Response <Response>` objects for full request lifecycle management.

    Attributes:
        ip (str): IP address of the client.
        port (int): Port number of the client.
        conn (socket): Active socket connection.
        connaddr (tuple): Address of the connected client.
        routes (dict): Mapping of route paths to handler functions.
        request (Request): Request object for parsing incoming data.
        response (Response): Response object for building and sending replies.
    """

    __attrs__ = [
        "ip", "port", "conn", "connaddr", "routes",
        "request", "response",
    ]

    def __init__(self, ip, port, conn, connaddr, routes):
        """
        Initialize a new HttpAdapter instance.

        :param ip (str): IP address of the client.
        :param port (int): Port number of the client.
        :param conn (socket): Active socket connection.
        :param connaddr (tuple): Address of the connected client.
        :param routes (dict): Mapping of route paths to handler functions.
        """

        #: IP address.
        self.ip = ip
        #: Port.
        self.port = port
        #: Connection
        self.conn = conn
        #: Conndection address
        self.connaddr = connaddr
        #: Routes
        self.routes = routes
        #: Request
        self.request = Request()
        #: Response
        self.response = Response()

    def handle_client(self, conn, addr, routes):
        """
        Handle an incoming client connection.

        This method reads the request from the socket, prepares the request object,
        invokes the appropriate route handler if available, builds the response,
        and sends it back to the client.

        :param conn (socket): The client socket connection.
        :param addr (tuple): The client's address.
        :param routes (dict): The route mapping for dispatching requests.
        """

        # Connection handler.
        self.conn = conn        
        # Connection address.
        self.connaddr = addr
        # Request handler
        req = self.request
        # Response handler
        resp = self.response

        msg = conn.recv(2048).decode()
        req.prepare(msg, routes)
        
        # ============== CHECK FOR RESTful ROUTE HANDLER FIRST ==============
        route_key = (req.method, req.path)
        if route_key in routes:
            handler = routes[route_key]
            
            try:
                # Call the route handler with proper parameters
                result = handler(
                    headers=req.headers,
                    body=req.body,
                    cookies=req.cookies,
                    client_addr=addr
                )
                
                # If handler returns a dict with status/body, build response
                if isinstance(result, dict):
                    status = result.get('status', 200)
                    body = result.get('body', '')
                    content_type = result.get('content_type', 'application/json')
                    
                    # Set response properties
                    resp.status_code = status
                    resp._content = body.encode('utf-8') if isinstance(body, str) else body
                    resp.headers['Content-Type'] = content_type
                    
                    # Build and send response
                    resp._header = resp.build_response_header(req)
                    response_bytes = resp._header + resp._content
                    conn.sendall(response_bytes)
                    conn.close()
                    return
                    
            except Exception as e:
                print(f"[HttpAdapter] Error calling handler for {route_key}: {e}")
                import traceback
                traceback.print_exc()
                
                # Send 500 Internal Server Error
                resp.status_code = 500
                resp._content = json.dumps({"Error": "Internal Server Error", "Details": str(e)}).encode('utf-8')
                resp.headers['Content-Type'] = 'application/json'
                resp._header = resp.build_response_header(req)
                conn.sendall(resp._header + resp._content)
                conn.close()
                return
        # ============== END OF RESTful ROUTE HANDLER ==============
        
        # URL REWRITING (for static files only)
        rewrite_map = {
            "/login": "/login.html",
            "/index": "/index.html",
            "/": "/index.html"
        }

        if req.method == "GET" and req.path in rewrite_map:
            req.path = rewrite_map[req.path]

        # TASK 1A – LOGIN WITH REDIRECT
        if req.method == "POST" and req.path == "/login":
            body = req.body or ""
            params = dict(x.split("=") for x in body.split("&") if "=" in x)

            username = unquote(params.get("username", ""))
            password = unquote(params.get("password", ""))

            if username == "admin" and password == "password":
                # Set cookie and redirect to /index
                resp.set_auth_cookie = True
                resp.redirect_to = "/index"  # NEW: Tell response to redirect
            else:
                resp.unauthorized = True

        # TASK 1B – COOKIE ACCESS CONTROL
        elif req.method == "GET" and (req.path == "/" or req.path == "/index.html"):
            cookie = req.cookies.get("auth", None)
            if cookie != "true":
                resp.unauthorized = True

        # BUILD RESPONSE (for static files)
        response_bytes = resp.build_response(req)
        conn.sendall(response_bytes)
        conn.close()

    def add_headers(self, request):
        """
        Add headers to the request.

        This method is intended to be overridden by subclasses to inject
        custom headers. It does nothing by default.

        
        :param request: :class:`Request <Request>` to add headers to.
        """
        pass

    def build_proxy_headers(self, proxy):
        """Returns a dictionary of the headers to add to any request sent
        through a proxy. 

        :class:`HttpAdapter <HttpAdapter>`.

        :param proxy: The url of the proxy being used for this request.
        :rtype: dict
        """
        headers = {}
        #
        # TODO: build your authentication here
        #       username, password =...
        # we provide dummy auth here
        #
        username, password = ("user1", "password")

        if username:
            headers["Proxy-Authorization"] = (username, password)

        return headers
