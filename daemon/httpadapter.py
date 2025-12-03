from .request import Request
from .response import Response
from .dictionary import CaseInsensitiveDict
from urllib.parse import unquote

class HttpAdapter:

    __attrs__ = [
        "ip", "port", "conn", "connaddr", "routes",
        "request", "response",
    ]

    def __init__(self, ip, port, conn, connaddr, routes):
        self.ip = ip
        self.port = port
        self.conn = conn
        self.connaddr = connaddr
        self.routes = routes
        self.request = Request()
        self.response = Response()

    def handle_client(self, conn, addr, routes):
        self.conn = conn        
        self.connaddr = addr
        req = self.request
        resp = self.response

        msg = conn.recv(2048).decode()
        req.prepare(msg, routes)
        
        # ---------------------------
        #   URL REWRITING
        # ---------------------------
        rewrite_map = {
            "/login": "/login.html",
            "/index": "/index.html",
            "/": "/index.html"
        }

        if req.method == "GET" and req.path in rewrite_map:
            req.path = rewrite_map[req.path]

        # ---------------------------
        #   ✅ TASK 1A — LOGIN WITH REDIRECT
        # ---------------------------
        if req.method == "POST" and req.path == "/login":
            body = req.body or ""
            params = dict(x.split("=") for x in body.split("&") if "=" in x)

            username = unquote(params.get("username", ""))
            password = unquote(params.get("password", ""))

            if username == "admin" and password == "password":
                # ✅ Set cookie and redirect to /index
                resp.set_auth_cookie = True
                resp.redirect_to = "/index"  # NEW: Tell response to redirect
            else:
                resp.unauthorized = True

        # ---------------------------------------
        #   TASK 1B — COOKIE ACCESS CONTROL
        # ---------------------------------------
        elif req.method == "GET" and (req.path == "/" or req.path == "/index.html"):
            cookie = req.cookies.get("auth", None)
            if cookie != "true":
                resp.unauthorized = True

        # ---------------------------------------
        #   BUILD RESPONSE
        # ---------------------------------------
        response_bytes = resp.build_response(req)
        conn.sendall(response_bytes)
        conn.close()
