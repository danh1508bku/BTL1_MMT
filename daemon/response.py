import datetime
import os
import mimetypes
from .dictionary import CaseInsensitiveDict

BASE_DIR = ""

class Response():   

    __attrs__ = [
        "_content", "_header", "status_code", "method",
        "headers", "url", "history", "encoding", "reason",
        "cookies", "elapsed", "request", "body", "reason",
    ]

    def __init__(self, request=None):
        self._content = b""
        self._content_consumed = False
        self._next = None
        self.status_code = None
        self.headers = {}
        self.url = None
        self.encoding = None
        self.history = []
        self.reason = ""
        self.cookies = CaseInsensitiveDict()
        self.elapsed = datetime.timedelta(0)
        self.request = None

        # flags do HttpAdapter set
        self.unauthorized = False
        self.set_auth_cookie = False
        self.redirect_to = None  # ✅ NEW: Redirect location

    def get_mime_type(self, path):
        try:
            mime_type, _ = mimetypes.guess_type(path)
        except Exception:
            return 'application/octet-stream'
        return mime_type or 'application/octet-stream'

    def prepare_content_type(self, mime_type='text/html'):
        base_dir = ""
        main_type, sub_type = mime_type.split('/', 1)
        print("[Response] processing MIME main_type={} sub_type={}".format(main_type, sub_type))

        if main_type == 'text':
            self.headers['Content-Type'] = 'text/{}'.format(sub_type)
            if sub_type in ['plain', 'css']:
                base_dir = BASE_DIR + "static/"
            elif sub_type == 'html':
                base_dir = BASE_DIR + "www/"
        elif main_type == 'image':
            base_dir = BASE_DIR + "static/"
            self.headers['Content-Type'] = 'image/{}'.format(sub_type)
        elif main_type == 'application':
            base_dir = BASE_DIR + "apps/"
            self.headers['Content-Type'] = 'application/{}'.format(sub_type)
        else:
            raise ValueError("Invalid MIME type")

        return base_dir

    def build_content(self, path, base_dir):
        filepath = os.path.join(base_dir, path.lstrip('/'))
        print("[Response] serving the object at location {}".format(filepath))

        if not os.path.exists(filepath):
            print("[Response] File not found: {}".format(filepath))
            return False, 13, b"404 Not Found"

        try:
            with open(filepath, "rb") as f:
                content = f.read()
            return True, len(content), content
        except Exception as e:
            print("[Response] Error reading file: {}".format(e))
            return False, 13, b"404 Not Found"

    def build_rfc6265_cookie(self, name, value, max_age=3600, path="/", 
                             secure=False, httponly=True, samesite="Lax"):
        """RFC 6265 Compliant Cookie"""
        cookie_parts = ["{}={}".format(name, value)]
        
        if max_age:
            cookie_parts.append("Max-Age={}".format(max_age))
        
        cookie_parts.append("Path={}".format(path))
        
        if secure:
            cookie_parts.append("Secure")
        
        if httponly:
            cookie_parts.append("HttpOnly")
        
        if samesite:
            cookie_parts.append("SameSite={}".format(samesite))
        
        return "; ".join(cookie_parts)

    def build_redirect_response(self):
        """
        ✅ Build HTTP 302 Found (Redirect) Response
        
        RFC 7231 Section 6.4.3: 302 Found
        The target resource resides temporarily under a different URI.
        """
        redirect_html = """<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0; url={}">
    <title>Redirecting...</title>
</head>
<body>
    <p>Redirecting to <a href="{}">{}</a>...</p>
</body>
</html>""".format(self.redirect_to, self.redirect_to, self.redirect_to)

        self._content = redirect_html.encode('utf-8')
        self.status_code = 302
        self.headers['Content-Type'] = 'text/html'
        
        # Build 302 response header
        header_lines = [
            "HTTP/1.1 302 Found",
            "Location: {}".format(self.redirect_to),
            "Content-Type: text/html",
            "Content-Length: {}".format(len(self._content)),
            "Cache-Control: no-cache",
            "Connection: close",
        ]

        # ✅ Set cookie on redirect
        if self.set_auth_cookie:
            cookie = self.build_rfc6265_cookie(
                name="auth", value="true", max_age=3600,
                path="/", secure=False, httponly=True, samesite="Lax"
            )
            header_lines.append("Set-Cookie: {}".format(cookie))

        header_lines.append("")
        header_lines.append("")

        return ("\r\n".join(header_lines)).encode("utf-8") + self._content

    def build_response_header(self, request):
        """Standard response header builder"""
        status_line = "HTTP/1.1 200 OK"
        
        if self.unauthorized:
            status_line = "HTTP/1.1 401 Unauthorized"
            self.status_code = 401
        elif self.status_code == 404:
            status_line = "HTTP/1.1 404 Not Found"
        elif self.status_code == 500:
            status_line = "HTTP/1.1 500 Internal Server Error"
        else:
            self.status_code = 200

        header_lines = [
            status_line,
            "Content-Type: {}".format(self.headers.get("Content-Type", "text/html")),
            "Content-Length: {}".format(len(self._content)),
            "Cache-Control: no-cache",
            "Connection: close",
        ]

        # RFC 7235 - WWW-Authenticate for 401
        if self.unauthorized:
            header_lines.append('WWW-Authenticate: FormBased realm="Backend Access"')

        # RFC 6265 - Set-Cookie
        if self.set_auth_cookie:
            cookie = self.build_rfc6265_cookie(
                name="auth", value="true", max_age=3600,
                path="/", secure=False, httponly=True, samesite="Lax"
            )
            header_lines.append("Set-Cookie: {}".format(cookie))

        header_lines.append("")
        header_lines.append("")

        return ("\r\n".join(header_lines)).encode("utf-8")

    def build_notfound(self):
        self.status_code = 404
        return (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 13\r\n"
            "Connection: close\r\n"
            "\r\n"
            "404 Not Found"
        ).encode('utf-8')

    def build_response(self, request):
        """
        ✅ Main response builder with redirect support
        """
        # Handle redirect first (highest priority)
        if self.redirect_to:
            print("[Response] Redirecting to: {}".format(self.redirect_to))
            return self.build_redirect_response()

        # Unauthorized
        if self.unauthorized:
            html = b"<h1>401 Unauthorized</h1><p>Access denied. Please login.</p>"
            self._content = html
            self.headers['Content-Type'] = "text/html"
            self.status_code = 401
            self._header = self.build_response_header(request)
            return self._header + self._content

        path = request.path
        mime_type = self.get_mime_type(path)
        print("[Response] {} path {} mime_type {}".format(request.method, request.path, mime_type))

        base_dir = None
        
        try:
            if path.endswith(".html") or mime_type == "text/html":
                base_dir = self.prepare_content_type("text/html")
            elif mime_type == "text/css":
                base_dir = self.prepare_content_type("text/css")
            elif mime_type.startswith("image/"):
                base_dir = self.prepare_content_type(mime_type)
            else:
                print("[Response] Unsupported MIME type: {}".format(mime_type))
                return self.build_notfound()
        except Exception as e:
            print("[Response] Error preparing content type: {}".format(e))
            return self.build_notfound()

        success, c_len, content = self.build_content(path, base_dir)
        
        if not success:
            print("[Response] Failed to build content for path: {}".format(path))
            return self.build_notfound()
        
        self._content = content
        self.status_code = 200
        self._header = self.build_response_header(request)

        return self._header + self._content