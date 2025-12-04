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
daemon.response
~~~~~~~~~~~~~~~~~

This module provides a :class: `Response <Response>` object to manage and persist 
response settings (cookies, auth, proxies), and to construct HTTP responses
based on incoming requests. 

The current version supports MIME type detection, content loading and header formatting
"""
import datetime
import os
import mimetypes
from .dictionary import CaseInsensitiveDict

BASE_DIR = ""

class Response():   
    """The :class:`Response <Response>` object, which contains a
    server's response to an HTTP request.

    Instances are generated from a :class:`Request <Request>` object, and
    should not be instantiated manually; doing so may produce undesirable
    effects.

    :class:`Response <Response>` object encapsulates headers, content, 
    status code, cookies, and metadata related to the request-response cycle.
    It is used to construct and serve HTTP responses in a custom web server.

    :attrs status_code (int): HTTP status code (e.g., 200, 404).
    :attrs headers (dict): dictionary of response headers.
    :attrs url (str): url of the response.
    :attrsencoding (str): encoding used for decoding response content.
    :attrs history (list): list of previous Response objects (for redirects).
    :attrs reason (str): textual reason for the status code (e.g., "OK", "Not Found").
    :attrs cookies (CaseInsensitiveDict): response cookies.
    :attrs elapsed (datetime.timedelta): time taken to complete the request.
    :attrs request (PreparedRequest): the original request object.

    Usage::

      >>> import Response
      >>> resp = Response()
      >>> resp.build_response(req)
      >>> resp
      <Response>
    """
    
    __attrs__ = [
        "_content", "_header", "status_code", "method",
        "headers", "url", "history", "encoding", "reason",
        "cookies", "elapsed", "request", "body", "reason",
    ]

    def __init__(self, request=None):
        """
        Initializes a new :class:`Response <Response>` object.

        : params request : The originating request object.
        """
        self._content = b""
        self._content_consumed = False
        self._next = None

        #: Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        #: Case-insensitive Dictionary of Response Headers.
        #: For example, ``headers['content-type']`` will return the
        #: value of a ``'Content-Type'`` response header.        
        self.headers = {}

        #: URL location of Response.
        self.url = None

        #: Encoding to decode with when accessing response text.
        self.encoding = None

        #: A list of :class:`Response <Response>` objects from
        #: the history of the Request.
        self.history = []

        #: Textual reason of responded HTTP Status, e.g. "Not Found" or "OK".
        self.reason = ""

        #: A of Cookies the response headers.
        self.cookies = CaseInsensitiveDict()

        #: The amount of time elapsed between sending the request
        self.elapsed = datetime.timedelta(0)

        #: The :class:`PreparedRequest <PreparedRequest>` object to which this
        #: is a response.
        self.request = None

        # Flags do HttpAdapter set
        self.unauthorized = False
        self.set_auth_cookie = False

        # Redirect location
        self.redirect_to = None  

    def get_mime_type(self, path):
        """
        Determines the MIME type of a file based on its path.

        "params path (str): Path to the file.

        :rtype str: MIME type string (e.g., 'text/html', 'image/png').
        """

        try:
            mime_type, _ = mimetypes.guess_type(path)
        except Exception:
            return 'application/octet-stream'
        return mime_type or 'application/octet-stream'

    def prepare_content_type(self, mime_type='text/html'):
        """
        Prepares the Content-Type header and determines the base directory
        for serving the file based on its MIME type.

        :params mime_type (str): MIME type of the requested resource.

        :rtype str: Base directory path for locating the resource.

        :raises ValueError: If the MIME type is unsupported.
        """

        base_dir = ""

        # Processing mime_type based on main_type and sub_type
        main_type, sub_type = mime_type.split('/', 1)
        print("[Response] processing MIME main_type={} sub_type={}".format(main_type, sub_type))

        if main_type == 'text':
            self.headers['Content-Type'] = 'text/{}'.format(sub_type)
            if sub_type in ['plain', 'css']:
                base_dir = BASE_DIR + "static/"
            elif sub_type == 'html':
                base_dir = BASE_DIR + "www/"
            elif sub_type in ["csv","xml"]:
                base_dir = BASE_DIR + "static/"

        elif main_type == 'image':
            base_dir = BASE_DIR + "static/"
            self.headers['Content-Type'] = 'image/{}'.format(sub_type)

        elif main_type == 'application':
            base_dir = BASE_DIR + "apps/"
            self.headers['Content-Type'] = 'application/{}'.format(sub_type)
        #
        #  TODO: process other mime_type
        #        application/xml       
        #        application/zip
        #        ...
        #        text/csv
        #        text/xml
        #        ...
        #        video/mp4 
        #        video/mpeg
        #        ...
        #        
        elif main_type == 'video':
            base_dir = BASE_DIR + "static/"
            self.headers['Content-Type'] = 'video/{}'.format(sub_type)
        
        else:
            raise ValueError("Invalid MIME type")

        return base_dir

    def build_content(self, path, base_dir):
        """
        Loads the objects file from storage space.

        :params path (str): relative path to the file.
        :params base_dir (str): base directory where the file is located.

        :rtype tuple: (boolean, int, bytes) representing success status, content length and content data.
        """

        filepath = os.path.join(base_dir, path.lstrip('/'))

        print("[Response] serving the object at location {}".format(filepath))
            #
            #  TODO: implement the step of fetch the object file
            #        store in the return value of content
            #
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

    def build_rfc6265_cookie(self, 
        name, value, max_age=3600, path="/", 
        secure=False, httponly=True, samesite="Lax"):

        """
        RFC 6265 Compliant Cookie
        """

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
        Build HTTP 302 Found (Redirect) Response
        
        RFC 7231 Section 6.4.3: 302 Found
        The target resource resides temporarily under a different URI.
        """

        redirect_html = """
        <!DOCTYPE html>
        <html>
            <head>
                <meta http-equiv="refresh" content="0; url={}">
                <title>Redirecting...</title>
            </head>
            <body>
                <p>Redirecting to <a href="{}">{}</a>...</p>
            </body>
        </html>
        """.format(self.redirect_to, self.redirect_to, self.redirect_to)

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

        # Set cookie on redirect
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
        """
        Standard response header builder
        """
        # Mặc định 200 OK
        status_line = "HTTP/1.1 200 OK"

        # Thiết lập các header CORS quan trọng
        self.headers["Access-Control-Allow-Origin"] = "*"
        self.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        self.headers["Access-Control-Allow-Headers"] = "Content-Type"
        
        # Xử lý Status Code
        if self.unauthorized:
            status_line = "HTTP/1.1 401 Unauthorized"
            self.status_code = 401
        elif self.status_code == 404:
            status_line = "HTTP/1.1 404 Not Found"
        elif self.status_code == 500:
            status_line = "HTTP/1.1 500 Internal Server Error"
        elif self.status_code == 204: # Thêm case cho OPTIONS
            status_line = "HTTP/1.1 204 No Content"
        elif self.status_code == 302:
            status_line = "HTTP/1.1 302 Found"
        else:
            self.status_code = 200

        # --- [FIX BUG TẠI ĐÂY] ---
        # Phải đưa các header từ self.headers vào danh sách gửi đi
        header_lines = [status_line]
        
        # 1. Thêm Content-Type và Length mặc định nếu chưa có
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "text/html"
        self.headers["Content-Length"] = str(len(self._content))
        self.headers["Cache-Control"] = "no-cache"
        self.headers["Connection"] = "close"

        # 2. Vòng lặp quan trọng: Đưa tất cả header (bao gồm CORS) vào message
        for key, value in self.headers.items():
            header_lines.append("{}: {}".format(key, value))

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
        Builds a full HTTP response including headers and content based on the request.

        :params request (class:`Request <Request>`): incoming request object.

        :rtype bytes: complete HTTP response using prepared headers and content.
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
            elif mime_type.startswith("image/") or mime_type.startswith("video/"):
                base_dir = self.prepare_content_type(mime_type)
            elif mime_type.startswith("application/"):
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