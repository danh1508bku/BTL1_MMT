# ============================================
# request.py - RFC 6265 Compliant Cookie Parsing
# ============================================

from .dictionary import CaseInsensitiveDict
import urllib
import re

class Request():

    __attrs__ = [
        "method", "url", "headers", "body", "reason",
        "cookies", "routes", "hook", "path", "version"
    ]

    def __init__(self):
        self.method = None
        self.url = None
        self.headers = None
        self.path = None        
        self.cookies = {}
        self.body = ""
        self.routes = {}
        self.hook = None
        self.version = None

    def extract_request_line(self, request):
        try:
            lines = request.splitlines()
            if not lines:
                return None, None, None
                
            first_line = lines[0]
            parts = first_line.split()
            
            if len(parts) != 3:
                return None, None, None
                
            method, path, version = parts

            if path == '/':
                path = '/index.html'
                
            return method, path, version
            
        except Exception as e:
            print("[Request] Error parsing request line: {}".format(e))
            return None, None, None
             
    def prepare_headers(self, request):
        lines = request.split('\r\n')
        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                key, val = line.split(': ', 1)
                headers[key.lower()] = val
        return headers

    def parse_rfc6265_cookies(self, cookie_header):
        """
        ✅ RFC 6265 Section 4.2 - Cookie Header Parsing
        
        Properly handles:
        - Multiple cookies separated by semicolons
        - Whitespace trimming
        - Invalid cookie formats
        """
        cookies = {}
        
        if not cookie_header:
            return cookies
        
        # RFC 6265 Section 4.2.1: cookie-string = cookie-pair *( ";" SP cookie-pair )
        pairs = cookie_header.split(";")
        
        for pair in pairs:
            pair = pair.strip()
            if "=" not in pair:
                continue  # Invalid cookie, skip
            
            try:
                name, value = pair.split("=", 1)
                name = name.strip()
                value = value.strip()
                
                # RFC 6265 Section 4.1.1 - Validate cookie-name
                if self.is_valid_cookie_name(name):
                    cookies[name] = value
                else:
                    print("[Request] Invalid cookie name: {}".format(name))
                    
            except ValueError:
                print("[Request] Malformed cookie pair: {}".format(pair))
                continue
        
        return cookies
    
    def is_valid_cookie_name(self, name):
        """
        ✅ RFC 6265 Section 4.1.1 - Cookie Name Validation
        cookie-name must not contain: ( ) < > @ , ; : \ " / [ ] ? = { } SP HT
        """
        if not name:
            return False
        
        invalid_chars = r'[()<>@,;:\\"/\[\]?={}\s]'
        return not re.search(invalid_chars, name)

    def prepare(self, request, routes=None):
        self.method, self.path, self.version = self.extract_request_line(request)
        
        if self.method is None:
            print("[Request] Failed to parse request line")
            return False
            
        print("[Request] {} path {} version {}".format(self.method, self.path, self.version))

        if routes is not None and routes != {}:
            self.routes = routes
            self.hook = routes.get((self.method, self.path))

        self.headers = self.prepare_headers(request)

        # ✅ RFC 6265 Compliant Cookie Parsing
        cookie_header = self.headers.get("cookie", "")
        self.cookies = self.parse_rfc6265_cookies(cookie_header)
        
        print("[Request] Parsed cookies: {}".format(self.cookies))

        if "\r\n\r\n" in request:
            self.body = request.split("\r\n\r\n", 1)[1]
        else:
            self.body = ""

        return True

    def prepare_body(self, data, files=None, json=None):
        if json is not None:
            import json as json_module
            self.body = json_module.dumps(json)
        elif data:
            if isinstance(data, dict):
                self.body = urllib.parse.urlencode(data)
            else:
                self.body = str(data)
        
        self.prepare_content_length(self.body)
        return

    def prepare_content_length(self, body):
        if body:
            self.headers["Content-Length"] = str(len(body))
        else:
            self.headers["Content-Length"] = "0"
        return

    def prepare_auth(self, auth, url=""):
        # TODO: Implement RFC 7617 (Basic Auth) if needed
        return

    def prepare_cookies(self, cookies):
        if cookies:
            if isinstance(cookies, dict):
                cookie_str = "; ".join(["{}={}".format(k, v) for k, v in cookies.items()])
                self.headers["Cookie"] = cookie_str
            else:
                self.headers["Cookie"] = str(cookies)
        return