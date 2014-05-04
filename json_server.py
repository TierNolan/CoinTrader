from __future__ import absolute_import, division, print_function, unicode_literals

import BaseHTTPServer
import base64


class JSONHTTPServer(BaseHTTPServer.HTTPServer):

    def __init__(self, username=None, password=None, *args, **kw):
        BaseHTTPServer.HTTPServer.__init__(self, *args, **kw)
        if username and password:
           self.expected_auth = 'Basic ' + base64.encodestring(username + b":" + password)
        else:
           self.expected_auth = None


class JSONHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def reject_auth(self, message):
        self.send_response(401, "Unauthorized")
        self.send_header("WWW-Authenticate", "Basic realm=\"JSON Server\"")
        self.end_headers()
        self.wfile.write("401 - Unauthorized - %s" % message)

    def accept_auth(self):
        self.send_response(200, "Success")
        self.send_header("WWW-Authenticate", "Basic realm=\"JSON Server\"")
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def handle_head(self):
        try:
            auth = self.headers['Authorization']
        except KeyError:
            self.reject_auth('Missing username and password')
            return False

        print (self.server.expected_auth)
        print (auth)

        if self.server.expected_auth and auth.strip() != self.server.expected_auth.strip():
            print ('mismatch')
            self.reject_auth("Bad username and password")
            return False

        self.accept_auth()
        return True

    def do_HEAD(self):
        self.handle_head()

    def do_GET(self):
        if self.handle_head():
            # TBD  ... need working client
            self.rfile.readline()
