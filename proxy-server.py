#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
from urllib.request import RequestHandler
from http import HTTPStatus

class OAuthProxyHandler(RequestHandler):
    def __init__(self):
        super().__init__()
    
    def do_GET(self):
        if self.path.startswith('/auth/'):
            # Proxy Supabase auth requests to avoid CORS
            return self.proxy_supabase_request()
        else:
            # Serve static files
            return super().do_GET()
    
    def proxy_supabase_request(self):
        try:
            # Extract the actual Supabase URL
            supabase_url = f"https://twnkjfrpxmdmlcxswizf.supabase.co{self.path}"
            
            print(f"Proxying request to: {supabase_url}")
            
            # Create request to Supabase
            req = urllib.request.Request(supabase_url)
            
            # Copy headers from original request
            for header, value in self.headers.items():
                if header.lower() != 'host':  # Don't copy host header
                    req.add_header(header, value)
            
            # Add CORS headers
            req.add_header('Access-Control-Allow-Origin', '*')
            req.add_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            req.add_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            
            try:
                with urllib.request.urlopen(req) as response:
                    # Copy response headers
                    self.send_response(response.status, response.headers, response.read())
            except Exception as e:
                print(f"Proxy error: {e}")
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Proxy error")
    
    def send_error(self, code, message):
        self.send_response(code, [('Content-Type', 'text/plain')], message.encode())

def run_server():
    port = 3000
    server = http.server.HTTPServer(('localhost', port), OAuthProxyHandler)
    
    print(f"🚀 OAuth Proxy Server running at:")
    print(f"   Local:   http://localhost:{port}")
    print(f"   Network:  http://192.168.1.100:{port}")
    print("")
    print("📁 This server proxies Supabase auth requests to avoid CORS issues")
    print("🔗 OAuth callbacks will work properly through this proxy")
    print("")
    print("Press Ctrl+C to stop the server")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")

if __name__ == "__main__":
    run_server()
