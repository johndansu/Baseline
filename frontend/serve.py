#!/usr/bin/env python3
"""
Simple HTTP server to serve Baseline frontend files
"""

import http.server
import socketserver
import os
import sys
from urllib.parse import unquote

class CORSHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
    
    def do_GET(self):
        # Get current directory
        path = self.translate_path(self.path)
        if path == '/':
            path = '/index.html'
        
        # Security check - prevent directory traversal
        if '..' in path or path.startswith('/..'):
            self.send_error(403, "Forbidden")
            return
        
        try:
            # Try to serve file
            full_path = os.path.join(os.getcwd(), path.lstrip('/'))
            if os.path.isfile(full_path):
                # Determine content type
                if path.endswith('.css'):
                    content_type = 'text/css'
                elif path.endswith('.js'):
                    content_type = 'application/javascript'
                elif path.endswith('.html'):
                    content_type = 'text/html'
                elif path.endswith('.png'):
                    content_type = 'image/png'
                else:
                    content_type = 'text/plain'
                
                with open(full_path, 'rb') as f:
                    content = f.read()
                    self.send_response(200, content, content_type)
            else:
                self.send_error(404, f"File not found: {path}")
        except Exception as e:
            self.send_error(500, f"Server error: {str(e)}")

def main():
    port = 8001
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port number: {sys.argv[1]}")
            sys.exit(1)
    else:
        port = 8001
    
    server_address = ('', port)
    
    print(f"🚀 Starting Baseline Frontend Server")
    print(f"📍 Server: http://localhost:{port}")
    print(f"📁 Serving files from: {os.getcwd()}")
    print(f"🌐 Open in browser: http://localhost:{port}/index.html")
    print(f"🛑 Press Ctrl+C to stop server")
    
    try:
        # Create server with CORS support
        httpd = socketserver.TCPServer(server_address, CORSHTTPRequestHandler)
        httpd = http.server.HTTPServer(httpd, CORSHTTPRequestHandler)
        
        print(f"✅ Server running on port {port}")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n🛑 Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == '__main__':
    main()
