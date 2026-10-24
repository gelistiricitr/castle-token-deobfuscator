import sys
import os
import json
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from castle_decoder import CastleTokenDecoder

decoder = CastleTokenDecoder()

class CastleDashboardHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/decode':
            try:
                content_len = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_len)
                req_data = json.loads(body.decode('utf-8'))
                token = req_data.get('token', '').strip()
                
                if not token:
                    raise ValueError("No token provided in request body")
                
                res = decoder.decode(token)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "data": res}, ensure_ascii=False).encode('utf-8'))
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode('utf-8'))
        else:
            self.send_error(404, "Endpoint not found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run_server(port=8089):
    server_address = ('127.0.0.1', port)
    httpd = ThreadingHTTPServer(server_address, CastleDashboardHandler)
    print(f"[*] Castle Token Deobfuscator Server running at http://127.0.0.1:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8089
    run_server(port)
