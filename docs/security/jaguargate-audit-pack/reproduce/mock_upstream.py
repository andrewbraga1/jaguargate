#!/usr/bin/env python3
"""Minimal upstream LLM server for JaguarGate proxy testing on 127.0.0.1:11434."""
import sys
import http.server
import socketserver
import json

class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","models":["llama3"]}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {
            "id": "upstream-mock-resp",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": "mock upstream safe response"}}]
        }
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def log_message(self, format, *args):
        pass

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4020
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), UpstreamHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    main()
