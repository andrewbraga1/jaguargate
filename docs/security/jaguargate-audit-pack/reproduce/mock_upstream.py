#!/usr/bin/env python3
"""Bilateral Inspection Upstream Mock Server for JaguarGate Gate 5 Audit.

Captures every incoming request (method, path, headers, raw body) so the audit
verifier can assert Quadrant 2 (Egress / Upstream Invariant) and supports
token-echo responses and real fragmented SSE streaming for Quadrant 3 checks.
"""
import http.server
import json
import re
import socketserver
import sys
import threading
import time

RE_JG_TOKEN = re.compile(r"<JG_PII_[A-Z0-9_]+_[0-9a-f]{8,32}>")

_lock = threading.Lock()
_history = []


class BilateralUpstreamHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send_json(self, code: int, obj: dict):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/_mock/last_request":
            with _lock:
                last = _history[-1] if _history else None
            self._send_json(200, {"last_request": last, "total_captured": len(_history)})
            return
        if self.path == "/_mock/history":
            with _lock:
                snap = list(_history)
            self._send_json(200, {"history": snap, "total_captured": len(snap)})
            return
        self._send_json(200, {"status": "ok", "models": ["llama3"]})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b""
        body_text = raw_body.decode("utf-8", errors="replace")

        if self.path == "/_mock/reset":
            with _lock:
                _history.clear()
            self._send_json(200, {"reset": True})
            return

        # Quadrant 2: Capture exact request received by upstream
        record = {
            "timestamp": time.time(),
            "method": "POST",
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body_text,
        }
        with _lock:
            _history.append(record)

        # Check if request asks for SSE streaming
        wants_stream = False
        try:
            parsed = json.loads(body_text)
            if isinstance(parsed, dict) and parsed.get("stream") is True:
                wants_stream = True
        except Exception:
            pass

        # Extract any JaguarGate tokens present in the upstream request so we can echo them
        # back to test Quadrant 3 (PII restored vs Secrets withheld on output)
        tokens = RE_JG_TOKEN.findall(body_text)
        if tokens:
            reply_content = "Upstream received tokens: " + " ".join(tokens)
        else:
            reply_content = "mock upstream safe response"

        if wants_stream:
            # Emit genuine fragmented SSE frames (split across chunks)
            chunks = [
                f'data: {json.dumps({"id":"sse-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":reply_content[:12]}}]})}\n\n',
                f'data: {json.dumps({"id":"sse-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":reply_content[12:]}}]})}\n\n',
                "data: [DONE]\n\n",
            ]
            payload = "".join(chunks).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
                time.sleep(0.005)
            return

        resp = {
            "id": "upstream-mock-resp",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": reply_content}}],
        }
        self._send_json(200, resp)

    def log_message(self, format, *args):
        pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4020
    with ThreadedTCPServer(("127.0.0.1", port), BilateralUpstreamHandler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
