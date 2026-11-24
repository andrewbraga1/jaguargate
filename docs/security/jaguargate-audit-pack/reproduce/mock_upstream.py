#!/usr/bin/env python3
"""Bilateral Inspection Upstream Mock Server for JaguarGate Gate 5 Audit.

Captures every incoming request (method, path, headers, raw body) AND records
the exact response / SSE fragments emitted back to JaguarGate so the audit
verifier can assert all 4 stages of the Kaizen Bidirectional Invariant.
"""
import http.server
import json
import re
import socketserver
import sys
import threading
import time

RE_JG_TOKEN = re.compile(r"<JG_PII_[A-Z0-9_]+_[0-9a-f]{8,32}>")
RE_JG_CANARY = re.compile(r"\[JG-CANARY:(jg_cnry_[0-9a-f]+)\]")

SYNTHETIC_PEM_HEADER = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
SYNTHETIC_PEM_BODY_1 = "MIIETESTSYNTHETICKEYBODY0000111122223333444455556666777788889999AAAABBBBCCCCDDDD"
SYNTHETIC_PEM_BODY_2 = "EEEEFFFF0000111122223333444455556666777788889999SYNTHETICKEYENDMATERIAL9999=="
SYNTHETIC_PEM_FOOTER = "-----" + "END RSA PRIVATE KEY" + "-----"

_lock = threading.Lock()
_history = []


def split_sse_fragments(text: str):
    """Split text into SSE delta fragments that cut *inside* sensitive tokens/secrets."""
    # 1. Cut PEM block across 4 SSE events (header, body1, body2, footer+suffix)
    if SYNTHETIC_PEM_HEADER in text:
        h_idx = text.find(SYNTHETIC_PEM_HEADER)
        f_idx = text.find(SYNTHETIC_PEM_FOOTER)
        if f_idx != -1:
            mid_body = (h_idx + len(SYNTHETIC_PEM_HEADER) + f_idx) // 2
            f_cut = f_idx + 12  # Split right inside -----END RSA PRIVATE KEY----- too!
            return [
                text[: h_idx + 14],
                text[h_idx + 14 : mid_body],
                text[mid_body:f_cut],
                text[f_cut:],
            ]

    # 2. Cut right inside the first <JG_PII_...> token across 3+ distinct chunks
    m = RE_JG_TOKEN.search(text)
    if m:
        s, e = m.start(), m.end()
        tok = text[s:e]
        cut1 = s + min(10, max(4, len(tok) // 3))
        cut2 = s + min(len(tok) - 4, max(cut1 + 4, (2 * len(tok)) // 3))
        parts = [
            text[:cut1],
            text[cut1:cut2],
            text[cut2:e],
        ]
        if e < len(text):
            parts.append(text[e:])
        return [p for p in parts if p]

    # 3. Cut right inside a spontaneous AWS key (AKIA...) across 3 distinct chunks
    akia_idx = text.find("AKIA")
    if akia_idx != -1 and akia_idx + 20 <= len(text):
        parts = [
            text[: akia_idx + 8],
            text[akia_idx + 8 : akia_idx + 14],
            text[akia_idx + 14 :],
        ]
        return [p for p in parts if p]

    # 4. Cut right inside a canary token if echoed
    cnry_idx = text.find("jg_cnry_")
    if cnry_idx != -1 and cnry_idx + 14 <= len(text):
        return [text[: cnry_idx + 6], text[cnry_idx + 6 : cnry_idx + 11], text[cnry_idx + 11 :]]

    mid = max(1, len(text) // 2)
    return [text[:mid], text[mid:]] if len(text) > 1 else [text]


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

        wants_stream = False
        try:
            parsed = json.loads(body_text)
            if isinstance(parsed, dict) and parsed.get("stream") is True:
                wants_stream = True
        except Exception:
            pass

        mock_behavior = (self.headers.get("X-Mock-Behavior") or "").strip().lower()
        tokens = RE_JG_TOKEN.findall(body_text)

        # Tool call leak mode (JG-R2: tests output tool_calls arguments DLP in JSON & SSE)
        if mock_behavior == "leak_tool_call_secret" or mock_behavior == "leak_tool_call_deep_secret":
            if mock_behavior == "leak_tool_call_deep_secret":
                # Build 18-level nested JSON object exceeding maxOutputJSONDepth (16) containing a secret at leaf
                deep_node = {"secret": "AKIAZ9X8W7V6U5T4S3R2"}
                for lvl in range(17, 0, -1):
                    deep_node = {f"l{lvl}": deep_node}
                tool_args = json.dumps({"target": "audit", "nested": deep_node}, separators=(",", ":"))
            else:
                tool_args = '{"target":"audit","secret":"AKIAZ9X8W7V6U5T4S3R2"}'
            sse_fragments = split_sse_fragments(tool_args) if wants_stream else []
            record = {
                "timestamp": time.time(),
                "method": "POST",
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body_text,
                "response_mode": "sse_tool_calls" if wants_stream else "json_tool_calls",
                "response_content_sent": tool_args,
                "sse_fragments_sent": sse_fragments,
            }
            with _lock:
                _history.append(record)

            if wants_stream:
                chunks = []
                for idx, frag in enumerate(sse_fragments):
                    tc = {"index": 0, "function": {"arguments": frag}}
                    if idx == 0:
                        tc["id"] = "call_mock_1"
                        tc["type"] = "function"
                        tc["function"]["name"] = "send_audit"
                    ev = {
                        "id": "sse-tc-1",
                        "object": "chat.completion.chunk",
                        "choices": [{"index": 0, "delta": {"tool_calls": [tc]}}],
                    }
                    chunks.append(f"data: {json.dumps(ev)}\n\n")
                chunks.append(
                    f'data: {json.dumps({"id":"sse-tc-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]})}\n\n'
                )
                chunks.append("data: [DONE]\n\n")
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
                "id": "upstream-mock-tc",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_mock_1",
                                    "type": "function",
                                    "function": {"name": "send_audit", "arguments": tool_args},
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
            }
            self._send_json(200, resp)
            return

        if mock_behavior == "leak_spontaneous_secret":
            reply_content = "Debug config key: AKIAZ9X8W7V6U5T4S3R2 active."
        elif mock_behavior == "leak_full_pem_key":
            reply_content = (
                f"Key dump: {SYNTHETIC_PEM_HEADER}\n"
                f"{SYNTHETIC_PEM_BODY_1}\n{SYNTHETIC_PEM_BODY_2}\n"
                f"{SYNTHETIC_PEM_FOOTER} end."
            )
        elif mock_behavior == "echo_canary":
            cm = RE_JG_CANARY.search(body_text)
            reply_content = f"Leaked system marker: {cm.group(1)} end." if cm else "no canary present"
        elif tokens:
            reply_content = "Upstream received tokens: " + " ".join(tokens) + "."
        else:
            reply_content = "mock upstream safe response"

        sse_fragments = split_sse_fragments(reply_content) if wants_stream else []

        record = {
            "timestamp": time.time(),
            "method": "POST",
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body_text,
            "response_mode": "sse" if wants_stream else "json",
            "response_content_sent": reply_content,
            "sse_fragments_sent": sse_fragments,
        }
        with _lock:
            _history.append(record)

        if wants_stream:
            chunks = []
            for idx, frag in enumerate(sse_fragments):
                delta = {"content": frag}
                if idx == 0:
                    delta["role"] = "assistant"
                event = {
                    "id": "sse-1",
                    "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": delta}],
                }
                chunks.append(f"data: {json.dumps(event)}\n\n")
            chunks.append("data: [DONE]\n\n")

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
