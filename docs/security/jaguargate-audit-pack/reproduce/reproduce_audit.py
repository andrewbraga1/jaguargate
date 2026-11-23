#!/usr/bin/env python3
"""
JaguarGate Gate 5 — 4-Stage Bilateral Audit Verifier
=====================================================
Enforces the Kaizen Bidirectional 4-Stage Invariant on every single vector:
  Stage 1 (Ingress):          Exact synthetic payload sent into JaguarGate.
  Stage 2 (Gateway Decision): HTTP status, X-JaguarGate-Status, X-JaguarGate-Codes
                              (and SSE warning events), veto/pruning telemetry.
  Stage 3 (Upstream Capture): Exact bytes received by mock_upstream, asserting
                              masked tokens arrived, raw PII/secrets NEVER leaked,
                              and upstream_reached == False when pre-blocked.
  Stage 4 (Egress Delivery):  Exact upstream response (including individual SSE
                              fragments proving true mid-token splitting) vs.
                              reconstructed client output (restoration / withholding /
                              JG-SEC-503 active output DLP / JG-SEC-501 halt).
  Control (Q4 Positive):      Direct-to-upstream bypass probe proving mock_upstream
                              genuinely captures raw PII when JaguarGate is bypassed.

Usage:
    python3 reproduce_audit.py <GATEWAY_URL> <MOCK_UPSTREAM_URL>
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

RE_JG_TOKEN = re.compile(r"<JG_PII_[A-Z0-9_]+_[0-9a-f]{8,32}>")
RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")


def http_json(method: str, url: str, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def parse_sse_client_stream(raw_text: str):
    """Parse SSE response into reconstructed delta text, event count, and warning codes."""
    reconstructed = []
    data_events = 0
    sse_codes = []
    sse_status = ""
    current_event = ""

    for line in raw_text.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("event:"):
            current_event = trimmed[len("event:") :].strip()
            continue
        if not trimmed.startswith("data:"):
            if trimmed == "":
                current_event = ""
            continue
        payload_str = trimmed[len("data:") :].strip()
        if payload_str == "[DONE]":
            continue
        try:
            obj = json.loads(payload_str)
        except Exception:
            continue

        if current_event == "jaguargate.warning" and isinstance(obj, dict):
            for c in obj.get("codes") or []:
                if c not in sse_codes:
                    sse_codes.append(c)
            if obj.get("status"):
                sse_status = str(obj["status"])
            continue

        if isinstance(obj, dict) and isinstance(obj.get("choices"), list):
            data_events += 1
            for ch in obj["choices"]:
                if isinstance(ch, dict):
                    delta = ch.get("delta") or {}
                    if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                        reconstructed.append(delta["content"])

    return "".join(reconstructed), data_events, sse_codes, sse_status


def run_positive_control(mock_url: str) -> bool:
    """Q4 Positive Control: Prove raw CPF reaches mock_upstream when bypassing JaguarGate."""
    print("\n--- [Q4 POSITIVE CONTROL] Direct-to-Upstream Leak Detection Check ---")
    http_json("POST", f"{mock_url}/_mock/reset")
    control_cpf = "52998224725"
    http_json(
        "POST",
        f"{mock_url}/v1/chat/completions",
        {"model": "llama3", "messages": [{"role": "user", "content": f"Control CPF {control_cpf}"}]},
    )
    _, cap = http_json("GET", f"{mock_url}/_mock/last_request")
    last_req = cap.get("last_request") or {}
    captured_body = last_req.get("body", "")
    if control_cpf not in captured_body:
        print("  [ABORT] Positive control FAILED: mock upstream did not capture raw CPF!")
        return False
    print(f"  [OK] Positive control PASSED: mock captured raw CPF ({control_cpf}) when bypassing gateway.")
    http_json("POST", f"{mock_url}/_mock/reset")
    return True


def main():
    gateway_url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:4010"
    mock_url = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else "http://127.0.0.1:4020"

    script_dir = os.path.dirname(os.path.abspath(__file__))
    vectors_path = os.path.join(script_dir, "test_vectors.json")
    report_path = os.path.join(script_dir, "..", "findings", "full_campaign_report.json")

    with open(vectors_path, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    print("=" * 88)
    print("  JAGUARGATE GATE 5 — 4-STAGE BILATERAL AUDIT VERIFIER")
    print(f"  Gateway Target:  {gateway_url}")
    print(f"  Upstream Mock:   {mock_url}")
    print("=" * 88)

    if not run_positive_control(mock_url):
        sys.exit(2)

    total_probes = 0
    passed_probes = 0
    findings = []
    evidence_log = []

    for front_name, rounds in vectors.items():
        print(f"\n--- [{front_name}] Executing {len(rounds)} 4-stage bilateral vectors ---")
        for i, vec in enumerate(rounds, 1):
            total_probes += 1
            tech = vec["technique"]
            endpoint = vec.get("endpoint", "/v1/chat/completions")
            headers = dict(vec.get("headers", {"Content-Type": "application/json"}))

            # Reset mock capture before each probe so Stage 3 is 100% isolated
            http_json("POST", f"{mock_url}/_mock/reset")

            if "raw_body" in vec:
                ingress_text = vec["raw_body"]
                data = ingress_text.encode("utf-8")
            else:
                payload_obj = json.loads(json.dumps(vec["payload"]))
                if "repeat_padding_bytes" in vec and isinstance(payload_obj, dict):
                    payload_obj["padding"] = "P" * int(vec["repeat_padding_bytes"])
                ingress_text = json.dumps(payload_obj, ensure_ascii=False)
                data = ingress_text.encode("utf-8")

            req = urllib.request.Request(
                f"{gateway_url}{endpoint}",
                data=data,
                headers=headers,
                method="POST",
            )

            t0 = time.perf_counter()
            resp_headers = {}
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    elapsed_ms = (time.perf_counter() - t0) * 1000
                    client_body = resp.read().decode("utf-8", errors="replace")
                    status = resp.status
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                client_body = e.read().decode("utf-8", errors="replace")
                status = e.code
                resp_headers = {k.lower(): v for k, v in e.headers.items()}
            except Exception as e:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                findings.append({"front": front_name, "round": i, "technique": tech, "error": str(e)})
                print(f"  [FAIL] r{i:02d} {tech:<44} -> transport error: {e}")
                continue

            # Stage 3 & Stage 4a: Inspect what actually reached mock_upstream and what it sent back
            _, cap = http_json("GET", f"{mock_url}/_mock/last_request")
            last_req = cap.get("last_request")
            upstream_reached = last_req is not None
            upstream_body = last_req["body"] if last_req else ""
            upstream_resp_mode = last_req.get("response_mode", "none") if last_req else "none"
            upstream_resp_sent = last_req.get("response_content_sent", "") if last_req else ""
            upstream_sse_fragments = last_req.get("sse_fragments_sent", []) if last_req else []

            # Parse Stage 2 & Stage 4b telemetry (headers + SSE reconstructed text/warnings)
            is_sse_client = "text/event-stream" in resp_headers.get("content-type", "").lower()
            reconstructed_text = ""
            client_sse_events = 0
            sse_codes = []
            sse_status = ""
            if is_sse_client:
                reconstructed_text, client_sse_events, sse_codes, sse_status = parse_sse_client_stream(client_body)

            hdr_status = resp_headers.get("x-jaguargate-status", "")
            effective_status = sse_status or hdr_status
            hdr_codes = [c.strip() for c in resp_headers.get("x-jaguargate-codes", "").split(",") if c.strip()]
            all_codes = list(dict.fromkeys(hdr_codes + sse_codes))
            effective_client_text = reconstructed_text if is_sse_client else client_body

            failures = []

            # --- STAGE 2 ASSERTIONS (Gateway Decision & Telemetry) ---
            allowed_statuses = vec.get("allowed_statuses", [200])
            if status not in allowed_statuses:
                failures.append(f"Stage2 HTTP {status} not in allowed {allowed_statuses}")

            expected_gw_status = vec.get("expect_gateway_status")
            if expected_gw_status and effective_status != expected_gw_status:
                failures.append(f"Stage2 status={effective_status!r}, expected {expected_gw_status!r}")

            for req_code in vec.get("expect_codes", []):
                if req_code not in all_codes and req_code not in client_body:
                    failures.append(f"Stage2 missing required code {req_code!r} (got codes={all_codes})")

            # --- STAGE 3 ASSERTIONS (Upstream Arrival / Pre-Upstream Block) ---
            if "expect_upstream_reached" in vec:
                want_reached = bool(vec["expect_upstream_reached"])
                if upstream_reached != want_reached:
                    failures.append(f"Stage3 upstream_reached={upstream_reached}, expected {want_reached}")

            for secret_str in vec.get("must_not_reach_upstream", []):
                if upstream_reached and secret_str in upstream_body:
                    failures.append(f"Stage3 UPSTREAM LEAK: {secret_str!r} reached provider unmasked!")

            expected_mask = vec.get("must_reach_upstream_masked")
            if expected_mask:
                if not upstream_reached:
                    failures.append(f"Stage3 expected masked token {expected_mask!r}, but upstream was not reached")
                elif expected_mask not in upstream_body:
                    failures.append(f"Stage3 DETECTOR MISSED: expected {expected_mask!r} in upstream body")

            expected_verbatim = vec.get("must_reach_upstream_verbatim")
            if expected_verbatim:
                if not upstream_reached or expected_verbatim not in upstream_body:
                    failures.append(f"Stage3 FALSE POSITIVE: benign string {expected_verbatim!r} altered/blocked")

            # --- STAGE 4 ASSERTIONS (Upstream Egress / True SSE Fragmentation -> Client Delivery) ---
            if vec.get("require_mid_token_sse_split"):
                if len(upstream_sse_fragments) < 3:
                    failures.append(
                        f"Stage4 SSE fragmentation too coarse: only {len(upstream_sse_fragments)} fragments sent"
                    )
                else:
                    for frag in upstream_sse_fragments:
                        if RE_JG_TOKEN.search(frag):
                            failures.append(f"Stage4 FAKE SSE SPLIT: full <JG_PII_...> token found intact in one chunk {frag!r}")
                        if RE_AWS_KEY.search(frag):
                            failures.append(f"Stage4 FAKE SSE SPLIT: full AWS key found intact in one chunk {frag!r}")

            expected_restore = vec.get("must_restore_in_client")
            if expected_restore and expected_restore not in effective_client_text:
                failures.append(
                    f"Stage4 RESTORE FAILED: expected {expected_restore!r} in client delivery ({effective_client_text[:160]!r})"
                )

            for forbidden_client in vec.get("must_not_leak_in_client", []):
                if forbidden_client in client_body or forbidden_client in effective_client_text:
                    failures.append(f"Stage4 CLIENT LEAK: forbidden {forbidden_client!r} delivered to client!")

            expected_client_marker = vec.get("must_contain_in_client")
            if expected_client_marker:
                if expected_client_marker not in client_body and expected_client_marker not in effective_client_text:
                    failures.append(f"Stage4 missing expected marker {expected_client_marker!r} in client response")

            entry = {
                "front": front_name,
                "round": i,
                "technique": tech,
                "latency_ms": round(elapsed_ms, 2),
                "stage1_ingress": {
                    "endpoint": endpoint,
                    "session_id": headers.get("X-JaguarGate-Session-ID", "default_session"),
                    "body_bytes": len(data),
                    "body_preview": ingress_text[:280],
                },
                "stage2_gateway_decision": {
                    "http_status": status,
                    "x_jaguargate_status": effective_status,
                    "x_jaguargate_severity": resp_headers.get("x-jaguargate-severity", ""),
                    "x_jaguargate_codes": all_codes,
                    "x_jaguargate_veto": resp_headers.get("x-jaguargate-veto", ""),
                },
                "stage3_upstream_capture": {
                    "upstream_reached": upstream_reached,
                    "body_preview": upstream_body[:320],
                },
                "stage4_egress_delivery": {
                    "response_mode": upstream_resp_mode,
                    "upstream_response_sent": upstream_resp_sent[:240],
                    "upstream_sse_fragments": upstream_sse_fragments,
                    "client_sse_events_count": client_sse_events,
                    "reconstructed_client_text": reconstructed_text[:240] if is_sse_client else "",
                    "client_body_preview": client_body[:320],
                },
                "passed": len(failures) == 0,
                "failures": failures,
            }
            evidence_log.append(entry)

            if failures:
                findings.append(entry)
                print(f"  [FAIL] r{i:02d} {tech:<44} -> HTTP {status} | {'; '.join(failures)}")
            else:
                passed_probes += 1
                print(
                    f"  [PASS] r{i:02d} {tech:<44} -> HTTP {status} [{effective_status or 'N/A'} {','.join(all_codes) or '-'}] ({elapsed_ms:.1f}ms)"
                )

    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "suite": "JaguarGate Gate 5 — 4-Stage Bilateral Audit",
                "gateway_url": gateway_url,
                "mock_upstream_url": mock_url,
                "positive_control_passed": True,
                "total_probes": total_probes,
                "passed_probes": passed_probes,
                "findings_count": len(findings),
                "results": evidence_log,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print("\n" + "=" * 88)
    print(f" RESULTS: Executed {total_probes} | Passed {passed_probes} | Findings: {len(findings)}")
    print(f" Evidence saved to: {os.path.abspath(report_path)}")
    print("=" * 88)
    if findings:
        print(" [FAIL] Bilateral Gate 5 verification detected failures.")
        sys.exit(1)
    else:
        print(f" [PASS] All {passed_probes}/{total_probes} 4-stage bilateral vectors passed under tested configuration.")
        sys.exit(0)


if __name__ == "__main__":
    main()
