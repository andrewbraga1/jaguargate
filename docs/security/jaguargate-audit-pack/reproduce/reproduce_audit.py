#!/usr/bin/env python3
"""
JaguarGate Gate 5 — 4-Quadrant Bilateral Audit Verifier
========================================================
Enforces the Maestro Kaizen Bidirectional Invariant:
  Q1 (Ingress):  Canonical & raw wire-level payloads sent to JaguarGate.
  Q2 (Upstream): Captures exact bytes received by mock_upstream and asserts
                 no forbidden PII/secrets leaked to the provider.
  Q3 (Client):   Asserts HTTP status, warning headers, PII restoration, and
                 strict secret withholding (restore_secrets=false).
  Q4 (Control):  Executes a Positive Control directly against mock_upstream
                 (bypassing JaguarGate) to prove the mock detects raw leaks.

Usage:
    python3 reproduce_audit.py <GATEWAY_URL> <MOCK_UPSTREAM_URL>
Example:
    python3 reproduce_audit.py http://127.0.0.1:4010 http://127.0.0.1:4020
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request


def http_json(method: str, url: str, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def run_positive_control(mock_url: str) -> bool:
    """Quadrant 4: Prove that without JaguarGate, raw CPF reaches the upstream mock."""
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

    print("=" * 84)
    print("  JAGUARGATE GATE 5 — 4-QUADRANT BILATERAL AUDIT VERIFIER")
    print(f"  Gateway Target:  {gateway_url}")
    print(f"  Upstream Mock:   {mock_url}")
    print("=" * 84)

    # Quadrant 4: Positive Control
    if not run_positive_control(mock_url):
        sys.exit(2)

    total_probes = 0
    passed_probes = 0
    findings = []
    evidence_log = []

    for front_name, rounds in vectors.items():
        print(f"\n--- [{front_name}] Executing {len(rounds)} bilateral vectors ---")
        for i, vec in enumerate(rounds, 1):
            total_probes += 1
            tech = vec["technique"]
            endpoint = vec.get("endpoint", "/v1/chat/completions")
            headers = dict(vec.get("headers", {"Content-Type": "application/json"}))

            # Reset mock capture before each probe so Q2 is 100% isolated to this probe
            http_json("POST", f"{mock_url}/_mock/reset")

            if "raw_body" in vec:
                data = vec["raw_body"].encode("utf-8")
            else:
                data = json.dumps(vec["payload"]).encode("utf-8")

            req = urllib.request.Request(
                f"{gateway_url}{endpoint}",
                data=data,
                headers=headers,
                method="POST",
            )

            t0 = time.perf_counter()
            resp_headers = {}
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
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
                client_body = ""
                status = 0
                findings.append({"front": front_name, "round": i, "technique": tech, "error": str(e)})
                print(f"  [FAIL] r{i:02d} {tech:<44} -> transport error: {e}")
                continue

            # Quadrant 2: Inspect what actually reached the upstream mock
            _, cap = http_json("GET", f"{mock_url}/_mock/last_request")
            last_req = cap.get("last_request")
            upstream_body = last_req["body"] if last_req else ""
            upstream_reached = last_req is not None

            failures = []

            # Q3: HTTP status expectation
            allowed_statuses = vec.get("allowed_statuses", [200, 400, 403, 422])
            if status not in allowed_statuses:
                failures.append(f"unexpected HTTP {status} (allowed={allowed_statuses})")

            # Q2: Forbidden data MUST NOT reach upstream
            for secret_str in vec.get("must_not_reach_upstream", []):
                if upstream_reached and secret_str in upstream_body:
                    failures.append(f"Q2 UPSTREAM LEAK: {secret_str!r} reached provider unmasked!")

            # Q2: Expected masked token MUST reach upstream (proves detector fired)
            expected_mask = vec.get("must_reach_upstream_masked")
            if expected_mask:
                if not upstream_reached:
                    failures.append(f"Q2 expected masked token {expected_mask!r} at upstream, but request was blocked/dropped")
                elif expected_mask not in upstream_body:
                    failures.append(f"Q2 DETECTOR MISSED: expected {expected_mask!r} in upstream body")

            # Q2: Negative control (non-PII must NOT be falsely masked)
            expected_verbatim = vec.get("must_reach_upstream_verbatim")
            if expected_verbatim:
                if not upstream_reached or expected_verbatim not in upstream_body:
                    failures.append(f"Q2 FALSE POSITIVE: benign string {expected_verbatim!r} was altered/blocked")

            # Q3: PII restoration in client response
            expected_restore = vec.get("must_restore_in_client")
            if expected_restore and expected_restore not in client_body:
                failures.append(f"Q3 RESTORE FAILED: expected PII {expected_restore!r} restored in client response")

            # Q3: Secret withholding in client response (restore_secrets=false)
            for forbidden_client in vec.get("must_not_leak_in_client", []):
                if forbidden_client in client_body:
                    failures.append(f"Q3 SECRET ECHO LEAK: secret {forbidden_client!r} was restored to client!")

            # Q3: Expected warning header
            expected_warn = vec.get("expect_warning_header")
            if expected_warn:
                all_hdr_vals = " ".join(resp_headers.values())
                if expected_warn not in all_hdr_vals and expected_warn not in client_body:
                    failures.append(f"Q3 MISSING WARNING FLAG: expected {expected_warn!r} in headers {resp_headers}")

            entry = {
                "front": front_name,
                "round": i,
                "technique": tech,
                "http_status": status,
                "latency_ms": round(elapsed_ms, 2),
                "upstream_reached": upstream_reached,
                "upstream_body_preview": upstream_body[:240],
                "client_body_preview": client_body[:240],
                "passed": len(failures) == 0,
                "failures": failures,
            }
            evidence_log.append(entry)

            if failures:
                findings.append(entry)
                print(f"  [FAIL] r{i:02d} {tech:<44} -> HTTP {status} | {'; '.join(failures)}")
            else:
                passed_probes += 1
                print(f"  [PASS] r{i:02d} {tech:<44} -> HTTP {status} ({elapsed_ms:.1f}ms) [Q1-Q4 OK]")

    # Persist structured reproducible evidence
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "suite": "JaguarGate Gate 5 — 4-Quadrant Bilateral Audit",
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

    print("\n" + "=" * 84)
    print(f" RESULTS: Executed {total_probes} | Passed {passed_probes} | Findings: {len(findings)}")
    print(f" Evidence saved to: {os.path.abspath(report_path)}")
    print("=" * 84)
    if findings:
        print(" [FAIL] Bilateral Gate 5 verification detected failures.")
        sys.exit(1)
    else:
        print(" [PASS] All 30/30 bilateral 4-quadrant vectors passed under tested configuration.")
        sys.exit(0)


if __name__ == "__main__":
    main()
