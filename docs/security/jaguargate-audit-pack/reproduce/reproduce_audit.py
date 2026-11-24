#!/usr/bin/env python3
"""
JaguarGate Gate 5 — Strict 4-Stage Bilateral Audit Verifier (with Provenance & Mutation Check)
==============================================================================================
Enforces the Kaizen Bidirectional 4-Stage Invariant on every vector:
  Stage 1 (Ingress):          Full synthetic payload sent into JaguarGate.
  Stage 2 (Gateway Decision): HTTP status + structured telemetry ONLY (X-JaguarGate-* headers
                              and structured SSE jaguargate.warning events — never body substrings).
  Stage 3 (Upstream Capture): Full bytes received by mock_upstream, asserting masked tokens
                              arrived, raw PII/secrets NEVER leaked, and upstream_reached == False
                              when pre-blocked.
  Stage 4 (Egress Delivery):  Full upstream response + individual SSE fragments (proving BOTH
                              absence of complete token in any single fragment AND presence of
                              complete token in joined fragments) vs. exact client reconstruction.
  Controls:
    - Q4 Positive Control:    Direct-to-upstream bypass probe proving mock captures raw PII.
    - Q5 Mutation Self-Test:  Deliberately unsafe synthetic mutations injected into the oracle
                              proving the verifier deterministically fails on regressions.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

RE_JG_TOKEN = re.compile(r"<JG_PII_[A-Z0-9_]+_[0-9a-f]{8,32}>")
RE_AWS_KEY = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
RE_PEM_FULL = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)


def sha256_file(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get_git_provenance(repo_dir: str) -> dict:
    info = {
        "git_commit": "unknown",
        "git_dirty": False,
        "git_modified_files": [],
        "git_worktree_diff_sha256": "",
    }
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo_dir, stderr=subprocess.DEVNULL
        )
        info["git_commit"] = out.decode("utf-8").strip()
        status_out = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=repo_dir, stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="replace")
        dirty_lines = [ln.strip() for ln in status_out.splitlines() if ln.strip()]
        if dirty_lines:
            info["git_dirty"] = True
            info["git_modified_files"] = dirty_lines
            diff_bytes = subprocess.check_output(
                ["git", "diff", "HEAD"], cwd=repo_dir, stderr=subprocess.DEVNULL
            )
            info["git_worktree_diff_sha256"] = hashlib.sha256(diff_bytes).hexdigest()
    except Exception:
        pass
    return info


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
    """Parse SSE response into reconstructed content, reconstructed tool args, event count, and structured warning codes."""
    reconstructed = []
    tool_args_parts = []
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
                if not isinstance(ch, dict):
                    continue
                delta = ch.get("delta") or {}
                if not isinstance(delta, dict):
                    continue
                if isinstance(delta.get("content"), str):
                    reconstructed.append(delta["content"])
                if isinstance(delta.get("tool_calls"), list):
                    for tc in delta["tool_calls"]:
                        if isinstance(tc, dict) and isinstance(tc.get("function"), dict):
                            arg_part = tc["function"].get("arguments")
                            if isinstance(arg_part, str):
                                tool_args_parts.append(arg_part)

    return "".join(reconstructed), "".join(tool_args_parts), data_events, sse_codes, sse_status


def extract_json_assistant_outputs(client_body: str):
    """Extract assistant content string and tool_calls arguments string from JSON response."""
    try:
        obj = json.loads(client_body)
    except Exception:
        return "", ""
    if not isinstance(obj, dict):
        return "", ""
    choices = obj.get("choices")
    if isinstance(choices, list) and choices:
        msg = (choices[0] or {}).get("message") or {}
        if isinstance(msg, dict):
            content = msg.get("content") if isinstance(msg.get("content"), str) else ""
            tcs = msg.get("tool_calls")
            if isinstance(tcs, list) and tcs:
                fn = (tcs[0] or {}).get("function") or {}
                args_str = fn.get("arguments") if isinstance(fn.get("arguments"), str) else ""
                return content, args_str
            return content, ""
    return "", ""


def validate_vector_schema(vec: dict, front: str, idx: int):
    """Enforce mandatory expectations on every vector definition."""
    required = ["technique", "allowed_statuses", "expect_gateway_status", "expect_upstream_reached"]
    missing = [k for k in required if k not in vec]
    if missing:
        raise ValueError(f"{front}[{idx}] ({vec.get('technique')}) missing mandatory fields: {missing}")
    if vec["expect_gateway_status"] in ("SANITIZED", "BLOCKED") and not vec.get("expect_codes"):
        raise ValueError(
            f"{front}[{idx}] ({vec['technique']}) has status {vec['expect_gateway_status']} but no expect_codes"
        )


def evaluate_vector_assertions(
    vec: dict,
    status: int,
    effective_status: str,
    structured_codes: list,
    upstream_reached: bool,
    upstream_body: str,
    upstream_sse_fragments: list,
    client_body: str,
    assistant_text: str,
    tool_args_text: str,
) -> list:
    """Pure, deterministic 4-stage assertion oracle."""
    failures = []

    # --- STAGE 2: HTTP Status & Structured Telemetry ONLY ---
    allowed_statuses = vec["allowed_statuses"]
    if status not in allowed_statuses:
        failures.append(f"Stage2 HTTP {status} not in allowed {allowed_statuses}")

    expected_gw_status = vec["expect_gateway_status"]
    if effective_status != expected_gw_status:
        failures.append(f"Stage2 status={effective_status!r}, expected {expected_gw_status!r}")

    for req_code in vec.get("expect_codes", []):
        if req_code not in structured_codes:
            failures.append(
                f"Stage2 missing required structured telemetry code {req_code!r} (got {structured_codes})"
            )

    # --- STAGE 3: Upstream Capture & Pre-Provider Block Invariant ---
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

    # --- STAGE 4: True Mid-Token SSE Split + Exact Reconstructed Client Output ---
    if vec.get("require_mid_token_sse_split"):
        if len(upstream_sse_fragments) < 3:
            failures.append(f"Stage4 SSE fragmentation too coarse: {len(upstream_sse_fragments)} fragments")
        else:
            joined_frags = "".join(upstream_sse_fragments)
            has_complete_in_joined = bool(
                RE_JG_TOKEN.search(joined_frags)
                or RE_AWS_KEY.search(joined_frags)
                or RE_PEM_FULL.search(joined_frags)
            )
            if not has_complete_in_joined:
                failures.append(
                    "Stage4 INVALID SSE TEST: joined upstream fragments did not contain a complete token/secret/PEM"
                )
            for frag in upstream_sse_fragments:
                if RE_JG_TOKEN.search(frag):
                    failures.append(f"Stage4 FAKE SSE SPLIT: intact <JG_PII_...> token in single chunk {frag!r}")
                if RE_AWS_KEY.search(frag):
                    failures.append(f"Stage4 FAKE SSE SPLIT: intact AWS key in single chunk {frag!r}")
                if RE_PEM_FULL.search(frag):
                    failures.append("Stage4 FAKE SSE SPLIT: intact PEM block in single chunk")

    if "expect_exact_client_text" in vec:
        want_exact = vec["expect_exact_client_text"]
        if assistant_text != want_exact:
            failures.append(
                f"Stage4 EXACT TEXT MISMATCH: got {assistant_text!r}, expected {want_exact!r}"
            )

    if "expect_exact_tool_args" in vec:
        want_args = vec["expect_exact_tool_args"]
        try:
            parsed_args = json.loads(tool_args_text)
            if parsed_args != want_args:
                failures.append(
                    f"Stage4 EXACT TOOL ARGS MISMATCH: got {parsed_args!r}, expected {want_args!r}"
                )
        except Exception as e:
            failures.append(f"Stage4 INVALID TOOL ARGS JSON ({e}): {tool_args_text!r}")

    expected_restore = vec.get("must_restore_in_client")
    if expected_restore and expected_restore not in assistant_text and expected_restore not in client_body:
        failures.append(f"Stage4 RESTORE FAILED: expected {expected_restore!r} in client delivery")

    for forbidden_client in vec.get("must_not_leak_in_client", []):
        if (
            forbidden_client in client_body
            or forbidden_client in assistant_text
            or forbidden_client in tool_args_text
        ):
            failures.append(f"Stage4 CLIENT LEAK: forbidden {forbidden_client!r} delivered to client!")

    expected_client_marker = vec.get("must_contain_in_client")
    if expected_client_marker:
        if expected_client_marker not in client_body and expected_client_marker not in assistant_text:
            failures.append(f"Stage4 missing expected marker {expected_client_marker!r} in client response")

    return failures


def run_mutation_self_test() -> bool:
    """Q5 Mutation Self-Test: Prove the assertion oracle deterministically rejects unsafe mutations."""
    print("\n--- [Q5 MUTATION SELF-TEST] Deliberate Unsafe Regression Oracle Check ---")
    base_vec = {
        "technique": "mutation_probe",
        "allowed_statuses": [200],
        "expect_gateway_status": "SANITIZED",
        "expect_codes": ["JG-PII-301"],
        "expect_upstream_reached": True,
        "require_mid_token_sse_split": True,
        "must_not_reach_upstream": ["123.456.789-09"],
        "must_reach_upstream_masked": "<JG_PII_CPF_",
        "must_not_leak_in_client": ["AKIAIOSFODNN7EXAMPLE"],
        "expect_exact_client_text": "Upstream received tokens: 123.456.789-09.",
    }

    mutations = [
        (
            "raw_cpf_leaked_to_upstream",
            dict(
                status=200,
                effective_status="SANITIZED",
                structured_codes=["JG-PII-301"],
                upstream_reached=True,
                upstream_body='{"content":"CPF 123.456.789-09 <JG_PII_CPF_0123456789abcdef>"}',
                upstream_sse_fragments=["<JG_PII_CP", "F_0123456789ab", "cdef>"],
                client_body="",
                assistant_text="Upstream received tokens: 123.456.789-09.",
                tool_args_text="",
            ),
        ),
        (
            "code_only_in_body_not_structured_telemetry",
            dict(
                status=200,
                effective_status="SANITIZED",
                structured_codes=[],
                upstream_reached=True,
                upstream_body='{"content":"<JG_PII_CPF_0123456789abcdef>"}',
                upstream_sse_fragments=["<JG_PII_CP", "F_0123456789ab", "cdef>"],
                client_body="JG-PII-301",
                assistant_text="Upstream received tokens: 123.456.789-09.",
                tool_args_text="",
            ),
        ),
        (
            "unsplit_token_in_single_sse_fragment",
            dict(
                status=200,
                effective_status="SANITIZED",
                structured_codes=["JG-PII-301"],
                upstream_reached=True,
                upstream_body='{"content":"<JG_PII_CPF_0123456789abcdef>"}',
                upstream_sse_fragments=["Prefix ", "<JG_PII_CPF_0123456789abcdef>", "."],
                client_body="",
                assistant_text="Upstream received tokens: 123.456.789-09.",
                tool_args_text="",
            ),
        ),
        (
            "truncated_or_duplicated_restoration",
            dict(
                status=200,
                effective_status="SANITIZED",
                structured_codes=["JG-PII-301"],
                upstream_reached=True,
                upstream_body='{"content":"<JG_PII_CPF_0123456789abcdef>"}',
                upstream_sse_fragments=["<JG_PII_CP", "F_0123456789ab", "cdef>"],
                client_body="",
                assistant_text="Upstream received tokens: 123.456.789-09 123.456.789-09",
                tool_args_text="",
            ),
        ),
    ]

    for m_name, kwargs in mutations:
        errs = evaluate_vector_assertions(base_vec, **kwargs)
        if not errs:
            print(f"  [ABORT] Mutation self-test FAILED to reject unsafe mutation: {m_name}")
            return False
    print(f"  [OK] Mutation self-test PASSED: all {len(mutations)} unsafe regressions deterministically rejected.")
    return True


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


def compact_synthetic_padding(s: str) -> str:
    if len(s) > 4096 and "PPPPPPPPPPPPPPPPPPPP" in s:
        return re.sub(r"P{256,}", lambda m: f"<SYNTHETIC_PADDING_{len(m.group(0))}_BYTES>", s)
    return s


def main():
    gateway_url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:4010"
    mock_url = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else "http://127.0.0.1:4020"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", "..", "..", ".."))
    binary_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(repo_root, "jgate")
    runtime_cfg_path = sys.argv[4] if len(sys.argv) > 4 else os.path.join(script_dir, "jaguargate.audit.yaml")
    template_cfg_path = sys.argv[5] if len(sys.argv) > 5 else os.path.join(script_dir, "jaguargate.audit.yaml")

    vectors_path = os.path.join(script_dir, "test_vectors.json")
    mock_script_path = os.path.join(script_dir, "mock_upstream.py")
    report_path = os.path.join(script_dir, "..", "findings", "full_campaign_report.json")

    with open(vectors_path, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    for front_name, rounds in vectors.items():
        for idx, vec in enumerate(rounds, 1):
            validate_vector_schema(vec, front_name, idx)

    effective_yaml = ""
    if os.path.isfile(runtime_cfg_path):
        with open(runtime_cfg_path, "r", encoding="utf-8") as ff:
            effective_yaml = ff.read()

    git_prov = get_git_provenance(repo_root)
    provenance = {
        **git_prov,
        "jgate_binary_sha256": sha256_file(binary_path),
        "reproduce_audit_sha256": sha256_file(os.path.abspath(__file__)),
        "mock_upstream_sha256": sha256_file(mock_script_path),
        "test_vectors_sha256": sha256_file(vectors_path),
        "fixture_template_sha256": sha256_file(template_cfg_path),
        "effective_runtime_config_sha256": sha256_file(runtime_cfg_path),
        "effective_runtime_config_yaml": effective_yaml,
    }

    print("=" * 90)
    print("  JAGUARGATE GATE 5 — STRICT 4-STAGE BILATERAL AUDIT VERIFIER")
    print(f"  Gateway Target:  {gateway_url}")
    print(f"  Upstream Mock:   {mock_url}")
    print(f"  Git Commit:      {provenance['git_commit'][:12]} (dirty={provenance['git_dirty']})")
    print(f"  Binary SHA-256:  {provenance['jgate_binary_sha256'][:16]}...")
    print(f"  Runtime Config:  {provenance['effective_runtime_config_sha256'][:16]}...")
    print("=" * 90)

    if not run_mutation_self_test():
        sys.exit(2)
    if not run_positive_control(mock_url):
        sys.exit(2)

    total_probes = 0
    passed_probes = 0
    findings = []
    evidence_log = []

    for front_name, rounds in vectors.items():
        print(f"\n--- [{front_name}] Executing {len(rounds)} strict 4-stage bilateral vectors ---")
        for i, vec in enumerate(rounds, 1):
            total_probes += 1
            tech = vec["technique"]
            endpoint = vec.get("endpoint", "/v1/chat/completions")
            headers = dict(vec.get("headers", {"Content-Type": "application/json"}))

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
                findings.append({"front": front_name, "round": i, "technique": tech, "error": str(e)})
                print(f"  [FAIL] r{i:02d} {tech:<46} -> transport error: {e}")
                continue

            _, cap = http_json("GET", f"{mock_url}/_mock/last_request")
            last_req = cap.get("last_request")
            upstream_reached = last_req is not None
            upstream_body = last_req["body"] if last_req else ""
            upstream_resp_mode = last_req.get("response_mode", "none") if last_req else "none"
            upstream_resp_sent = last_req.get("response_content_sent", "") if last_req else ""
            upstream_sse_fragments = last_req.get("sse_fragments_sent", []) if last_req else []

            is_sse_client = "text/event-stream" in resp_headers.get("content-type", "").lower()
            if is_sse_client:
                assistant_text, tool_args_text, client_sse_events, sse_codes, sse_status = parse_sse_client_stream(
                    client_body
                )
            else:
                assistant_text, tool_args_text = extract_json_assistant_outputs(client_body)
                client_sse_events = 0
                sse_codes = []
                sse_status = ""

            hdr_status = resp_headers.get("x-jaguargate-status", "")
            effective_status = sse_status or hdr_status
            hdr_codes = [c.strip() for c in resp_headers.get("x-jaguargate-codes", "").split(",") if c.strip()]
            structured_codes = list(dict.fromkeys(hdr_codes + sse_codes))

            failures = evaluate_vector_assertions(
                vec=vec,
                status=status,
                effective_status=effective_status,
                structured_codes=structured_codes,
                upstream_reached=upstream_reached,
                upstream_body=upstream_body,
                upstream_sse_fragments=upstream_sse_fragments,
                client_body=client_body,
                assistant_text=assistant_text,
                tool_args_text=tool_args_text,
            )

            entry = {
                "front": front_name,
                "round": i,
                "technique": tech,
                "latency_ms": round(elapsed_ms, 2),
                "stage1_ingress": {
                    "endpoint": endpoint,
                    "session_id": headers.get("X-JaguarGate-Session-ID", "default_session"),
                    "body_bytes": len(data),
                    "body": compact_synthetic_padding(ingress_text),
                },
                "stage2_gateway_decision": {
                    "http_status": status,
                    "x_jaguargate_status": effective_status,
                    "x_jaguargate_severity": resp_headers.get("x-jaguargate-severity", ""),
                    "x_jaguargate_codes": structured_codes,
                    "x_jaguargate_veto": resp_headers.get("x-jaguargate-veto", ""),
                },
                "stage3_upstream_capture": {
                    "upstream_reached": upstream_reached,
                    "body": compact_synthetic_padding(upstream_body),
                },
                "stage4_egress_delivery": {
                    "response_mode": upstream_resp_mode,
                    "upstream_response_sent": upstream_resp_sent,
                    "upstream_sse_fragments": upstream_sse_fragments,
                    "client_sse_events_count": client_sse_events,
                    "reconstructed_assistant_text": assistant_text,
                    "reconstructed_tool_arguments": tool_args_text,
                    "client_body": client_body,
                },
                "passed": len(failures) == 0,
                "failures": failures,
            }
            evidence_log.append(entry)

            if failures:
                findings.append(entry)
                print(f"  [FAIL] r{i:02d} {tech:<46} -> HTTP {status} | {'; '.join(failures)}")
            else:
                passed_probes += 1
                print(
                    f"  [PASS] r{i:02d} {tech:<46} -> HTTP {status} [{effective_status} {','.join(structured_codes) or '-'}] ({elapsed_ms:.1f}ms)"
                )

    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "suite": "JaguarGate Gate 5 — Strict 4-Stage Bilateral Audit",
                "provenance": provenance,
                "gateway_url": gateway_url,
                "mock_upstream_url": mock_url,
                "mutation_self_test_passed": True,
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

    print("\n" + "=" * 90)
    print(f" RESULTS: Executed {total_probes} | Passed {passed_probes} | Findings: {len(findings)}")
    print(f" Evidence saved to: {os.path.abspath(report_path)}")
    print("=" * 90)
    if findings:
        print(" [FAIL] Bilateral Gate 5 verification detected failures.")
        sys.exit(1)
    else:
        print(
            f" [PASS] All {passed_probes}/{total_probes} strict 4-stage bilateral vectors passed with provenance."
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
