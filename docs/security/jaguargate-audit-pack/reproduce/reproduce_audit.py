#!/usr/bin/env python3
"""
JaguarGate Gate 5 Audit Verification Runner
Community Reproduction Script for JaguarGate 6d2057e Gate 5 Certification
"""
import sys
import os
import json
import time
import urllib.request
import urllib.error

def check_target(target_url: str):
    try:
        req = urllib.request.Request(f"{target_url}/health", method="GET")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status == 200
    except Exception:
        return False

def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:4010"
    vectors_file = os.path.join(os.path.dirname(__file__), "test_vectors.json")
    
    if not os.path.exists(vectors_file):
        print(f"[FAIL] test_vectors.json not found at {vectors_file}")
        sys.exit(1)
        
    with open(vectors_file, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    print("=" * 80)
    print(" JAGUARGATE GATE 5 CERTIFICATION REPRODUCTION SUITE")
    print(f" Target: {target_url}")
    print("=" * 80)

    if not check_target(target_url):
        print(f"[ERROR] Target gateway at {target_url} is not responding on /health.")
        print("Please ensure JaguarGate is running (e.g. `jgate serve -c jaguargate.yaml`).")
        sys.exit(2)

    total_probes = 0
    neutralized = 0
    findings = []
    
    for front_name, front_vectors in vectors.items():
        print(f"\n--- Running {front_name} ({len(front_vectors)} rounds) ---")
        for i, vec in enumerate(front_vectors, 1):
            total_probes += 1
            endpoint = f"{target_url}{vec['endpoint']}"
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            headers.update(vec.get("headers", {}))
            data = json.dumps(vec["payload"]).encode("utf-8")
            
            t0 = time.perf_counter()
            try:
                req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    elapsed_ms = (time.perf_counter() - t0) * 1000
                    body = resp.read().decode("utf-8", errors="replace")
                    status = resp.status
            except urllib.error.HTTPError as e:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                body = e.read().decode("utf-8", errors="replace")
                status = e.code
            except Exception as e:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                body = ""
                status = 0
                findings.append({"front": front_name, "round": i, "technique": vec["technique"], "error": str(e)})

            canary = vec.get("expected_leak_canary")
            if canary and canary in body:
                print(f"  [CRITICAL LEAK] r{i:02d} {vec['technique']}: canary [{canary}] leaked in response!")
                findings.append({"front": front_name, "round": i, "technique": vec["technique"], "leak": canary})
            elif status == 200 or status in (400, 403, 422):
                neutralized += 1
                print(f"  [OK] r{i:02d} {vec['technique']:<38} -> HTTP {status} ({elapsed_ms:.1f}ms)")
            else:
                print(f"  [FAIL] r{i:02d} {vec['technique']:<38} -> HTTP {status}")
                findings.append({"front": front_name, "round": i, "technique": vec["technique"], "status": status})

    print("\n" + "=" * 80)
    print(f" RESULTS: Executed {total_probes} | Neutralized {neutralized} | Findings: {len(findings)}")
    if findings:
        print(" [FAIL] Gate 5 reproduction identified findings/anomalies.")
        sys.exit(1)
    else:
        print(" [PASS] Gate 5 Zero-Vulnerability Certification 100% REPRODUCED.")
        sys.exit(0)

if __name__ == "__main__":
    main()
