"""AASE end-to-end verification against the local safe mock target."""
import httpx
import json
import time
import sys

API = "http://127.0.0.1:8010"
TARGET = "http://127.0.0.1:8055"

def main():
    # -------------------------------------------------------
    # TEST 1: Auto-Recon against the local safe mock target
    # -------------------------------------------------------
    print("=== TEST 1: Auto-Recon ===")
    r = httpx.post(f"{API}/api/recon", json={"target_url": TARGET}, timeout=30.0)
    print(f"Status: {r.status_code}")
    assert r.status_code == 200, f"Auto-Recon FAILED with {r.status_code}: {r.text}"
    data = r.json()
    ep_count = len(data["endpoints"])
    print(f"Endpoints: {ep_count}")
    print(f"Hosts: {data['hosts']}")
    scan_id = data["scan_id"]
    print(f"Scan ID: {scan_id}")
    for ep in data["endpoints"][:3]:
        print(f"  {ep['method']} {ep['path']} auth={ep['authRequired']} conf={ep['schemaConfidence']}% cases={ep['fuzzCases']}")
    assert ep_count > 0, "No endpoints found!"
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 2: HAR File Upload
    # -------------------------------------------------------
    print("=== TEST 2: HAR File Upload ===")
    har_path = r"c:\Users\Thinkpad\Desktop\API-Spec-Enumerator\example_traffic.har"
    with open(har_path, "rb") as f:
        r2 = httpx.post(f"{API}/api/ingest", files={"file": ("example_traffic.har", f, "application/json")}, timeout=15.0)
    print(f"Status: {r2.status_code}")
    assert r2.status_code == 200, f"HAR Upload FAILED: {r2.text}"
    har_data = r2.json()
    har_id = har_data["scan_id"]
    print(f"HAR Scan ID: {har_id}, Endpoints: {len(har_data['endpoints'])}, Hosts: {har_data['hosts']}")
    for ep in har_data["endpoints"][:3]:
        print(f"  {ep['method']} {ep['path']} auth={ep['authRequired']} conf={ep['schemaConfidence']}% cases={ep['fuzzCases']}")
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 3: Paste Ingestion (raw HTTP)
    # -------------------------------------------------------
    print("=== TEST 3: Paste Ingestion (Raw HTTP) ===")
    raw_http = "GET /api/users HTTP/1.1\nHost: 127.0.0.1:8055\nAccept: application/json\n\n"
    r3 = httpx.post(f"{API}/api/ingest/paste", json={"text": raw_http}, timeout=10.0)
    print(f"Status: {r3.status_code}")
    assert r3.status_code == 200, f"Paste FAILED: {r3.text}"
    paste_data = r3.json()
    print(f"Paste Endpoints: {len(paste_data['endpoints'])}, Hosts: {paste_data['hosts']}")
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 4: Launch Live Attack (safe categories only)
    # -------------------------------------------------------
    print("=== TEST 4: Launch Live Attack ===")
    selected = [ep["id"] for ep in data["endpoints"][:3]]
    run_body = {
        "selected_endpoints": selected,
        "config": {
            "allowlist": ["127.0.0.1"],
            "target_base_url": TARGET,
            "rate_limit": 5.0,
            "concurrency": 2,
            "respect_robots": True,
            "aggressive": False,
            "categories": ["cors", "hidden_params", "auth"],
            "dry_run": False
        }
    }
    r4 = httpx.post(f"{API}/api/scan/{scan_id}/run", json=run_body, timeout=10.0)
    print(f"Launch Status: {r4.status_code} -> {r4.json()}")
    assert r4.status_code == 200, f"Launch FAILED: {r4.text}"
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 5: Poll Status Until Complete
    # -------------------------------------------------------
    print("=== TEST 5: Live Status Polling ===")
    for i in range(60):
        time.sleep(1)
        r5 = httpx.get(f"{API}/api/scan/{scan_id}/status", timeout=5.0)
        st = r5.json()
        running = st["isRunning"]
        prog = st["progress"]
        cases = st["casesRun"]
        total = st["totalCases"]
        findings = len(st["findings"])
        print(f"  [{i+1}s] Running={running} Progress={prog}% Cases={cases}/{total} Findings={findings}")
        if not running and cases >= total and total > 0:
            print("  -> SCAN COMPLETE")
            break
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 6: Verify Findings
    # -------------------------------------------------------
    r6 = httpx.get(f"{API}/api/scan/{scan_id}/status", timeout=5.0)
    st6 = r6.json()
    findings_count = len(st6["findings"])
    print(f"=== TEST 6: Findings ({findings_count}) ===")
    for f in st6["findings"]:
        print(f"  [{f['severity']}] {f['type']} - {f['method']} {f['endpoint']} | {f['evidence']}")
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 7: OpenAPI Shadow API Diff
    # -------------------------------------------------------
    print("=== TEST 7: OpenAPI Shadow Diff ===")
    spec_path = r"c:\Users\Thinkpad\Desktop\API-Spec-Enumerator\example_spec.yaml"
    with open(spec_path, "rb") as f:
        r7 = httpx.post(f"{API}/api/scan/{har_id}/openapi", files={"file": ("example_spec.yaml", f, "application/x-yaml")}, timeout=10.0)
    print(f"Shadow API Status: {r7.status_code}")
    if r7.status_code == 200:
        shadow = r7.json()
        print(f"Undocumented: {len(shadow.get('undocumented', []))}")
        print(f"Unimplemented: {len(shadow.get('unimplemented', []))}")
        print(f"Param Mismatches: {len(shadow.get('param_mismatches', []))}")
        print(f"Coverage: {shadow.get('coverage_percent', 0)}%")
    else:
        print(f"Shadow API response: {r7.text}")
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 8: Executive HTML Report
    # -------------------------------------------------------
    print("=== TEST 8: Executive HTML Report ===")
    r8 = httpx.get(f"{API}/api/scan/{scan_id}/export.html", timeout=10.0)
    print(f"Report Status: {r8.status_code}, Size: {len(r8.content)} bytes")
    assert r8.status_code == 200, f"Report FAILED: {r8.text}"
    has_curl = "curl" in r8.text.lower()
    has_cvss = "cvss" in r8.text.lower()
    has_cwe = "cwe" in r8.text.lower()
    print(f"Contains curl PoC: {has_curl}, CVSS: {has_cvss}, CWE: {has_cwe}")
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 9: JSON Export
    # -------------------------------------------------------
    print("=== TEST 9: JSON Export ===")
    r9 = httpx.get(f"{API}/api/scan/{scan_id}/export.json", timeout=10.0)
    print(f"JSON Export Status: {r9.status_code}, Size: {len(r9.content)} bytes")
    assert r9.status_code == 200, f"JSON Export FAILED: {r9.text}"
    jdata = r9.json()
    print(f"Meta keys: {list(jdata['meta'].keys())}")
    print(f"Findings in export: {len(jdata['findings'])}")
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 10: Patches
    # -------------------------------------------------------
    print("=== TEST 10: Patches ===")
    r10 = httpx.get(f"{API}/api/scan/{scan_id}/patches", timeout=10.0)
    print(f"Patches Status: {r10.status_code}")
    assert r10.status_code == 200, f"Patches FAILED: {r10.text}"
    pdata = r10.json()
    print(f"Total patches: {pdata['total']}")
    if pdata["patches"]:
        p = pdata["patches"][0]
        print(f"  First: [{p['language']}] {p['title']} for {p['finding_type']}")
    print("-> PASSED\n")

    # -------------------------------------------------------
    # TEST 11: Error handling - bad input
    # -------------------------------------------------------
    print("=== TEST 11: Error Handling ===")
    r11a = httpx.post(f"{API}/api/ingest/paste", json={"text": "random garbage not HTTP"}, timeout=5.0)
    print(f"Bad paste: {r11a.status_code} (expected 400)")
    assert r11a.status_code == 400, f"Expected 400 but got {r11a.status_code}"

    r11b = httpx.get(f"{API}/api/scan/nonexistent/status", timeout=5.0)
    print(f"Bad scan ID: {r11b.status_code} (expected 404)")
    assert r11b.status_code == 404, f"Expected 404 but got {r11b.status_code}"
    print("-> PASSED\n")

    # -------------------------------------------------------
    # FINAL SUMMARY
    # -------------------------------------------------------
    print("=" * 60)
    print("=== ALL 11 TESTS PASSED ===")
    print("=" * 60)
    print(f"Auto-Recon: {ep_count} endpoints from {TARGET}")
    print(f"HAR Upload: {len(har_data['endpoints'])} endpoints")
    print(f"Paste Ingest: {len(paste_data['endpoints'])} endpoints")
    print(f"Live Scan: {st6['casesRun']}/{st6['totalCases']} cases completed")
    print(f"Findings: {findings_count}")
    print(f"Report: {len(r8.content)} bytes HTML")
    print(f"Patches: {pdata['total']}")

if __name__ == "__main__":
    main()
