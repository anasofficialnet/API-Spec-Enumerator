from __future__ import annotations

import json
import time

import httpx


API = "http://127.0.0.1:8010"
TARGET = "http://127.0.0.1:8055"

RAW_HTTP = """GET /api/discovery HTTP/1.1
Host: 127.0.0.1:8055
Accept: application/json

GET /api/cors HTTP/1.1
Host: 127.0.0.1:8055
Accept: application/json

GET /api/private HTTP/1.1
Host: 127.0.0.1:8055
Accept: application/json

GET /api/flaky HTTP/1.1
Host: 127.0.0.1:8055
Accept: application/json

POST /api/items HTTP/1.1
Host: 127.0.0.1:8055
Content-Type: application/json

{"name":"Widget","callback":"http://placeholder.local/callback"}

POST /api/transfer HTTP/1.1
Host: 127.0.0.1:8055
Content-Type: application/json

{"amount":25}

POST /graphql HTTP/1.1
Host: 127.0.0.1:8055
Content-Type: application/json

{"query":"{ health }"}
"""

SLOW_HTTP = """GET /api/slow HTTP/1.1
Host: 127.0.0.1:8055
Accept: application/json
"""


def _poll_scan(client: httpx.Client, scan_id: str, timeout_seconds: int = 30) -> dict:
    for _ in range(timeout_seconds):
        status = client.get(f"{API}/api/scan/{scan_id}/status")
        status.raise_for_status()
        body = status.json()
        print(
            f"scan={scan_id} progress={body['progress']}% "
            f"cases={body['casesRun']}/{body['totalCases']} "
            f"findings={len(body['findings'])} cancelled={body.get('isCancelled')}"
        )
        if not body["isRunning"]:
            return body
        time.sleep(1)
    raise RuntimeError(f"Timed out waiting for scan {scan_id}")


def main() -> None:
    with httpx.Client(timeout=20.0) as client:
        print("== Auto-Recon ==")
        recon = client.post(
            f"{API}/api/recon",
            json={"target_url": TARGET, "max_depth": 4, "max_requests": 120, "concurrency": 8},
        )
        recon.raise_for_status()
        recon_data = recon.json()
        print(f"Recon endpoints: {len(recon_data['endpoints'])}")

        print("== Ingest ==")
        ingest = client.post(f"{API}/api/ingest/paste", json={"text": RAW_HTTP})
        ingest.raise_for_status()
        ingest_data = ingest.json()
        scan_id = ingest_data["scan_id"]
        endpoint_ids = [endpoint["id"] for endpoint in ingest_data["endpoints"]]
        print(f"Scan ID: {scan_id}")
        print(f"Endpoints: {len(endpoint_ids)}")

        print("== Attack Graph ==")
        graph = client.get(f"{API}/api/scan/{scan_id}/attack-graph")
        graph.raise_for_status()
        graph_data = graph.json()
        print(
            json.dumps(
                {
                    "nodes": len(graph_data.get("nodes", [])),
                    "edges": len(graph_data.get("edges", [])),
                    "paths": len(graph_data.get("paths", [])),
                },
                indent=2,
            )
        )

        run_payload = {
            "selected_endpoints": endpoint_ids,
            "config": {
                "allowlist": ["127.0.0.1", "localhost"],
                "target_base_url": TARGET,
                "rate_limit": 10.0,
                "concurrency": 2,
                "max_retries": 3,
                "respect_robots": False,
                "aggressive": False,
                "categories": ["auth", "hidden_params", "cors"],
                "enable_race": True,
                "burst_size": 3,
                "enable_graphql": True,
                "enable_attack_graph": True,
                "enable_auto_login": True,
                "login_config": {
                    "login_url": f"{TARGET}/auth/login",
                    "username": "demo",
                    "password": "demo",
                },
                "enable_oast": True,
                "oast_callback_base_url": API,
            },
        }

        print("== Preview ==")
        preview = client.post(f"{API}/api/scan/{scan_id}/preview", json=run_payload)
        preview.raise_for_status()
        print(json.dumps(preview.json(), indent=2))

        print("== Run ==")
        launch = client.post(f"{API}/api/scan/{scan_id}/run", json=run_payload)
        launch.raise_for_status()
        status_body = _poll_scan(client, scan_id)

        oast_events = client.get(f"{API}/api/scan/{scan_id}/oast")
        oast_events.raise_for_status()
        oast_data = oast_events.json()
        print(f"OAST events: {len(oast_data['events'])}")

        report = client.get(f"{API}/api/scan/{scan_id}/export.html")
        report.raise_for_status()
        print(f"HTML report bytes: {len(report.content)}")

        print("== Cancellation ==")
        slow_ingest = client.post(f"{API}/api/ingest/paste", json={"text": SLOW_HTTP})
        slow_ingest.raise_for_status()
        slow_scan_id = slow_ingest.json()["scan_id"]
        slow_endpoint_ids = [endpoint["id"] for endpoint in slow_ingest.json()["endpoints"]]
        slow_payload = {
            "selected_endpoints": slow_endpoint_ids,
            "config": {
                "allowlist": ["127.0.0.1", "localhost"],
                "target_base_url": TARGET,
                "rate_limit": 1.0,
                "concurrency": 1,
                "max_retries": 0,
                "respect_robots": False,
                "aggressive": False,
                "categories": ["hidden_params", "cors"],
            },
        }
        start_slow = client.post(f"{API}/api/scan/{slow_scan_id}/run", json=slow_payload)
        start_slow.raise_for_status()
        time.sleep(0.2)
        cancel = client.post(f"{API}/api/scan/{slow_scan_id}/cancel")
        cancel.raise_for_status()
        cancelled = _poll_scan(client, slow_scan_id, timeout_seconds=10)
        print(json.dumps(cancelled, indent=2))

        print("== Summary ==")
        print(
            json.dumps(
                {
                    "recon_endpoints": len(recon_data["endpoints"]),
                    "graph_paths": len(graph_data.get("paths", [])),
                    "run_cases": f"{status_body['casesRun']}/{status_body['totalCases']}",
                    "findings": len(status_body["findings"]),
                    "oast_events": len(oast_data["events"]),
                    "cancelled": cancelled.get("isCancelled"),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
