import asyncio
import json
from pathlib import Path

import httpx

ARTIFACT_DIR = Path("artifacts") / "e2e"
REQRES_HAR_PATH = ARTIFACT_DIR / "reqres.har"
REQRES_SPEC_PATH = ARTIFACT_DIR / "reqres_spec.yaml"
REPORT_PATH = ARTIFACT_DIR / "e2e_report.html"

REQRES_HAR = {
    "log": {
        "version": "1.2",
        "creator": {
            "name": "Manual",
            "version": "1.0",
        },
        "entries": [
            {
                "startedDateTime": "2023-01-01T00:00:00.000Z",
                "time": 100,
                "request": {
                    "method": "GET",
                    "url": "https://reqres.in/api/users?page=2",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [
                        {"name": "Host", "value": "reqres.in"},
                        {"name": "User-Agent", "value": "curl/8.x"},
                    ],
                    "queryString": [{"name": "page", "value": "2"}],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"size": 0, "mimeType": "application/json"},
                },
            },
            {
                "startedDateTime": "2023-01-01T00:00:01.000Z",
                "time": 150,
                "request": {
                    "method": "POST",
                    "url": "https://reqres.in/api/users",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [
                        {"name": "Host", "value": "reqres.in"},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "queryString": [],
                    "postData": {
                        "mimeType": "application/json",
                        "text": "{\"name\": \"morpheus\", \"job\": \"leader\"}",
                    },
                    "headersSize": -1,
                    "bodySize": 37,
                },
                "response": {
                    "status": 201,
                    "headers": [],
                    "content": {"size": 0, "mimeType": "application/json"},
                },
            },
        ],
    }
}

REQRES_OPENAPI = """
openapi: 3.0.0
info:
  title: ReqRes API
  version: 1.0.0
paths:
  /api/users:
    get:
      summary: List users
      parameters:
        - name: page
          in: query
          schema:
            type: integer
    post:
      summary: Create user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                job:
                  type: string
  /api/unknown:
    get:
      summary: Undocumented endpoint we didn't hit in HAR
"""


async def run_e2e_test() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    with open(REQRES_HAR_PATH, "w", encoding="utf-8") as handle:
        json.dump(REQRES_HAR, handle)
    with open(REQRES_SPEC_PATH, "w", encoding="utf-8") as handle:
        handle.write(REQRES_OPENAPI)

    async with httpx.AsyncClient(timeout=60.0) as client:
        print("1. Uploading traffic (ingestion)...")
        with open(REQRES_HAR_PATH, "rb") as handle:
            resp = await client.post(
                "http://127.0.0.1:8010/api/ingest",
                files={"file": ("reqres.har", handle, "application/json")},
            )

        data = resp.json()
        scan_id = data["scan_id"]
        endpoints = data["endpoints"]
        print(f"Ingested successfully. Scan ID: {scan_id}. Found {len(endpoints)} endpoints.")

        print("\n2. Uploading OpenAPI spec (shadow API analysis)...")
        with open(REQRES_SPEC_PATH, "rb") as handle:
            shadow_resp = await client.post(
                f"http://127.0.0.1:8010/api/scan/{scan_id}/openapi",
                files={"file": ("reqres_spec.yaml", handle, "text/yaml")},
            )
        shadow_data = shadow_resp.json()
        print(f"Shadow API report: {shadow_data['coverage_percent']}% coverage.")
        print(f"   Undocumented APIs found in traffic: {len(shadow_data['undocumented'])}")
        print(f"   Unimplemented APIs (in spec but not traffic): {len(shadow_data['unimplemented'])}")

        print("\n3. Launching scan engine...")
        config = {
            "selected_endpoints": [endpoint["id"] for endpoint in endpoints],
            "config": {
                "allowlist": ["reqres.in"],
                "target_base_url": "https://reqres.in",
                "rate_limit": 5.0,
                "concurrency": 2,
                "respect_robots": False,
                "dry_run": False,
                "aggressive": True,
                "categories": ["auth", "hidden_params", "cors", "error_leak", "sqli", "xss", "ssti"],
                "enable_bola": False,
                "enable_stateful": True,
                "enable_race": True,
                "burst_size": 2,
                "enable_mutations": True,
                "enable_graphql": False,
            },
        }

        await client.post(f"http://127.0.0.1:8010/api/scan/{scan_id}/run", json=config)
        print("Run triggered.")

        while True:
            await asyncio.sleep(2)
            status_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/status")
            status = status_resp.json()
            if not status.get("isRunning", False):
                print(f"Scan complete. {status.get('casesRun')} cases executed.")
                print(f"Discovered {len(status.get('findings', []))} potential vulnerabilities.")
                break
            print(f"   Scanning... {status.get('progress', 0):.1f}%")

        print("\n4. Verifying auto-remediation patches...")
        patch_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/patches")
        patches = patch_resp.json()
        print(f"Downloaded {patches.get('total', 0)} security patches.")

        print("\n5. Exporting reports...")
        json_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/export.json")
        html_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/export.html")
        print(f"Downloaded JSON report: {len(json_resp.content)} bytes")
        print(f"Downloaded HTML report: {len(html_resp.content)} bytes")

        with open(REPORT_PATH, "wb") as handle:
            handle.write(html_resp.content)

        print(f"\nEnd-to-end test completed successfully. Report saved to {REPORT_PATH}.")


if __name__ == "__main__":
    asyncio.run(run_e2e_test())
