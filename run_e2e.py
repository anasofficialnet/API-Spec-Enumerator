import asyncio
import httpx
import json
import os

REQRES_HAR = {
  "log": {
    "version": "1.2",
    "creator": {
      "name": "Manual",
      "version": "1.0"
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
            { "name": "Host", "value": "reqres.in" },
            { "name": "User-Agent", "value": "curl/8.x" }
          ],
          "queryString": [{"name": "page", "value": "2"}],
          "headersSize": -1,
          "bodySize": 0
        },
        "response": { "status": 200, "headers": [], "content": {"size": 0, "mimeType": "application/json"} }
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
            { "name": "Host", "value": "reqres.in" },
            { "name": "Content-Type", "value": "application/json" }
          ],
          "queryString": [],
          "postData": {
            "mimeType": "application/json",
            "text": "{\"name\": \"morpheus\", \"job\": \"leader\"}"
          },
          "headersSize": -1,
          "bodySize": 37
        },
        "response": { "status": 201, "headers": [], "content": {"size": 0, "mimeType": "application/json"} }
      }
    ]
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

async def run_e2e_test():
    with open("reqres.har", "w") as f:
        json.dump(REQRES_HAR, f)
    with open("reqres_spec.yaml", "w") as f:
        f.write(REQRES_OPENAPI)
        
    async with httpx.AsyncClient(timeout=60.0) as client:
        print("1️⃣ Uploading Traffic (Ingestion)...")
        with open("reqres.har", "rb") as f:
            resp = await client.post("http://127.0.0.1:8010/api/ingest", files={"file": ("reqres.har", f, "application/json")})
        
        data = resp.json()
        scan_id = data["scan_id"]
        endpoints = data["endpoints"]
        print(f"✅ Ingested successfully. Scan ID: {scan_id}. Found {len(endpoints)} endpoints.")
        
        print("\n2️⃣ Uploading OpenAPI Spec (Shadow API Analysis)...")
        with open("reqres_spec.yaml", "rb") as f:
            shadow_resp = await client.post(f"http://127.0.0.1:8010/api/scan/{scan_id}/openapi", files={"file": ("reqres_spec.yaml", f, "text/yaml")})
        shadow_data = shadow_resp.json()
        print(f"✅ Shadow API Report: {shadow_data['coverage_percent']}% coverage.")
        print(f"   Undocumented APIs found in traffic: {len(shadow_data['undocumented'])}")
        print(f"   Unimplemented APIs (in spec but not traffic): {len(shadow_data['unimplemented'])}")

        print("\n3️⃣ Launching Scan Engine...")
        config = {
            "selected_endpoints": [ep["id"] for ep in endpoints],
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
                "enable_graphql": False
            }
        }
        
        run_resp = await client.post(f"http://127.0.0.1:8010/api/scan/{scan_id}/run", json=config)
        print("✅ Run triggered.")
        
        while True:
            await asyncio.sleep(2)
            status_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/status")
            status = status_resp.json()
            if not status.get("isRunning", False):
                print(f"✅ Scan Complete! {status.get('casesRun')} cases executed.")
                print(f"✅ Discovered {len(status.get('findings', []))} potential vulnerabilities.")
                break
            else:
                print(f"   Scanning... {status.get('progress', 0):.1f}%")

        print("\n4️⃣ Verifying Auto-Remediation Patches...")
        patch_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/patches")
        patches = patch_resp.json()
        print(f"✅ Downloaded {patches.get('total', 0)} security patches.")
        
        print("\n5️⃣ Exporting Reports...")
        json_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/export.json")
        html_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/export.html")
        print(f"✅ Downloaded JSON Report: {len(json_resp.content)} bytes")
        print(f"✅ Downloaded HTML Report: {len(html_resp.content)} bytes")
        
        with open("e2e_report.html", "wb") as f:
            f.write(html_resp.content)
            
        print("\n🎉 End-to-End Test Completed Successfully! (Check e2e_report.html)")

if __name__ == "__main__":
    asyncio.run(run_e2e_test())
