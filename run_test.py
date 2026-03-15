import asyncio
import httpx
import json

RAW_HTTP = """GET / HTTP/1.1
Host: testphp.vulnweb.com
User-Agent: curl/8.x
Accept: */*

"""

async def run_test():
    async with httpx.AsyncClient(timeout=30.0) as client:
        print("Uploading Raw HTTP traffic to AASE via /api/ingest/paste...")
        resp = await client.post("http://127.0.0.1:8010/api/ingest/paste", json={"text": RAW_HTTP})
        
        if resp.status_code != 200:
            print(f"Failed to upload: {resp.text}")
            return
            
        data = resp.json()
        scan_id = data["scan_id"]
        endpoints = data["endpoints"]
        print(f"Uploaded! Scan ID: {scan_id}. Found {len(endpoints)} endpoints.")
        
        print("Launching Aggressive Power Scan...")
        payload = {
            "selected_endpoints": [ep["id"] for ep in endpoints],
            "config": {
                "allowlist": ["testphp.vulnweb.com"],
                "target_base_url": "http://testphp.vulnweb.com",
                "rate_limit": 10.0,
                "concurrency": 5,
                "respect_robots": False,
                "dry_run": False,
                "aggressive": True,
                "categories": ["auth", "hidden_params", "cors", "error_leak", "sqli", "xss", "ssti"],
                "enable_bola": False,
                "enable_stateful": True,
                "enable_race": True,
                "burst_size": 10,
                "enable_mutations": True,
                "enable_graphql": True
            }
        }
        
        run_resp = await client.post(f"http://127.0.0.1:8010/api/scan/{scan_id}/run", json=payload)
        print(f"Run triggered: {run_resp.status_code}")
        
        while True:
            await asyncio.sleep(2)
            status_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/status")
            status = status_resp.json()
            if not status.get("isRunning", False):
                print("\n✅ Scan Complete!")
                print("--------------------------------------------------")
                print(f"Total Cases Run: {status.get('casesRun')}")
                print(f"Total Findings: {len(status.get('findings', []))}")
                for f in status.get('findings', []):
                    print(f"[{f['severity']}] {f['type']} on {f['endpoint']}")
                    print(f"  Issue: {f['evidence']}")
                
                # Get patches
                patch_resp = await client.get(f"http://127.0.0.1:8010/api/scan/{scan_id}/patches")
                if patch_resp.status_code == 200:
                    patches = patch_resp.json()
                    print(f"\nCreated {patches.get('total', 0)} automatically generated patches.")
                break
            else:
                progress = status.get('progress', 0)
                print(f"Scanning... {progress:.1f}% ({status.get('casesRun')} / {status.get('totalCases')} cases)")

if __name__ == "__main__":
    asyncio.run(run_test())
