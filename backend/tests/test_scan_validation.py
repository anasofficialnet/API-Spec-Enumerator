from __future__ import annotations

import json
import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import SCANS, ScanState, app


client = TestClient(app)

SAMPLE_HAR = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "http://localhost:5000/api/users",
                    "headers": [{"name": "Accept", "value": "application/json"}],
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                },
            },
            {
                "request": {
                    "method": "POST",
                    "url": "http://localhost:5000/api/users",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "postData": {"mimeType": "application/json", "text": '{"name":"Alice"}'},
                },
                "response": {
                    "status": 201,
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                },
            },
        ]
    }
}).encode()

GRAPHQL_HAR = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/graphql",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "postData": {"mimeType": "application/json", "text": '{"query":"{ __typename }"}'},
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                },
            }
        ]
    }
}).encode()


def _ingest_sample(content: bytes = SAMPLE_HAR) -> dict:
    response = client.post("/api/ingest", files={"file": ("sample.har", content, "application/json")})
    assert response.status_code == 200, response.text
    return response.json()


def test_ingest_reports_detected_capabilities():
    data = _ingest_sample(GRAPHQL_HAR)
    assert data["capabilities"]["graphql"] is True
    assert data["capabilities"]["graphqlCount"] >= 1
    assert data["capabilities"]["websocket"] is False


def test_preview_rejects_bola_without_second_user_auth():
    data = _ingest_sample()
    endpoint_ids = [endpoint["id"] for endpoint in data["endpoints"]]

    preview = client.post(
        f"/api/scan/{data['scan_id']}/preview",
        json={
            "selected_endpoints": endpoint_ids,
            "config": {
                "allowlist": ["localhost"],
                "target_base_url": "http://localhost:5000",
                "enable_bola": True,
            },
        },
    )

    assert preview.status_code == 400
    assert "second user token" in preview.json()["detail"].lower()


def test_preview_rejects_auto_login_without_required_fields():
    data = _ingest_sample()
    endpoint_ids = [endpoint["id"] for endpoint in data["endpoints"]]

    preview = client.post(
        f"/api/scan/{data['scan_id']}/preview",
        json={
            "selected_endpoints": endpoint_ids,
            "config": {
                "allowlist": ["localhost"],
                "target_base_url": "http://localhost:5000",
                "enable_auto_login": True,
            },
        },
    )

    assert preview.status_code == 400
    assert "auto login requires" in preview.json()["detail"].lower()


def test_preview_rejects_remote_oast_with_local_callback():
    data = _ingest_sample()
    endpoint_ids = [endpoint["id"] for endpoint in data["endpoints"]]

    preview = client.post(
        f"/api/scan/{data['scan_id']}/preview",
        json={
            "selected_endpoints": endpoint_ids,
            "config": {
                "allowlist": ["api.example.com"],
                "target_base_url": "https://api.example.com",
                "enable_oast": True,
                "oast_callback_base_url": "http://127.0.0.1:8010",
            },
        },
    )

    assert preview.status_code == 400
    assert "reachable from the remote target host" in preview.json()["detail"].lower()


def test_preview_rejects_race_without_selected_write_endpoints():
    data = _ingest_sample()
    get_only_endpoint = next(endpoint["id"] for endpoint in data["endpoints"] if endpoint["method"] == "GET")

    preview = client.post(
        f"/api/scan/{data['scan_id']}/preview",
        json={
            "selected_endpoints": [get_only_endpoint],
            "config": {
                "allowlist": ["localhost"],
                "target_base_url": "http://localhost:5000",
                "enable_race": True,
                "burst_size": 5,
            },
        },
    )

    assert preview.status_code == 400
    assert "write endpoints" in preview.json()["detail"].lower()


def test_scan_events_include_dry_run_log_for_completed_runs():
    scan_id = "dry-run-events"
    SCANS[scan_id] = ScanState(
        scan_id=scan_id,
        file_name="dry-run.har",
        format="har",
        records=[],
        endpoints={},
        is_running=False,
        total_cases=2,
        cases_run=2,
        dry_run_log=[
            {"id": "baseline", "method": "GET", "url": "http://localhost:5000/api/users", "ep_key": "ep-1"},
            {"id": "cors_probe", "method": "GET", "url": "http://localhost:5000/api/users", "ep_key": "ep-1"},
        ],
    )
    try:
        with client.stream("GET", f"/api/scan/{scan_id}/events") as response:
            assert response.status_code == 200
            body = "".join(response.iter_text())
    finally:
        SCANS.pop(scan_id, None)

    assert "\"dry_run_log\"" in body
    assert "\"baseline\"" in body
    assert "{\"done\": true}" in body
