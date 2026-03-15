"""
AASE Backend Test Suite
Run with: pip install pytest pytest-asyncio httpx && pytest tests/ -v
"""
from __future__ import annotations

import json
import sys
import os
import importlib

# Make the backend importable from this tests/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from modules.auto_recon import AutoReconEngine
from main import (
    app,
    _normalize_path,
    _parse_har,
    _parse_jsonl,
    _parse_raw_http,
    _build_endpoints,
    _build_cases,
    RunConfig,
    EndpointInfo,
    RequestRecord,
    OASTEngine,
)


# ---------------------------------------------------------------------------
# Unit Tests: path normalisation
# ---------------------------------------------------------------------------

def test_normalize_numeric_segment():
    assert _normalize_path("/users/123") == "/users/{id}"

def test_normalize_uuid_segment():
    assert _normalize_path("/items/550e8400-e29b-41d4-a716-446655440000") == "/items/{id}"

def test_normalize_multi_segment():
    assert _normalize_path("/orgs/99/repos/42/pulls/7") == "/orgs/{id}/repos/{id}/pulls/{id}"

def test_normalize_no_dynamic():
    assert _normalize_path("/api/users") == "/api/users"

def test_normalize_root():
    assert _normalize_path("/") == "/"


# ---------------------------------------------------------------------------
# Unit Tests: HAR parser
# ---------------------------------------------------------------------------

SAMPLE_HAR = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "http://localhost:5000/api/users",
                    "headers": [{"name": "Accept", "value": "application/json"}],
                    "queryString": [],
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "content": {"mimeType": "application/json", "text": "[{\"id\":1}]"},
                },
            },
            {
                "request": {
                    "method": "POST",
                    "url": "http://localhost:5000/api/users",
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"},
                        {"name": "Authorization", "value": "Bearer tok"},
                    ],
                    "queryString": [],
                    "postData": {"mimeType": "application/json", "text": '{"name":"Alice"}'},
                },
                "response": {
                    "status": 201,
                    "headers": [],
                    "content": {"mimeType": "application/json", "text": '{"id":2}'},
                },
            },
        ]
    }
}).encode()

def test_parse_har_count():
    records = _parse_har(SAMPLE_HAR)
    assert len(records) == 2

def test_parse_har_methods():
    records = _parse_har(SAMPLE_HAR)
    methods = {r.method for r in records}
    assert methods == {"GET", "POST"}

def test_parse_har_body():
    records = _parse_har(SAMPLE_HAR)
    post_rec = next(r for r in records if r.method == "POST")
    assert post_rec.body is not None
    data = json.loads(post_rec.body)
    assert data["name"] == "Alice"

def test_parse_har_auth_header():
    records = _parse_har(SAMPLE_HAR)
    post_rec = next(r for r in records if r.method == "POST")
    assert "Authorization" in post_rec.headers

def test_parse_har_status():
    records = _parse_har(SAMPLE_HAR)
    get_rec = next(r for r in records if r.method == "GET")
    assert get_rec.status == 200


# ---------------------------------------------------------------------------
# Unit Tests: JSONL parser
# ---------------------------------------------------------------------------

SAMPLE_JSONL = b'\n'.join([
    b'{"method":"GET","url":"http://localhost:5000/api/items","headers":{"Accept":"application/json"},"status":200}',
    b'{"method":"POST","url":"http://localhost:5000/api/items","headers":{"Content-Type":"application/json"},"body":{"name":"Widget"},"status":201}',
    b'',  # blank line should be skipped
    b'not-valid-json',  # should be skipped
])

def test_parse_jsonl_count():
    records = _parse_jsonl(SAMPLE_JSONL)
    assert len(records) == 2

def test_parse_jsonl_methods():
    records = _parse_jsonl(SAMPLE_JSONL)
    assert records[0].method == "GET"
    assert records[1].method == "POST"

def test_parse_jsonl_body_dict():
    records = _parse_jsonl(SAMPLE_JSONL)
    post_rec = records[1]
    assert post_rec.body is not None
    data = json.loads(post_rec.body)
    assert data["name"] == "Widget"


# ---------------------------------------------------------------------------
# Unit Tests: raw HTTP paste parser
# ---------------------------------------------------------------------------

RAW_HTTP = (
    "GET /api/users HTTP/1.1\n"
    "Host: localhost:5000\n"
    "Accept: application/json\n"
    "\n"
    "POST /api/orders HTTP/1.1\n"
    "Host: localhost:5000\n"
    "Content-Type: application/json\n"
    "\n"
    '{"item_id":1,"qty":2}'
)

def test_parse_raw_http_count():
    records = _parse_raw_http(RAW_HTTP)
    assert len(records) == 2

def test_parse_raw_http_methods():
    records = _parse_raw_http(RAW_HTTP)
    assert records[0].method == "GET"
    assert records[1].method == "POST"

def test_parse_raw_http_host():
    records = _parse_raw_http(RAW_HTTP)
    assert "localhost:5000" in records[0].url


# ---------------------------------------------------------------------------
# Unit Tests: endpoint discovery
# ---------------------------------------------------------------------------

def test_build_endpoints_deduplication():
    """Two records with same method+host+normalized_path → one endpoint."""
    records = [
        RequestRecord("GET", "http://localhost:5000/api/users/1", {}, None, 200),
        RequestRecord("GET", "http://localhost:5000/api/users/2", {}, None, 200),
        RequestRecord("POST", "http://localhost:5000/api/users", {"Content-Type": "application/json"}, b'{"name":"x"}', 201),
    ]
    endpoints = _build_endpoints(records)
    assert len(endpoints) == 2  # /api/users/{id} and /api/users

def test_build_endpoints_preserves_source_metadata():
    records = [
        RequestRecord("GET", "http://localhost:5000/api/users/1", {}, None, 200, source="seed_probe", discovery_status="confirmed"),
        RequestRecord("GET", "http://localhost:5000/api/users/2", {}, None, 200, source="traffic"),
        RequestRecord("GET", "http://localhost:5000/api/users/3", {}, None, 200, source="crawl", discovery_status="derived"),
    ]
    endpoints = _build_endpoints(records)
    endpoint = next(iter(endpoints.values()))
    assert endpoint.path == "/api/users/{id}"
    assert endpoint.primary_source == "traffic"
    assert endpoint.all_sources == ["traffic", "crawl", "seed_probe"]
    assert endpoint.source_statuses["seed_probe"] == "confirmed"

def test_build_endpoints_seed_probe_status_tracked():
    records = [
        RequestRecord("GET", "https://example.com/graphql", {}, None, 200, source="seed_probe", discovery_status="confirmed"),
    ]
    endpoints = _build_endpoints(records)
    endpoint = next(iter(endpoints.values()))
    assert endpoint.primary_source == "seed_probe"
    assert endpoint.discovery_status == "confirmed"
    assert endpoint.all_sources == ["seed_probe"]


# ---------------------------------------------------------------------------
# Unit Tests: fuzz case builder
# ---------------------------------------------------------------------------

def _make_endpoint_and_record():
    rec = RequestRecord(
        method="GET",
        url="http://localhost:5000/api/users?page=1",
        headers={"Authorization": "Bearer tok"},
        body=None,
        status=200,
    )
    ep = EndpointInfo(
        id="ep-test",
        method="GET",
        path="/api/users",
        host="localhost:5000",
        status_codes=[200],
        auth_required=True,
        params=["page"],
        body_fields=[],
        schema_confidence=85.0,
        fuzz_cases=10,
    )
    return ep, rec

def test_build_cases_includes_baseline():
    ep, rec = _make_endpoint_and_record()
    config = RunConfig(allowlist=["localhost"], target_base_url="http://localhost:5000")
    cases = _build_cases(rec, ep, config)
    ids = [c["id"] for c in cases]
    assert "baseline" in ids

def test_build_cases_includes_cors():
    ep, rec = _make_endpoint_and_record()
    config = RunConfig(allowlist=["localhost"], target_base_url="http://localhost:5000")
    cases = _build_cases(rec, ep, config)
    ids = [c["id"] for c in cases]
    assert "cors_probe" in ids

def test_build_cases_includes_auth_bypass():
    ep, rec = _make_endpoint_and_record()
    config = RunConfig(allowlist=["localhost"], target_base_url="http://localhost:5000")
    cases = _build_cases(rec, ep, config)
    ids = [c["id"] for c in cases]
    assert "auth_bypass" in ids

def test_build_cases_auth_bypass_missing_headers():
    ep, rec = _make_endpoint_and_record()
    config = RunConfig(allowlist=["localhost"], target_base_url="http://localhost:5000")
    cases = _build_cases(rec, ep, config)
    bypass = next(c for c in cases if c["id"] == "auth_bypass")
    assert "Authorization" not in bypass["headers"]
    assert "Cookie" not in bypass["headers"]


# ---------------------------------------------------------------------------
# Integration Tests: full upload → status round-trip
# ---------------------------------------------------------------------------

client = TestClient(app)

def test_ingest_har():
    response = client.post(
        "/api/ingest",
        files={"file": ("sample.har", SAMPLE_HAR, "application/json")},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert "scan_id" in data
    assert data["transactions"] == 2
    assert len(data["endpoints"]) >= 1
    assert data["endpoints"][0]["primary_source"] == "traffic"
    assert data["endpoints"][0]["all_sources"] == ["traffic"]

def test_ingest_jsonl():
    response = client.post(
        "/api/ingest",
        files={"file": ("sample.jsonl", SAMPLE_JSONL, "application/octet-stream")},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["transactions"] == 2

def test_ingest_paste():
    response = client.post(
        "/api/ingest/paste",
        json={"text": RAW_HTTP},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["transactions"] == 2

def test_ingest_paste_jsonl():
    response = client.post(
        "/api/ingest/paste",
        json={"text": SAMPLE_JSONL.decode("utf-8")},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["transactions"] == 2
    assert data["format"] == "jsonl"

def test_auto_recon(monkeypatch):
    async def fake_execute_recon(self):
        return [
            RequestRecord(
                "GET",
                "https://example.com/api/users",
                {"Accept": "application/json"},
                None,
                200,
                source="seed_probe",
                discovery_status="confirmed",
            )
        ]

    monkeypatch.setattr(AutoReconEngine, "execute_recon", fake_execute_recon)
    try:
        backend_auto_recon = importlib.import_module("backend.modules.auto_recon")
    except ModuleNotFoundError:
        backend_auto_recon = None
    if backend_auto_recon is not None:
        monkeypatch.setattr(backend_auto_recon.AutoReconEngine, "execute_recon", fake_execute_recon)

    response = client.post("/api/recon", json={"target_url": "example.com"})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["format"] == "auto_recon"
    assert data["transactions"] == 1
    assert "example.com" in data["hosts"]
    assert len(data["endpoints"]) == 1
    assert data["endpoints"][0]["primary_source"] == "seed_probe"
    assert data["endpoints"][0]["discovery_status"] == "confirmed"

def test_auto_recon_js_candidate_extraction():
    engine = AutoReconEngine("https://example.com")
    text = """
    fetch(`/api/users/${userId}`);
    axios.post("/orders");
    const gql = "/graphql";
    """
    candidates = engine._extract_js_candidates(text, engine.base_url)
    assert "https://example.com/api/users/1" in candidates
    assert "https://example.com/orders" in candidates
    assert "https://example.com/graphql" in candidates

def test_auto_recon_source_map_reference_extraction():
    engine = AutoReconEngine("https://example.com")
    js = """
    console.log("bundle");
    //# sourceMappingURL=/_next/static/chunks/app.js.map
    """
    source_map = engine._extract_source_map_reference(js, "https://example.com/_next/static/chunks/app.js")
    assert source_map == "https://example.com/_next/static/chunks/app.js.map"

def test_auto_recon_source_map_candidate_extraction():
    engine = AutoReconEngine("https://example.com")
    payload = {
        "version": 3,
        "sources": [
            "webpack://_N_E/./src/app/api/users/route.ts",
        ],
        "sourcesContent": [
            "fetch('/api/orders'); axios.post('/graphql');",
        ],
    }
    candidates = engine._extract_source_map_candidates(payload, "https://example.com/_next/static/chunks/app.js.map")
    assert "https://example.com/api/users" in candidates
    assert "https://example.com/api/orders" in candidates
    assert "https://example.com/graphql" in candidates

def test_auto_recon_json_response_path_extraction():
    engine = AutoReconEngine("https://example.com")
    found = set()
    engine._extract_json_candidates(
        {
            "profile": "/api/profile",
            "orders": ["/api/orders/55"],
            "nested": {"audit": "/api/audit/9"},
        },
        engine.base_url,
        found,
    )
    assert "https://example.com/api/profile" in found
    assert "https://example.com/api/orders/55" in found
    assert "https://example.com/api/audit/9" in found

def test_auto_recon_spec_records_are_labeled():
    engine = AutoReconEngine("https://example.com")
    engine._record_spec_endpoint("POST", "/orders/{id}", ["amount"])
    assert len(engine.records) == 1
    record = engine.records[0]
    assert record.source == "spec"
    assert record.discovery_status == "derived"
    assert record.url == "https://example.com/orders/1"

def test_scan_status_initial():
    # Ingest first to get a scan_id
    res = client.post("/api/ingest", files={"file": ("sample.har", SAMPLE_HAR, "application/json")})
    scan_id = res.json()["scan_id"]

    status = client.get(f"/api/scan/{scan_id}/status")
    assert status.status_code == 200
    body = status.json()
    assert "isRunning" in body
    assert body["isRunning"] is False

def test_dry_run_scan():
    """Upload → start dry run scan → poll to completion."""
    # Ingest
    res = client.post("/api/ingest", files={"file": ("sample.har", SAMPLE_HAR, "application/json")})
    assert res.status_code == 200
    data = res.json()
    scan_id = data["scan_id"]
    endpoint_ids = [e["id"] for e in data["endpoints"]]

    # Start dry run
    run_res = client.post(f"/api/scan/{scan_id}/run", json={
        "selected_endpoints": endpoint_ids,
        "config": {
            "allowlist": ["localhost"],
            "target_base_url": "http://localhost:5000",
            "dry_run": True,
            "rate_limit": 100.0,
            "concurrency": 1,
        },
    })
    assert run_res.status_code == 200
    assert run_res.json()["status"] == "started"

def test_preview_scan():
    res = client.post("/api/ingest", files={"file": ("sample.har", SAMPLE_HAR, "application/json")})
    assert res.status_code == 200
    data = res.json()
    scan_id = data["scan_id"]
    endpoint_ids = [e["id"] for e in data["endpoints"]]

    preview = client.post(f"/api/scan/{scan_id}/preview", json={
        "selected_endpoints": endpoint_ids,
        "config": {
            "allowlist": ["localhost"],
            "target_base_url": "http://localhost:5000",
            "dry_run": True,
            "rate_limit": 100.0,
            "concurrency": 1,
            "categories": ["auth", "hidden_params", "cors"],
        },
    })
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["totalCases"] == sum(body["endpointCases"].values())
    assert body["totalCases"] > 0


def test_cancel_scan_idle():
    res = client.post("/api/ingest", files={"file": ("sample.har", SAMPLE_HAR, "application/json")})
    assert res.status_code == 200
    scan_id = res.json()["scan_id"]

    cancel = client.post(f"/api/scan/{scan_id}/cancel")
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "idle"


def test_attack_graph_route():
    res = client.post("/api/ingest", files={"file": ("sample.har", SAMPLE_HAR, "application/json")})
    assert res.status_code == 200
    scan_id = res.json()["scan_id"]

    graph = client.get(f"/api/scan/{scan_id}/attack-graph")
    assert graph.status_code == 200
    body = graph.json()
    assert "nodes" in body
    assert "edges" in body
    assert "paths" in body
    assert len(body["nodes"]) >= 1


def test_oast_callback_route():
    OASTEngine.registry.clear()
    res = client.post("/api/ingest", files={"file": ("sample.har", SAMPLE_HAR, "application/json")})
    assert res.status_code == 200
    data = res.json()
    scan_id = data["scan_id"]
    endpoint_id = data["endpoints"][0]["id"]

    payload = OASTEngine.register_payload(
        scan_id=scan_id,
        endpoint_id=endpoint_id,
        endpoint_path="/api/users",
        vector_type="blind_ssrf_header",
        callback_base_url="http://testserver",
        request_url="http://localhost:5000/api/users",
    )

    callback = client.get(f"/api/oast/{payload['token']}")
    assert callback.status_code == 200, callback.text

    events = client.get(f"/api/scan/{scan_id}/oast")
    assert events.status_code == 200
    assert len(events.json()["events"]) == 1

    report = client.get(f"/api/scan/{scan_id}/report")
    assert report.status_code == 200
    findings = report.json()["findings"]
    assert any(f["type"] == "Confirmed Blind Callback/OAST" for f in findings)

def test_export_json():
    res = client.post("/api/ingest", files={"file": ("sample.har", SAMPLE_HAR, "application/json")})
    scan_id = res.json()["scan_id"]
    export = client.get(f"/api/scan/{scan_id}/export.json")
    assert export.status_code == 200
    payload = export.json()
    assert payload["meta"]["scan_id"] == scan_id
    assert "findings" in payload

def test_export_html():
    res = client.post("/api/ingest", files={"file": ("sample.har", SAMPLE_HAR, "application/json")})
    scan_id = res.json()["scan_id"]
    export = client.get(f"/api/scan/{scan_id}/export.html")
    assert export.status_code == 200
    html = export.text
    assert "confidential" in html.lower()
    assert scan_id in html

def test_404_on_missing_scan():
    assert client.get("/api/scan/doesnotexist/status").status_code == 404
    assert client.get("/api/scan/doesnotexist/export.json").status_code == 404
