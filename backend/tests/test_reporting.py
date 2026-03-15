from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import _build_replay_curl, _developer_notes_for_finding
from modules.report_generator import generate_executive_report


def test_build_replay_curl_preserves_headers_and_body():
    request = (
        "POST /api/orders HTTP/1.1\n"
        "Host: api.example.com\n"
        "Authorization: Bearer test-token\n"
        "Content-Type: application/json\n"
        "\n"
        '{"order_id":123}'
    )
    curl = _build_replay_curl("POST", "https://api.example.com/api/orders", request)

    assert "curl" in curl
    assert "Authorization: Bearer test-token" in curl
    assert "--data-raw" in curl
    assert "https://api.example.com/api/orders" in curl


def test_developer_notes_are_specific_for_cross_user_access():
    notes = _developer_notes_for_finding(
        "Cross-User Access Control Bypass",
        "User B accessed User A's order",
        "Verify ownership",
    )
    assert "object-level access control" in notes.lower()
    assert "User B accessed User A's order" in notes


def test_generate_executive_report_includes_replay_and_notes():
    state = SimpleNamespace(
        file_name="demo.har",
        format="har",
        cases_run=12,
        total_cases=12,
        started_at="2026-03-15 10:00:00",
        report_findings=[
            {
                "id": "F-100001",
                "severity": "HIGH",
                "type": "Cross-User Access Control Bypass",
                "endpoint": "/api/orders/{id}",
                "method": "GET",
                "host": "api.example.com",
                "cvss": 8.8,
                "cwe": "CWE-639",
                "evidence": "User B accessed User A data.",
                "request": "GET /api/orders/123 HTTP/1.1\nHost: api.example.com",
                "response": "HTTP/1.1 200\nContent-Type: application/json\n\n{\"id\":123}",
                "request_url": "https://api.example.com/api/orders/123",
                "replay_curl": "curl -i -s -X GET 'https://api.example.com/api/orders/123'",
                "request_summary": "Method: GET\nURL: https://api.example.com/api/orders/123",
                "response_summary": "Status: HTTP/1.1 200",
                "developer_notes": "Compare User A and User B access on the same order.",
                "verification_steps": [
                    "Replay the request and confirm the same result.",
                    "Retry with another user session.",
                ],
                "recommendation": "Verify ownership before returning the order.",
                "timestamp": "2026-03-15 10:00:05",
            }
        ],
    )

    html = generate_executive_report("scan-123", state)
    assert "Replay Command" in html
    assert "Developer Notes" in html
    assert "Verification Steps" in html
    assert "curl -i -s -X GET" in html
