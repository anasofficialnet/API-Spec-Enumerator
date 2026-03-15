"""
AASE Module 1: Cross-User Access Detection Engine
=================================================
Detects broken object-level authorization by replaying User A's
resource-specific requests with User B's credentials. If User B
can access User A's resources, it is treated as a confirmed issue.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse, urlunparse

# Reuse regexes for ID detection
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
)
NUM_RE = re.compile(r"^\d+$")
# Match common ID-bearing param names
ID_PARAM_RE = re.compile(r"(?:^|_)(id|Id|ID|uuid|key|slug|token|ref|code)(?:$|_)", re.IGNORECASE)


@dataclass
class ResourceId:
    """A resource identifier discovered in traffic."""

    value: str
    source: str  # "url_path" | "url_param" | "response_body" | "request_body"
    endpoint_id: str
    param_name: Optional[str] = None


def _is_id_value(val: str) -> bool:
    """Check if a string looks like a resource identifier."""
    if NUM_RE.match(val) and len(val) <= 20:
        return True
    if UUID_RE.match(val):
        return True
    # Short alphanumeric slugs (4-40 chars, not common words)
    if re.match(r"^[a-zA-Z0-9_-]{4,40}$", val) and not val.isalpha():
        return True
    return False


def extract_resource_ids(records: list, endpoints: dict) -> Dict[str, List[ResourceId]]:
    """
    Extract resource IDs from recorded traffic.
    Returns a mapping of endpoint_id -> list of ResourceId objects.
    """
    id_map: Dict[str, List[ResourceId]] = {}

    for rec in records:
        parsed = urlparse(rec.url)
        ep_id = None
        for eid, ep in endpoints.items():
            if parsed.netloc == ep.host and rec.method == ep.method:
                path_segs = [s for s in (parsed.path or "/").split("/") if s]
                ep_segs = [s for s in ep.path.split("/") if s]
                if len(path_segs) == len(ep_segs):
                    ep_id = eid
                    break
        if not ep_id:
            continue

        id_map.setdefault(ep_id, [])

        path_segments = [s for s in (parsed.path or "/").split("/") if s]
        for seg in path_segments:
            if _is_id_value(seg):
                id_map[ep_id].append(ResourceId(value=seg, source="url_path", endpoint_id=ep_id))

        query_params = parse_qs(parsed.query)
        for param_name, values in query_params.items():
            if ID_PARAM_RE.search(param_name):
                for value in values:
                    if _is_id_value(value):
                        id_map[ep_id].append(
                            ResourceId(
                                value=value,
                                source="url_param",
                                endpoint_id=ep_id,
                                param_name=param_name,
                            )
                        )

        if rec.response_body:
            try:
                resp_data = json.loads(rec.response_body.decode("utf-8", errors="ignore"))
                _extract_json_ids(resp_data, ep_id, "response_body", id_map)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        if rec.body:
            try:
                req_data = json.loads(rec.body.decode("utf-8", errors="ignore"))
                _extract_json_ids(req_data, ep_id, "request_body", id_map)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    for ep_id, resources in list(id_map.items()):
        seen = set()
        unique: List[ResourceId] = []
        for rid in resources:
            key = (rid.value, rid.source)
            if key not in seen:
                seen.add(key)
                unique.append(rid)
        id_map[ep_id] = unique

    return id_map


def _extract_json_ids(
    data: Any,
    ep_id: str,
    source: str,
    id_map: Dict[str, List[ResourceId]],
    depth: int = 0,
) -> None:
    """Recursively extract ID-like values from JSON data."""
    if depth > 5:
        return
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (str, int)):
                str_val = str(value)
                if ID_PARAM_RE.search(key) and _is_id_value(str_val):
                    id_map.setdefault(ep_id, []).append(
                        ResourceId(value=str_val, source=source, endpoint_id=ep_id, param_name=key)
                    )
            elif isinstance(value, (dict, list)):
                _extract_json_ids(value, ep_id, source, id_map, depth + 1)
    elif isinstance(data, list):
        for item in data[:10]:
            _extract_json_ids(item, ep_id, source, id_map, depth + 1)


def build_bola_cases(
    records: list,
    endpoints: dict,
    user_a_auth: dict,
    user_b_auth: dict,
    target_base_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Build cross-user replay cases by taking User A's resource requests
    and replaying them with User B's credentials.
    """
    id_map = extract_resource_ids(records, endpoints)
    cases: List[Dict[str, Any]] = []

    for ep_id, resource_ids in id_map.items():
        if ep_id not in endpoints:
            continue
        endpoint = endpoints[ep_id]

        rec = None
        for record in records:
            parsed = urlparse(record.url)
            if parsed.netloc == endpoint.host and record.method == endpoint.method:
                rec = record
                break
        if not rec:
            continue

        user_b_headers = dict(rec.headers)
        user_b_headers.pop("Authorization", None)
        user_b_headers.pop("Cookie", None)
        if user_b_auth.get("bearer"):
            user_b_headers["Authorization"] = f"Bearer {user_b_auth['bearer']}"
        for key, value in user_b_auth.get("headers", {}).items():
            user_b_headers[key] = value
        if user_b_auth.get("cookies"):
            cookie_str = "; ".join(f"{key}={value}" for key, value in user_b_auth["cookies"].items())
            user_b_headers["Cookie"] = cookie_str

        seen_urls = set()
        for rid in resource_ids:
            url = rec.url
            if target_base_url:
                parsed = urlparse(url)
                base = urlparse(target_base_url)
                url = urlunparse((base.scheme, base.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

            if rid.value not in url and rid.source == "url_path":
                continue

            if url in seen_urls:
                continue
            seen_urls.add(url)

            cases.append(
                {
                    "id": "bola_probe",
                    "method": rec.method,
                    "url": url,
                    "headers": user_b_headers,
                    "body": rec.body,
                    "ep_key": ep_id,
                    "category": "bola",
                    "bola_meta": {
                        "resource_id": rid.value,
                        "resource_source": rid.source,
                        "user_a_auth": bool(user_a_auth),
                        "user_b_auth": bool(user_b_auth),
                    },
                }
            )

    return cases


def analyze_bola_response(
    baseline_body: Optional[bytes],
    cross_user_body: Optional[bytes],
    cross_user_status: int,
    case_meta: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Analyze a cross-user access replay response.
    Returns finding details if cross-user access is detected, None otherwise.
    """
    if cross_user_status >= 400:
        return None

    if cross_user_status < 300:
        similarity = 0.0
        if baseline_body and cross_user_body:
            try:
                baseline_text = baseline_body.decode("utf-8", errors="ignore")[:2000]
                cross_text = cross_user_body.decode("utf-8", errors="ignore")[:2000]
                if baseline_text and cross_text:
                    common = sum(1 for a, b in zip(baseline_text, cross_text) if a == b)
                    similarity = common / max(len(baseline_text), len(cross_text), 1)
            except Exception:
                pass

        severity = "CRITICAL" if similarity > 0.7 else "HIGH"
        resource_id = str((case_meta or {}).get("resource_id") or "").strip()
        evidence = f"User B accessed User A's resource (HTTP {cross_user_status})"
        if resource_id:
            evidence += f" for resource id {resource_id}"
        if similarity > 0.5:
            evidence += f" - response similarity {similarity:.0%} (likely same data)"

        return {
            "severity": severity,
            "type": "Cross-User Access Control Bypass",
            "evidence": evidence,
            "recommendation": (
                "Implement object-level authorization checks. Verify that the authenticated user "
                "owns or has permission to access the requested resource. Use middleware to enforce "
                "ownership validation on all resource-specific endpoints."
            ),
            "cwe": "CWE-639",
            "cvss": 9.1 if severity == "CRITICAL" else 7.5,
        }

    return None
