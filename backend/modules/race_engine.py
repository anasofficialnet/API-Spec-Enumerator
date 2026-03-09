"""
AASE Module 3: Race Condition Detection Engine
===============================================
Identifies race-prone endpoints and sends concurrent request
bursts to detect Time-of-Check-Time-of-Use (TOCTOU) flaws.
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

# Keywords that indicate race-prone operations
RACE_KEYWORDS = re.compile(
    r"(transfer|redeem|checkout|purchase|buy|pay|withdraw|apply|coupon|"
    r"voucher|gift|claim|activate|create|submit|vote|like|follow|subscribe)",
    re.IGNORECASE,
)


def identify_race_targets(endpoints: dict) -> List[str]:
    """
    Identify endpoints likely vulnerable to race conditions.
    Returns list of endpoint IDs.
    """
    targets = []
    for eid, ep in endpoints.items():
        # Only POST/PUT/PATCH are state-changing
        if ep.method not in ("POST", "PUT", "PATCH"):
            continue
        # Check if path contains race-prone keywords
        if RACE_KEYWORDS.search(ep.path):
            targets.append(eid)
            continue
        # Also flag any POST endpoint with body fields (state-changing)
        if ep.method == "POST" and ep.body_fields:
            targets.append(eid)
    return targets


def build_race_burst(
    rec: Any,
    endpoint: Any,
    config_auth: Optional[dict] = None,
    target_base_url: Optional[str] = None,
    burst_size: int = 10,
) -> List[Dict[str, Any]]:
    """
    Build a burst of identical requests for race condition testing.
    All requests in a burst are meant to be sent simultaneously.
    """
    headers = dict(rec.headers)
    if config_auth:
        if config_auth.get("bearer"):
            headers["Authorization"] = f"Bearer {config_auth['bearer']}"
        for k, v in config_auth.get("headers", {}).items():
            headers[k] = v
        if config_auth.get("cookies"):
            cookie_str = "; ".join(f"{k}={v}" for k, v in config_auth["cookies"].items())
            headers["Cookie"] = cookie_str

    url = rec.url
    if target_base_url:
        parsed = urlparse(url)
        base = urlparse(target_base_url)
        if base.scheme and base.netloc:
            url = urlunparse((base.scheme, base.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

    burst_id = uuid.uuid4().hex[:8]
    cases = []
    for i in range(burst_size):
        cases.append({
            "id": "race_burst",
            "method": rec.method,
            "url": url,
            "headers": headers,
            "body": rec.body,
            "ep_key": endpoint.id,
            "category": "race",
            "race_meta": {
                "burst_id": burst_id,
                "burst_index": i,
                "burst_size": burst_size,
                "endpoint_path": endpoint.path,
            },
        })

    return cases


async def execute_race_burst(
    client: Any,
    cases: List[Dict[str, Any]],
) -> List[Tuple[Dict[str, Any], Any]]:
    """
    Execute all cases in a burst simultaneously.
    Returns list of (case, response) tuples.
    """
    async def _send(case: Dict[str, Any]):
        try:
            resp = await client.request(
                case["method"],
                case["url"],
                headers=case["headers"],
                content=case.get("body"),
            )
            return (case, resp)
        except Exception:
            return (case, None)

    results = await asyncio.gather(*[_send(c) for c in cases])
    return list(results)


def analyze_race_results(
    results: List[Tuple[Dict[str, Any], Any]],
) -> Optional[Dict[str, Any]]:
    """
    Analyze race burst results.
    If multiple requests succeed (2xx) and produce different resource IDs,
    it indicates a race condition.
    """
    successful = []
    for case, resp in results:
        if resp is None:
            continue
        if resp.status_code < 300:
            body_text = ""
            try:
                body_text = resp.content.decode("utf-8", errors="ignore")
            except Exception:
                pass
            successful.append({
                "status": resp.status_code,
                "body": body_text[:1000],
                "index": case.get("race_meta", {}).get("burst_index", 0),
            })

    if len(successful) <= 1:
        return None

    # Check if responses contain different IDs (distinct resources created)
    bodies = [s["body"] for s in successful]
    unique_bodies = set(bodies)

    meta = results[0][0].get("race_meta", {}) if results else {}
    burst_size = meta.get("burst_size", len(results))

    if len(successful) > 1:
        severity = "CRITICAL" if len(unique_bodies) > 1 else "HIGH"
        evidence = (
            f"{len(successful)}/{burst_size} concurrent requests succeeded. "
        )
        if len(unique_bodies) > 1:
            evidence += (
                f"{len(unique_bodies)} distinct responses detected — "
                f"likely multiple resources created from a single operation."
            )
        else:
            evidence += "All responses identical — possible duplicate processing."

        return {
            "severity": severity,
            "type": "Race Condition (TOCTOU)",
            "evidence": evidence,
            "recommendation": (
                "Implement server-side locking mechanisms:\n"
                "1. Database-level: Use SELECT FOR UPDATE or advisory locks\n"
                "2. Application-level: Use idempotency keys with unique constraints\n"
                "3. Redis distributed locks for multi-instance deployments\n"
                "4. Optimistic locking with version columns"
            ),
            "cwe": "CWE-362",
            "cvss": 8.1 if severity == "CRITICAL" else 6.5,
        }

    return None
