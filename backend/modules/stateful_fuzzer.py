"""
AASE Module 2: Stateful Sequential Fuzzing
===========================================
Discovers multi-step API workflows from traffic order and
generates fuzzing cases that exploit business logic flaws
by skipping steps, replaying steps, or mutating intermediate state.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class ChainStep:
    """One step in a request chain."""
    method: str
    path: str
    host: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes]
    endpoint_id: str
    order: int


@dataclass
class RequestChain:
    """An ordered sequence of dependent API calls."""
    chain_id: str
    steps: List[ChainStep]
    description: str


# Keywords that indicate state-changing / sequential semantics
CHAIN_KEYWORDS = {
    "create": 1, "register": 1, "signup": 1, "init": 1,
    "add": 2, "cart": 2, "select": 2, "configure": 2,
    "update": 3, "modify": 3, "edit": 3,
    "confirm": 4, "submit": 4, "checkout": 4, "finalize": 4,
    "pay": 5, "transfer": 5, "execute": 5, "process": 5,
    "verify": 6, "validate": 6, "complete": 6,
    "delete": 7, "cancel": 7, "revoke": 7,
}


def _path_order_score(path: str) -> int:
    """Score a path by its likely position in a workflow."""
    path_lower = path.lower()
    best = 0
    for keyword, score in CHAIN_KEYWORDS.items():
        if keyword in path_lower:
            best = max(best, score)
    return best


def discover_chains(records: list, endpoints: dict) -> List[RequestChain]:
    """
    Analyze recorded traffic to discover request chains.
    Groups requests by host and session, then orders by temporal sequence.
    """
    # Group records by host
    host_groups: Dict[str, List] = {}
    for i, rec in enumerate(records):
        parsed = urlparse(rec.url)
        host = parsed.netloc
        if host not in host_groups:
            host_groups[host] = []
        host_groups[host].append((i, rec))

    chains: List[RequestChain] = []

    for host, host_records in host_groups.items():
        # Group by session (cookie/auth similarity)
        sessions: Dict[str, List] = {}
        for idx, rec in host_records:
            # Session key: auth token or cookie (first 32 chars)
            auth = rec.headers.get("Authorization", "")
            cookie = rec.headers.get("Cookie", "")
            session_key = (auth[:32] + cookie[:32]) or "anonymous"
            if session_key not in sessions:
                sessions[session_key] = []
            sessions[session_key].append((idx, rec))

        for session_key, session_records in sessions.items():
            if len(session_records) < 2:
                continue

            # Sort by original order (index in records list)
            session_records.sort(key=lambda x: x[0])

            # Build chain from POST/PUT/PATCH/DELETE requests (state-changing)
            state_changing = []
            for idx, rec in session_records:
                if rec.method in ("POST", "PUT", "PATCH", "DELETE"):
                    parsed = urlparse(rec.url)
                    # Find endpoint_id
                    ep_id = "unknown"
                    for eid, ep in endpoints.items():
                        if ep.host == parsed.netloc and ep.method == rec.method:
                            ep_id = eid
                            break
                    state_changing.append(ChainStep(
                        method=rec.method,
                        path=parsed.path or "/",
                        host=parsed.netloc,
                        url=rec.url,
                        headers=dict(rec.headers),
                        body=rec.body,
                        endpoint_id=ep_id,
                        order=idx,
                    ))

            if len(state_changing) >= 2:
                # Sort by semantic order score, then by original order
                state_changing.sort(key=lambda s: (_path_order_score(s.path), s.order))

                chain = RequestChain(
                    chain_id=uuid.uuid4().hex[:8],
                    steps=state_changing,
                    description=f"{host}: {' → '.join(f'{s.method} {s.path}' for s in state_changing[:5])}",
                )
                chains.append(chain)

    return chains


def build_stateful_cases(
    chain: RequestChain,
    config_auth: Optional[dict] = None,
    target_base_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Generate fuzz cases from a request chain:
    1. Skip-step: omit intermediate steps
    2. Replay-step: repeat a step multiple times
    3. Reverse-order: execute chain in reverse
    4. Mutate-intermediate: alter body of intermediate step
    """
    cases: List[Dict[str, Any]] = []

    if len(chain.steps) < 2:
        return cases

    def _apply_auth(headers: Dict[str, str]) -> Dict[str, str]:
        h = dict(headers)
        if config_auth:
            if config_auth.get("bearer"):
                h["Authorization"] = f"Bearer {config_auth['bearer']}"
            for k, v in config_auth.get("headers", {}).items():
                h[k] = v
            if config_auth.get("cookies"):
                cookie_str = "; ".join(f"{k}={v}" for k, v in config_auth["cookies"].items())
                h["Cookie"] = cookie_str
        return h

    def _apply_base(url: str) -> str:
        if not target_base_url:
            return url
        parsed = urlparse(url)
        base = urlparse(target_base_url)
        if base.scheme and base.netloc:
            from urllib.parse import urlunparse
            return urlunparse((base.scheme, base.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
        return url

    # 1. Skip-step attacks: for each intermediate step, create a chain that skips it
    for skip_idx in range(len(chain.steps) - 1):
        # Execute only the last step (the "finalize" step) without the skipped prerequisite
        final_step = chain.steps[-1]
        cases.append({
            "id": "stateful_skip",
            "method": final_step.method,
            "url": _apply_base(final_step.url),
            "headers": _apply_auth(final_step.headers),
            "body": final_step.body,
            "ep_key": final_step.endpoint_id,
            "category": "stateful",
            "stateful_meta": {
                "chain_id": chain.chain_id,
                "attack": "skip_step",
                "skipped_step": skip_idx,
                "chain_desc": chain.description,
            },
        })

    # 2. Replay attack: repeat a step multiple times to check for idempotency issues
    for step in chain.steps:
        if step.method in ("POST", "PUT", "PATCH"):
            cases.append({
                "id": "stateful_replay",
                "method": step.method,
                "url": _apply_base(step.url),
                "headers": _apply_auth(step.headers),
                "body": step.body,
                "ep_key": step.endpoint_id,
                "category": "stateful",
                "stateful_meta": {
                    "chain_id": chain.chain_id,
                    "attack": "replay",
                    "replayed_path": step.path,
                    "chain_desc": chain.description,
                },
            })

    # 3. Reverse-order: execute the last step first
    first_step = chain.steps[0]
    last_step = chain.steps[-1]
    if first_step != last_step:
        cases.append({
            "id": "stateful_reverse",
            "method": last_step.method,
            "url": _apply_base(last_step.url),
            "headers": _apply_auth(last_step.headers),
            "body": last_step.body,
            "ep_key": last_step.endpoint_id,
            "category": "stateful",
            "stateful_meta": {
                "chain_id": chain.chain_id,
                "attack": "reverse_order",
                "chain_desc": chain.description,
            },
        })

    # 4. Mutate intermediate step body (if JSON)
    for step in chain.steps[:-1]:
        if step.body:
            try:
                body_data = json.loads(step.body.decode("utf-8", errors="ignore"))
                if isinstance(body_data, dict):
                    # Mutate: set all numeric values to 0
                    mutated = {k: (0 if isinstance(v, (int, float)) else v) for k, v in body_data.items()}
                    mutated_body = json.dumps(mutated).encode("utf-8")

                    # Execute the final step after the mutated intermediate
                    final_step = chain.steps[-1]
                    cases.append({
                        "id": "stateful_mutate",
                        "method": final_step.method,
                        "url": _apply_base(final_step.url),
                        "headers": _apply_auth(final_step.headers),
                        "body": final_step.body,
                        "ep_key": final_step.endpoint_id,
                        "category": "stateful",
                        "stateful_meta": {
                            "chain_id": chain.chain_id,
                            "attack": "mutate_intermediate",
                            "mutated_step": step.path,
                            "chain_desc": chain.description,
                        },
                    })
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    return cases


def analyze_stateful_response(
    case: Dict[str, Any],
    status_code: int,
    body: bytes,
    baseline_status: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Analyze response from a stateful fuzz case."""
    meta = case.get("stateful_meta", {})
    attack = meta.get("attack", "unknown")

    # If the final step succeeded without prerequisites → logic flaw
    if status_code < 400:
        if attack == "skip_step":
            return {
                "severity": "HIGH",
                "type": "Business Logic Bypass (Skip-Step)",
                "evidence": (
                    f"Final step succeeded (HTTP {status_code}) after skipping step {meta.get('skipped_step')}. "
                    f"Chain: {meta.get('chain_desc', 'N/A')}"
                ),
                "recommendation": (
                    "Implement server-side state validation. Each step in a multi-step workflow "
                    "should verify that all prerequisite steps have been completed. Use session-bound "
                    "state tracking or database flags."
                ),
                "cwe": "CWE-841",
                "cvss": 7.5,
            }
        elif attack == "replay":
            return {
                "severity": "MEDIUM",
                "type": "Replay/Idempotency Issue",
                "evidence": (
                    f"Replayed {meta.get('replayed_path', 'N/A')} succeeded (HTTP {status_code}). "
                    f"Chain: {meta.get('chain_desc', 'N/A')}"
                ),
                "recommendation": (
                    "Implement idempotency keys for state-changing operations. Use unique "
                    "transaction IDs and reject duplicate submissions server-side."
                ),
                "cwe": "CWE-841",
                "cvss": 5.5,
            }
        elif attack == "reverse_order":
            return {
                "severity": "HIGH",
                "type": "Business Logic Bypass (Reverse Order)",
                "evidence": (
                    f"Final step executed out of order succeeded (HTTP {status_code}). "
                    f"Chain: {meta.get('chain_desc', 'N/A')}"
                ),
                "recommendation": (
                    "Enforce strict step ordering in multi-step workflows. Validate state "
                    "transitions server-side, not just client-side."
                ),
                "cwe": "CWE-841",
                "cvss": 7.5,
            }
        elif attack == "mutate_intermediate":
            return {
                "severity": "MEDIUM",
                "type": "Business Logic Bypass (State Mutation)",
                "evidence": (
                    f"Final step succeeded (HTTP {status_code}) after mutating intermediate state. "
                    f"Mutated: {meta.get('mutated_step', 'N/A')}"
                ),
                "recommendation": (
                    "Validate intermediate state integrity before processing final steps. "
                    "Use checksums or signed tokens for multi-step data integrity."
                ),
                "cwe": "CWE-841",
                "cvss": 6.0,
            }

    return None
