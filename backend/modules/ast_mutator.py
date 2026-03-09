"""
AASE Module 4: AST-Based JSON Mutation Fuzzer
==============================================
Performs structural mutations on JSON request bodies to bypass
WAFs and discover edge-case parsing vulnerabilities.
"""
from __future__ import annotations

import copy
import json
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse


# Mutation strategies
MUTATION_TYPES = [
    "type_swap",        # Change value types (str→int, int→str, etc.)
    "deep_nesting",     # Wrap values in deeply nested objects
    "key_duplication",  # Duplicate JSON keys with different values
    "oversized",        # Extremely long strings / large numbers
    "prototype_pollution",  # __proto__, constructor injection
    "null_injection",   # Null bytes and null values
    "extra_fields",     # Add unexpected admin/role/privilege fields
]


def _type_swap_mutations(body: dict) -> List[dict]:
    """Swap value types: string↔int, string→array, string→bool, string→null."""
    mutations = []
    for key, value in body.items():
        if isinstance(value, str):
            # String → Integer
            m = dict(body)
            m[key] = 99999
            mutations.append(m)
            # String → Array
            m = dict(body)
            m[key] = [value, value]
            mutations.append(m)
            # String → Boolean
            m = dict(body)
            m[key] = True
            mutations.append(m)
            # String → Null
            m = dict(body)
            m[key] = None
            mutations.append(m)
        elif isinstance(value, (int, float)):
            # Int → String
            m = dict(body)
            m[key] = str(value)
            mutations.append(m)
            # Int → Negative
            m = dict(body)
            m[key] = -abs(value) - 1
            mutations.append(m)
            # Int → Float overflow
            m = dict(body)
            m[key] = 9999999999999999999
            mutations.append(m)
        elif isinstance(value, bool):
            m = dict(body)
            m[key] = not value
            mutations.append(m)
    return mutations[:8]  # Cap mutations per type


def _deep_nesting_mutations(body: dict) -> List[dict]:
    """Wrap values in deeply nested objects/arrays."""
    mutations = []
    for key, value in list(body.items())[:3]:
        # Deep object nesting (50 levels)
        nested = value
        for _ in range(50):
            nested = {"value": nested}
        m = dict(body)
        m[key] = nested
        mutations.append(m)

        # Deep array nesting
        nested = value
        for _ in range(50):
            nested = [nested]
        m = dict(body)
        m[key] = nested
        mutations.append(m)
    return mutations


def _key_duplication_mutations(body: dict) -> List[dict]:
    """
    Create JSON strings with duplicate keys.
    Since Python dicts can't have duplicate keys, we build raw JSON strings.
    Returns dicts with a special __raw_json__ key containing the raw JSON.
    """
    mutations = []
    for key, value in list(body.items())[:3]:
        # Build JSON with the same key twice, different values
        parts = []
        for k, v in body.items():
            parts.append(f"{json.dumps(k)}: {json.dumps(v)}")
        # Add duplicate with modified value
        if isinstance(value, str):
            dup_val = json.dumps("AASE_DUPLICATE_" + value)
        elif isinstance(value, (int, float)):
            dup_val = json.dumps(value + 1)
        else:
            dup_val = json.dumps("AASE_DUPLICATE")
        parts.append(f"{json.dumps(key)}: {dup_val}")
        raw_json = "{" + ", ".join(parts) + "}"
        mutations.append({"__raw_json__": raw_json})
    return mutations


def _oversized_mutations(body: dict) -> List[dict]:
    """Generate oversized values to test buffer handling."""
    mutations = []
    for key, value in list(body.items())[:3]:
        # Very long string (10KB)
        m = dict(body)
        m[key] = "A" * 10000
        mutations.append(m)

        # Very large number
        m = dict(body)
        m[key] = 10 ** 308
        mutations.append(m)

        # Unicode stress
        m = dict(body)
        m[key] = "\u0000" * 100 + "\uffff" * 100
        mutations.append(m)
    return mutations


def _prototype_pollution_mutations(body: dict) -> List[dict]:
    """Inject prototype pollution payloads."""
    payloads = [
        {"__proto__": {"admin": True, "role": "admin"}},
        {"constructor": {"prototype": {"admin": True}}},
        {"__proto__": {"isAdmin": True}},
        {"constructor": {"prototype": {"isAdmin": True}}},
    ]
    mutations = []
    for payload in payloads:
        m = dict(body)
        m.update(payload)
        mutations.append(m)
    return mutations


def _extra_field_mutations(body: dict) -> List[dict]:
    """Add unexpected privilege/admin fields."""
    extra_fields = [
        {"admin": True},
        {"role": "admin"},
        {"is_admin": True},
        {"privilege": "superadmin"},
        {"user_type": "admin"},
        {"permissions": ["*", "admin", "write", "delete"]},
        {"verified": True, "email_verified": True},
        {"price": 0, "amount": 0, "total": 0},
        {"discount": 100, "coupon": "FREE"},
    ]
    mutations = []
    for extra in extra_fields:
        m = dict(body)
        m.update(extra)
        mutations.append(m)
    return mutations


def generate_mutations(body: dict) -> List[Dict[str, Any]]:
    """
    Generate all mutation variants for a given JSON body.
    Returns list of dicts, each with the mutated body and mutation type.
    """
    all_mutations = []

    for mut in _type_swap_mutations(body):
        all_mutations.append({"body": mut, "type": "type_swap"})

    for mut in _deep_nesting_mutations(body):
        all_mutations.append({"body": mut, "type": "deep_nesting"})

    for mut in _key_duplication_mutations(body):
        all_mutations.append({"body": mut, "type": "key_duplication"})

    for mut in _oversized_mutations(body):
        all_mutations.append({"body": mut, "type": "oversized"})

    for mut in _prototype_pollution_mutations(body):
        all_mutations.append({"body": mut, "type": "prototype_pollution"})

    for mut in _extra_field_mutations(body):
        all_mutations.append({"body": mut, "type": "extra_fields"})

    return all_mutations


def build_mutation_cases(
    rec: Any,
    endpoint: Any,
    config_auth: Optional[dict] = None,
    target_base_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Build fuzz cases using AST-based JSON mutations."""
    if not rec.body:
        return []

    try:
        body_data = json.loads(rec.body.decode("utf-8", errors="ignore"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    if not isinstance(body_data, dict):
        return []

    headers = dict(rec.headers)
    headers["Content-Type"] = "application/json"
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

    mutations = generate_mutations(body_data)
    cases = []

    for mut in mutations:
        mut_body = mut["body"]
        if "__raw_json__" in mut_body:
            body_bytes = mut_body["__raw_json__"].encode("utf-8")
        else:
            body_bytes = json.dumps(mut_body).encode("utf-8")

        cases.append({
            "id": f"mutation_{mut['type']}",
            "method": rec.method,
            "url": url,
            "headers": headers,
            "body": body_bytes,
            "ep_key": endpoint.id,
            "category": "mutation",
            "mutation_meta": {
                "mutation_type": mut["type"],
            },
        })

    return cases


def analyze_mutation_response(
    case: Dict[str, Any],
    status_code: int,
    body: bytes,
    baseline_status: Optional[int] = None,
    baseline_len: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Analyze response from a mutation fuzz case."""
    meta = case.get("mutation_meta", {})
    mutation_type = meta.get("mutation_type", "unknown")
    body_len = len(body)

    # 5xx = server error from mutation
    if status_code >= 500:
        severity = "MEDIUM"
        if mutation_type == "prototype_pollution":
            severity = "HIGH"

        return {
            "severity": severity,
            "type": f"JSON Mutation Crash ({mutation_type})",
            "evidence": (
                f"{mutation_type} mutation triggered server error (HTTP {status_code}). "
                f"The server failed to handle malformed input gracefully."
            ),
            "recommendation": (
                "Implement strict input validation and schema enforcement:\n"
                "1. Use Pydantic or JSON Schema to validate all incoming JSON\n"
                "2. Reject unexpected fields with 400 errors\n"
                "3. Enforce type constraints on all fields\n"
                "4. Set maximum depth limits for nested objects"
            ),
            "cwe": "CWE-20",
            "cvss": 6.5 if severity == "HIGH" else 4.5,
        }

    # Prototype pollution: if 2xx with admin/privilege fields, it may have been mass-assigned
    if mutation_type in ("prototype_pollution", "extra_fields") and status_code < 300:
        text = body.decode("utf-8", errors="ignore")[:2000]
        suspicious_words = ["admin", "role", "privilege", "superadmin", "isAdmin"]
        if any(word in text for word in suspicious_words):
            return {
                "severity": "CRITICAL",
                "type": f"Mass Assignment / {mutation_type.replace('_', ' ').title()}",
                "evidence": (
                    f"Server accepted {mutation_type} payload (HTTP {status_code}) and response "
                    f"contains privilege-related fields. Potential mass assignment vulnerability."
                ),
                "recommendation": (
                    "Implement allowlist-based field filtering:\n"
                    "1. Only accept explicitly allowed fields in request bodies\n"
                    "2. Use Pydantic models with explicit field definitions\n"
                    "3. Never bind raw user input directly to database models\n"
                    "4. Block __proto__ and constructor fields at the framework level"
                ),
                "cwe": "CWE-915",
                "cvss": 9.1,
            }

    # Large response delta from oversized input
    if mutation_type == "oversized" and baseline_len:
        delta = abs(body_len - baseline_len)
        if delta > max(5000, baseline_len * 0.5):
            return {
                "severity": "LOW",
                "type": "Oversized Input Anomaly",
                "evidence": (
                    f"Oversized mutation changed response length by {delta} bytes "
                    f"(baseline: {baseline_len}, mutation: {body_len})"
                ),
                "recommendation": (
                    "Implement input size limits and request body size caps. "
                    "Validate string lengths and numeric ranges server-side."
                ),
                "cwe": "CWE-400",
                "cvss": 3.5,
            }

    return None
