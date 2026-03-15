"""
AASE Module 7: GraphQL & WebSocket Support
===========================================
Detects GraphQL endpoints, runs introspection, and generates
GraphQL fuzz queries. Detects WebSocket upgrades and generates
HTTP-upgrade probe cases for those endpoints.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse


@dataclass
class GraphQLEndpoint:
    endpoint_id: str
    url: str
    host: str
    headers: Dict[str, str]
    has_introspection: bool = False
    type_names: List[str] = field(default_factory=list)
    query_fields: List[str] = field(default_factory=list)
    mutation_fields: List[str] = field(default_factory=list)


@dataclass
class WSEndpoint:
    endpoint_id: str
    url: str
    host: str
    headers: Dict[str, str]
    protocol: str = "ws"


INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name type { name kind ofType { name kind } } }
    }
  }
}"""

GRAPHQL_PATH_RE = re.compile(r"/graphql\b", re.IGNORECASE)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
NUM_RE = re.compile(r"^\d+$")


def _normalize_path(path: str) -> str:
    parts = [segment for segment in path.split("/") if segment]
    normalized = []
    for segment in parts:
        if NUM_RE.match(segment) or UUID_RE.match(segment):
            normalized.append("{id}")
        else:
            normalized.append(segment)
    return "/" + "/".join(normalized)


def _match_endpoint_id(records_path: str, host: str, method: str, endpoints: dict) -> Optional[str]:
    normalized_path = _normalize_path(records_path or "/")
    for eid, ep in endpoints.items():
        if ep.host == host and ep.method == method and ep.path == normalized_path:
            return eid
    return None


def detect_graphql_endpoints(records: list, endpoints: dict) -> List[GraphQLEndpoint]:
    """Detect GraphQL endpoints from recorded traffic."""
    gql_eps: Dict[str, GraphQLEndpoint] = {}

    for rec in records:
        parsed = urlparse(rec.url)
        is_gql = False

        # Check URL path
        if GRAPHQL_PATH_RE.search(parsed.path or ""):
            is_gql = True

        # Check if POST with query field in body
        if rec.method == "POST" and rec.body:
            try:
                body = json.loads(rec.body.decode("utf-8", errors="ignore"))
                if isinstance(body, dict) and "query" in body:
                    is_gql = True
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        if is_gql:
            key = f"{parsed.netloc}:{parsed.path}"
            if key not in gql_eps:
                ep_id = _match_endpoint_id(parsed.path or "/", parsed.netloc, rec.method, endpoints)
                gql_eps[key] = GraphQLEndpoint(
                    endpoint_id=ep_id or f"gql_{uuid.uuid4().hex[:6]}",
                    url=rec.url,
                    host=parsed.netloc,
                    headers=dict(rec.headers),
                )

    return list(gql_eps.values())


def parse_introspection_result(data: dict) -> Dict[str, Any]:
    """Parse introspection query result to extract schema info."""
    schema_info = {"types": [], "queries": [], "mutations": []}

    schema = data.get("data", {}).get("__schema", {})
    if not schema:
        return schema_info

    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

    for t in schema.get("types", []):
        name = t.get("name", "")
        if name.startswith("__"):
            continue
        kind = t.get("kind", "")
        fields = [f.get("name", "") for f in (t.get("fields") or []) if f.get("name")]

        if name == query_type_name:
            schema_info["queries"] = fields
        elif name == mutation_type_name:
            schema_info["mutations"] = fields
        elif kind == "OBJECT":
            schema_info["types"].append({"name": name, "fields": fields})

    return schema_info


def build_graphql_fuzz_cases(
    gql_ep: GraphQLEndpoint,
    schema_info: Optional[Dict[str, Any]] = None,
    config_auth: Optional[dict] = None,
    target_base_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Generate GraphQL-specific fuzz cases."""
    headers = dict(gql_ep.headers)
    headers["Content-Type"] = "application/json"
    if config_auth:
        if config_auth.get("bearer"):
            headers["Authorization"] = f"Bearer {config_auth['bearer']}"
        for k, v in config_auth.get("headers", {}).items():
            headers[k] = v

    url = gql_ep.url
    if target_base_url:
        parsed = urlparse(url)
        base = urlparse(target_base_url)
        if base.scheme and base.netloc:
            url = urlunparse((base.scheme, base.netloc, parsed.path, "", "", ""))

    cases = []

    # 1. Introspection probe
    cases.append({
        "id": "graphql_introspection",
        "method": "POST",
        "url": url,
        "headers": headers,
        "body": json.dumps({"query": INTROSPECTION_QUERY}).encode(),
        "ep_key": gql_ep.endpoint_id,
        "category": "graphql",
        "graphql_meta": {"attack": "introspection"},
    })

    # 2. Deep nesting DoS
    nested = "{ __typename " + "a { __typename " * 30 + "}" * 30 + "}"
    cases.append({
        "id": "graphql_depth_dos",
        "method": "POST",
        "url": url,
        "headers": headers,
        "body": json.dumps({"query": nested}).encode(),
        "ep_key": gql_ep.endpoint_id,
        "category": "graphql",
        "graphql_meta": {"attack": "depth_dos"},
    })

    # 3. Batch query attack
    batch = [{"query": "{ __typename }"} for _ in range(50)]
    cases.append({
        "id": "graphql_batch",
        "method": "POST",
        "url": url,
        "headers": headers,
        "body": json.dumps(batch).encode(),
        "ep_key": gql_ep.endpoint_id,
        "category": "graphql",
        "graphql_meta": {"attack": "batch"},
    })

    # 4. Field suggestion probe
    cases.append({
        "id": "graphql_field_suggest",
        "method": "POST",
        "url": url,
        "headers": headers,
        "body": json.dumps({"query": "{ nonExistentField12345 }"}).encode(),
        "ep_key": gql_ep.endpoint_id,
        "category": "graphql",
        "graphql_meta": {"attack": "field_suggestion"},
    })

    # 5. Alias-based DoS
    aliases = " ".join(f"a{i}: __typename" for i in range(100))
    cases.append({
        "id": "graphql_alias_dos",
        "method": "POST",
        "url": url,
        "headers": headers,
        "body": json.dumps({"query": "{ " + aliases + " }"}).encode(),
        "ep_key": gql_ep.endpoint_id,
        "category": "graphql",
        "graphql_meta": {"attack": "alias_dos"},
    })

    # 6. If we have schema, fuzz known queries/mutations
    if schema_info:
        for q_field in schema_info.get("queries", [])[:5]:
            cases.append({
                "id": "graphql_query_fuzz",
                "method": "POST",
                "url": url,
                "headers": headers,
                "body": json.dumps({"query": f"{{ {q_field} }}"}).encode(),
                "ep_key": gql_ep.endpoint_id,
                "category": "graphql",
                "graphql_meta": {"attack": "query_fuzz", "field": q_field},
            })
        for m_field in schema_info.get("mutations", [])[:5]:
            cases.append({
                "id": "graphql_mutation_fuzz",
                "method": "POST",
                "url": url,
                "headers": headers,
                "body": json.dumps({
                    "query": f'mutation {{ {m_field}(input: {{}}) {{ __typename }} }}'
                }).encode(),
                "ep_key": gql_ep.endpoint_id,
                "category": "graphql",
                "graphql_meta": {"attack": "mutation_fuzz", "field": m_field},
            })

    return cases


def detect_ws_endpoints(records: list, endpoints: dict) -> List[WSEndpoint]:
    """Detect WebSocket upgrade requests in traffic."""
    ws_eps: Dict[str, WSEndpoint] = {}

    for rec in records:
        upgrade = rec.headers.get("Upgrade", "").lower()
        connection = rec.headers.get("Connection", "").lower()

        if upgrade == "websocket" or "upgrade" in connection:
            parsed = urlparse(rec.url)
            key = f"{parsed.netloc}:{parsed.path}"
            if key not in ws_eps:
                ep_id = _match_endpoint_id(parsed.path or "/", parsed.netloc, rec.method, endpoints)
                ws_url = rec.url.replace("http://", "ws://").replace("https://", "wss://")
                ws_eps[key] = WSEndpoint(
                    endpoint_id=ep_id or f"ws_{uuid.uuid4().hex[:6]}",
                    url=ws_url,
                    host=parsed.netloc,
                    headers=dict(rec.headers),
                    protocol="wss" if "https" in rec.url else "ws",
                )

    return list(ws_eps.values())


def build_ws_fuzz_cases(
    ws_ep: WSEndpoint,
    config_auth: Optional[dict] = None,
    target_base_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Generate WebSocket fuzz cases (tested via HTTP upgrade)."""
    headers = dict(ws_ep.headers)
    if config_auth:
        if config_auth.get("bearer"):
            headers["Authorization"] = f"Bearer {config_auth['bearer']}"

    url = ws_ep.url.replace("ws://", "http://").replace("wss://", "https://")
    if target_base_url:
        parsed = urlparse(url)
        base = urlparse(target_base_url)
        if base.scheme and base.netloc:
            url = urlunparse((base.scheme, base.netloc, parsed.path, "", "", ""))

    cases = []

    # 1. Cross-Site WebSocket Hijacking (no Origin)
    no_origin = dict(headers)
    no_origin.pop("Origin", None)
    no_origin["Upgrade"] = "websocket"
    no_origin["Connection"] = "Upgrade"
    cases.append({
        "id": "ws_cswsh",
        "method": "GET",
        "url": url,
        "headers": no_origin,
        "body": None,
        "ep_key": ws_ep.endpoint_id,
        "category": "websocket",
        "ws_meta": {"attack": "cswsh"},
    })

    # 2. Evil Origin
    evil = dict(headers)
    evil["Origin"] = "https://evil-attacker.com"
    evil["Upgrade"] = "websocket"
    evil["Connection"] = "Upgrade"
    cases.append({
        "id": "ws_evil_origin",
        "method": "GET",
        "url": url,
        "headers": evil,
        "body": None,
        "ep_key": ws_ep.endpoint_id,
        "category": "websocket",
        "ws_meta": {"attack": "evil_origin"},
    })

    # 3. No-auth WebSocket
    noauth = dict(headers)
    noauth.pop("Authorization", None)
    noauth.pop("Cookie", None)
    noauth["Upgrade"] = "websocket"
    noauth["Connection"] = "Upgrade"
    cases.append({
        "id": "ws_noauth",
        "method": "GET",
        "url": url,
        "headers": noauth,
        "body": None,
        "ep_key": ws_ep.endpoint_id,
        "category": "websocket",
        "ws_meta": {"attack": "no_auth"},
    })

    return cases


def analyze_graphql_response(case, status_code, body):
    """Analyze GraphQL fuzz response."""
    meta = case.get("graphql_meta", {})
    attack = meta.get("attack", "unknown")
    text = body.decode("utf-8", errors="ignore")[:4000] if body else ""

    if attack == "introspection" and status_code < 300:
        if "__schema" in text or "queryType" in text:
            return {
                "severity": "MEDIUM",
                "type": "GraphQL Introspection Enabled",
                "evidence": "Full schema introspection is enabled — attackers can map the entire API.",
                "recommendation": "Disable introspection in production environments.",
                "cwe": "CWE-200", "cvss": 5.3,
            }

    if attack == "depth_dos" and status_code < 400:
        return {
            "severity": "LOW",
            "type": "GraphQL Missing Depth Limit",
            "evidence": f"Server accepted deeply nested query (HTTP {status_code}). No depth limit enforced.",
            "recommendation": "Implement query depth limiting (max 10-15 levels).",
            "cwe": "CWE-400", "cvss": 4.0,
        }

    if attack == "batch" and status_code < 300:
        try:
            resp = json.loads(text)
            if isinstance(resp, list) and len(resp) > 10:
                return {
                    "severity": "MEDIUM",
                    "type": "GraphQL Batch Query Abuse",
                    "evidence": f"Server processed {len(resp)} batched queries — potential DoS vector.",
                    "recommendation": "Limit batch query size to prevent resource exhaustion.",
                    "cwe": "CWE-400", "cvss": 5.5,
                }
        except json.JSONDecodeError:
            pass

    if attack == "field_suggestion" and status_code < 500:
        if "did you mean" in text.lower() or "suggestions" in text.lower():
            return {
                "severity": "LOW",
                "type": "GraphQL Field Suggestion Leak",
                "evidence": "Server suggests valid field names on typos — information disclosure.",
                "recommendation": "Disable field suggestions in production.",
                "cwe": "CWE-200", "cvss": 3.5,
            }

    if attack == "alias_dos" and status_code < 400:
        return {
            "severity": "LOW",
            "type": "GraphQL Alias DoS",
            "evidence": f"Server accepted 100 aliases without limiting (HTTP {status_code}).",
            "recommendation": "Implement alias count limits and query complexity analysis.",
            "cwe": "CWE-400", "cvss": 4.0,
        }

    if status_code >= 500:
        return {
            "severity": "MEDIUM",
            "type": f"GraphQL Server Error ({attack})",
            "evidence": f"GraphQL {attack} probe triggered server error (HTTP {status_code}).",
            "recommendation": "Handle malformed GraphQL queries gracefully.",
            "cwe": "CWE-20", "cvss": 5.0,
        }

    return None


def analyze_ws_response(case, status_code, body):
    """Analyze WebSocket fuzz response."""
    meta = case.get("ws_meta", {})
    attack = meta.get("attack", "unknown")

    if attack == "cswsh" and status_code < 400:
        return {
            "severity": "HIGH",
            "type": "Cross-Site WebSocket Hijacking (CSWSH)",
            "evidence": f"WebSocket accepted connection without Origin validation (HTTP {status_code}).",
            "recommendation": "Validate the Origin header on WebSocket upgrade requests.",
            "cwe": "CWE-346", "cvss": 7.1,
        }

    if attack == "evil_origin" and status_code < 400:
        return {
            "severity": "HIGH",
            "type": "WebSocket Origin Bypass",
            "evidence": f"WebSocket accepted evil origin 'evil-attacker.com' (HTTP {status_code}).",
            "recommendation": "Implement strict Origin allowlisting for WebSocket connections.",
            "cwe": "CWE-346", "cvss": 7.1,
        }

    if attack == "no_auth" and status_code < 400:
        return {
            "severity": "HIGH",
            "type": "WebSocket Missing Authentication",
            "evidence": f"WebSocket connected without credentials (HTTP {status_code}).",
            "recommendation": "Require authentication tokens on WebSocket upgrade requests.",
            "cwe": "CWE-306", "cvss": 7.5,
        }

    return None
