from __future__ import annotations

import asyncio
import base64
import logging
import json
import re
import shlex
import difflib
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlunparse

import httpx
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("aase")

# Power Modules — support both `backend.modules.*` (from project root) and `modules.*` (from backend/)
try:
    from backend.modules.bola_detector import (
        extract_resource_ids, build_bola_cases, analyze_bola_response,
    )
    from backend.modules.stateful_fuzzer import (
        discover_chains, build_stateful_cases, analyze_stateful_response,
    )
    from backend.modules.race_engine import (
        identify_race_targets, build_race_burst, execute_race_burst, analyze_race_results,
    )
    from backend.modules.ast_mutator import (
        build_mutation_cases, analyze_mutation_response,
    )
    from backend.modules.shadow_api import (
        parse_openapi_spec, diff_traffic_vs_spec,
    )
    from backend.modules.patch_generator import generate_patches
    from backend.modules.graphql_ws import (
        detect_graphql_endpoints, build_graphql_fuzz_cases, analyze_graphql_response,
        detect_ws_endpoints, build_ws_fuzz_cases, analyze_ws_response,
        parse_introspection_result,
    )
    from backend.modules.attack_graph import build_attack_graph, build_graph_chains
    from backend.modules.auto_login import execute_auto_login
    from backend.modules.waf_bypass import ShadowRunnerWAF
    from backend.modules.oast_engine import OASTEngine
    from backend.modules.session_manager import AuthSessionManager
except ImportError:
    from modules.bola_detector import (
        extract_resource_ids, build_bola_cases, analyze_bola_response,
    )
    from modules.stateful_fuzzer import (
        discover_chains, build_stateful_cases, analyze_stateful_response,
    )
    from modules.race_engine import (
        identify_race_targets, build_race_burst, execute_race_burst, analyze_race_results,
    )
    from modules.ast_mutator import (
        build_mutation_cases, analyze_mutation_response,
    )
    from modules.shadow_api import (
        parse_openapi_spec, diff_traffic_vs_spec,
    )
    from modules.patch_generator import generate_patches
    from modules.graphql_ws import (
        detect_graphql_endpoints, build_graphql_fuzz_cases, analyze_graphql_response,
        detect_ws_endpoints, build_ws_fuzz_cases, analyze_ws_response,
        parse_introspection_result,
    )
    from modules.attack_graph import build_attack_graph, build_graph_chains
    from modules.auto_login import execute_auto_login
    from modules.waf_bypass import ShadowRunnerWAF
    from modules.oast_engine import OASTEngine
    from modules.session_manager import AuthSessionManager

# -----------------------------
# Models
# -----------------------------

class AuthConfig(BaseModel):
    bearer: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)

class BolaConfig(BaseModel):
    user_a_auth: Optional[AuthConfig] = None
    user_b_auth: Optional[AuthConfig] = None

class LoginConfig(BaseModel):
    login_url: str
    username: str
    password: str

class RunConfig(BaseModel):
    allowlist: List[str] = Field(default_factory=list)
    target_base_url: Optional[str] = None
    rate_limit: float = 2.0
    concurrency: int = 1
    max_retries: int = 2
    retry_backoff_ms: int = 500
    respect_robots: bool = True
    aggressive: bool = False
    auth: Optional[AuthConfig] = None
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    custom_cookies: Dict[str, str] = Field(default_factory=dict)
    dry_run: bool = False
    categories: List[str] = Field(default_factory=list)
    # Power feature flags
    enable_bola: bool = False
    bola_config: Optional[BolaConfig] = None
    enable_stateful: bool = False
    enable_race: bool = False
    burst_size: int = 10
    enable_mutations: bool = False
    enable_graphql: bool = False
    enable_attack_graph: bool = False
    enable_auto_login: bool = False
    login_config: Optional[LoginConfig] = None
    enable_waf_evasion: bool = False
    enable_oast: bool = False
    oast_callback_base_url: Optional[str] = None

class IngestResponse(BaseModel):
    scan_id: str
    fileName: str
    format: str
    transactions: int
    hosts: List[str]
    endpoints: List[Dict[str, Any]]
    capabilities: Optional[Dict[str, Any]] = None

class ReconRequest(BaseModel):
    target_url: str
    max_depth: int = 4
    max_requests: int = 160
    concurrency: int = 8

class RunRequest(BaseModel):
    selected_endpoints: List[str]
    config: RunConfig

class ScanStatus(BaseModel):
    isRunning: bool
    isCancelled: bool = False
    progress: int
    casesRun: int
    totalCases: int
    findings: List[Dict[str, Any]]
    dry_run_log: Optional[List[Dict[str, Any]]] = None
    lastError: Optional[str] = None

# -----------------------------
# Internal state
# -----------------------------

@dataclass
class RequestRecord:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes]
    status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[bytes] = None
    source: str = "unknown"
    discovery_status: Optional[str] = None

@dataclass
class EndpointInfo:
    id: str
    method: str
    path: str
    host: str
    status_codes: List[int]
    auth_required: bool
    params: List[str]
    body_fields: List[str]
    schema_confidence: float
    fuzz_cases: int
    primary_source: str = "unknown"
    all_sources: List[str] = field(default_factory=list)
    discovery_status: Optional[str] = None
    source_statuses: Dict[str, str] = field(default_factory=dict)

@dataclass
class ScanState:
    scan_id: str
    file_name: str
    format: str
    records: List[RequestRecord]
    endpoints: Dict[str, EndpointInfo]
    is_running: bool = False
    total_cases: int = 0
    cases_run: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    report_findings: List[Dict[str, Any]] = field(default_factory=list)
    baselines: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    stored_auth: Optional[AuthConfig] = None
    last_updated: float = field(default_factory=time.time)
    dry_run_log: List[Dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    last_error: Optional[str] = None
    is_cancelled: bool = False
    cancel_requested: bool = False
    cancel_reason: Optional[str] = None
    run_task: Optional[Any] = None
    # Power feature state
    shadow_report: Optional[Dict[str, Any]] = None
    openapi_spec: Optional[bytes] = None
    openapi_fmt: str = "json"
    attack_graph_cache: Optional[Dict[str, Any]] = None

SCANS: Dict[str, ScanState] = {}
ROBOTS_CACHE: Dict[str, List[str]] = {}

# -----------------------------
# App
# -----------------------------

app = FastAPI(title="AASE Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4028",
        "http://127.0.0.1:4028",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://api-spec-enumerator.vercel.app",
        "https://api-spec-enumerator-vxy9.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Helpers
# -----------------------------

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
NUM_RE = re.compile(r"^\d+$")
SOURCE_PRIORITY = {
    "traffic": 5,
    "spec": 4,
    "crawl": 3,
    "response_link": 2,
    "seed_probe": 1,
    "unknown": 0,
}
DISCOVERY_STATUS_PRIORITY = {
    "confirmed": 4,
    "derived": 3,
    "guessed": 2,
    "failed": 1,
}


def _normalize_path(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    normalized = []
    for p in parts:
        if NUM_RE.match(p) or UUID_RE.match(p):
            normalized.append("{id}")
        else:
            normalized.append(p)
    return "/" + "/".join(normalized)


def _lower_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _parse_body(content_type: str, body: Optional[bytes]) -> Tuple[List[str], Optional[Dict[str, Any]]]:
    if not body:
        return [], None
    ct = (content_type or "").lower()
    try:
        if "application/json" in ct:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            if isinstance(data, dict):
                return list(data.keys()), data
            return [], None
        if "application/x-www-form-urlencoded" in ct:
            kv = parse_qs(body.decode("utf-8", errors="ignore"))
            return list(kv.keys()), {k: v[0] if v else "" for k, v in kv.items()}
    except Exception:
        return [], None
    return [], None


def _detect_auth(headers: Dict[str, str]) -> bool:
    """Real heuristic evaluation for active authorization enforcement."""
    h = _lower_headers(headers)
    auth_indicators = ["authorization", "x-api-key", "x-auth-token", "bearer", "token"]
    if any(ind in h for ind in auth_indicators):
        return True
    if "cookie" in h and any(sess in h["cookie"].lower() for sess in ["session", "token", "jwt", "auth"]):
        return True
    return False


def _normalize_source_label(source: Optional[str]) -> str:
    if not source:
        return "unknown"
    return source if source in SOURCE_PRIORITY else "unknown"


def _normalize_discovery_status(status: Optional[str]) -> Optional[str]:
    if not status:
        return None
    return status if status in DISCOVERY_STATUS_PRIORITY else None


def _preferred_discovery_status(current: Optional[str], candidate: Optional[str]) -> Optional[str]:
    candidate = _normalize_discovery_status(candidate)
    current = _normalize_discovery_status(current)
    if candidate is None:
        return current
    if current is None:
        return candidate
    if DISCOVERY_STATUS_PRIORITY[candidate] > DISCOVERY_STATUS_PRIORITY[current]:
        return candidate
    return current


def _sorted_sources(sources: List[str]) -> List[str]:
    if not sources:
        return ["unknown"]
    unique = {_normalize_source_label(source) for source in sources}
    if "unknown" in unique and len(unique) > 1:
        unique.remove("unknown")
    return sorted(unique, key=lambda source: (-SOURCE_PRIORITY.get(source, 0), source))


def _primary_source(sources: List[str]) -> str:
    return _sorted_sources(sources)[0]


def _default_discovery_status(source: str) -> Optional[str]:
    source = _normalize_source_label(source)
    if source == "seed_probe":
        return "guessed"
    if source in {"crawl", "response_link", "spec"}:
        return "derived"
    return None


def _apply_record_source_defaults(
    records: List[RequestRecord],
    source: str,
    discovery_status: Optional[str] = None,
) -> List[RequestRecord]:
    normalized_source = _normalize_source_label(source)
    normalized_status = _normalize_discovery_status(discovery_status)
    for record in records:
        if _normalize_source_label(getattr(record, "source", None)) == "unknown":
            record.source = normalized_source
        if normalized_status and not _normalize_discovery_status(getattr(record, "discovery_status", None)):
            record.discovery_status = normalized_status
    return records

def _schema_confidence(method: str, param_count: int, body_fields: int, sample_count: int) -> float:
    """Calculate schema confidence based on structural perfection and telemetry depth."""
    base = 50.0
    if sample_count > 5:
        base += 15.0
    elif sample_count > 1:
        base += 5.0
        
    if method in ["POST", "PUT", "PATCH"]:
        if body_fields > 0:
            base += 25.0
        else:
            base -= 20.0
            
    if param_count > 0:
        base += 10.0
        
    return float(min(100.0, max(10.0, base)))

def _estimate_fuzz_cases(method: str, param_count: int, body_fields: int) -> int:
    """Calculate the exact permutation matrix of standard payload injections."""
    base_cases = sum(len(v) for v in DEFAULT_PAYLOADS.values()) if 'DEFAULT_PAYLOADS' in globals() else 45
    
    # Base structural tests (method tampering, CORS, broken auth)
    total = 12 
    
    # Injection permutations per parameter/field
    injection_points = param_count + body_fields
    if injection_points > 0:
        total += (injection_points * base_cases)
        
    # Method specific edge cases
    if method in ["POST", "PUT", "PATCH"]:
        total += 15  # Content-Type spoofing, JSON limits, Mass Assignment
        
    return total


def _safe_host(host: str) -> str:
    return host.lower().split(":")[0]


def _host_in_allowlist(host: str, allowlist: List[str]) -> bool:
    h = _safe_host(host)
    for a in allowlist:
        a = _safe_host(a)
        if h == a or h.endswith("." + a):
            return True
    return False


def _is_local_host(host: Optional[str]) -> bool:
    if not host:
        return False
    normalized = _safe_host(host)
    return (
        normalized == "localhost"
        or normalized == "0.0.0.0"
        or normalized == "::1"
        or normalized.startswith("127.")
    )


def _has_auth_config(auth: Optional[AuthConfig]) -> bool:
    if not auth:
        return False
    return bool(auth.bearer or auth.headers or auth.cookies)


def _resolve_target_host(config: RunConfig) -> Optional[str]:
    if config.target_base_url:
        parsed = urlparse(config.target_base_url)
        if parsed.hostname:
            return parsed.hostname
    if config.allowlist:
        return _safe_host(config.allowlist[0])
    return None


def _scan_capabilities(records: List[RequestRecord], endpoints: Dict[str, EndpointInfo]) -> Dict[str, Any]:
    graphql_endpoints = detect_graphql_endpoints(records, endpoints)
    websocket_endpoints = detect_ws_endpoints(records, endpoints)
    return {
        "graphql": bool(graphql_endpoints),
        "graphqlCount": len(graphql_endpoints),
        "websocket": bool(websocket_endpoints),
        "websocketCount": len(websocket_endpoints),
    }


def _validate_scan_request(state: ScanState, selected: set[str], config: RunConfig) -> None:
    if not config.allowlist:
        raise HTTPException(status_code=400, detail="Allowlist is required")

    if config.enable_bola:
        bola_auth = config.bola_config.user_b_auth if config.bola_config else None
        if not _has_auth_config(bola_auth):
            raise HTTPException(
                status_code=400,
                detail="BOLA/IDOR Detection requires a second user token or credential set.",
            )

    if config.enable_auto_login:
        login = config.login_config
        if not login or not login.login_url.strip() or not login.username.strip() or not login.password.strip():
            raise HTTPException(
                status_code=400,
                detail="Auto Login requires login URL, username, and password.",
            )

    if config.enable_oast:
        callback = (config.oast_callback_base_url or "").strip()
        if not callback:
            raise HTTPException(
                status_code=400,
                detail="OAST requires a reachable callback server URL.",
            )
        parsed_callback = urlparse(callback)
        if parsed_callback.scheme not in {"http", "https"} or not parsed_callback.netloc:
            raise HTTPException(
                status_code=400,
                detail="OAST callback URL must be a valid http:// or https:// URL.",
            )
        target_host = _resolve_target_host(config)
        callback_host = parsed_callback.hostname
        if callback_host and _is_local_host(callback_host) and target_host and not _is_local_host(target_host):
            raise HTTPException(
                status_code=400,
                detail="OAST callback URL must be reachable from the remote target host.",
            )

    if config.enable_race:
        if int(config.burst_size or 0) < 2:
            raise HTTPException(
                status_code=400,
                detail="Race Condition testing requires a burst size of at least 2.",
            )
        selected_methods = {
            state.endpoints[eid].method
            for eid in selected
            if eid in state.endpoints
        }
        if not selected_methods.intersection({"POST", "PUT", "PATCH", "DELETE"}):
            raise HTTPException(
                status_code=400,
                detail="Race conditions are meaningful only on selected write endpoints.",
            )


RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}


def _auth_dict(config_auth: Optional[AuthConfig]) -> Optional[Dict[str, Any]]:
    if not config_auth:
        return None
    return {
        "bearer": config_auth.bearer,
        "headers": dict(config_auth.headers),
        "cookies": dict(config_auth.cookies),
    }


def _check_cancelled(state: ScanState) -> None:
    if state.cancel_requested:
        raise asyncio.CancelledError(state.cancel_reason or "Scan cancelled")


def _retry_delay_seconds(resp: Optional[httpx.Response], attempt: int, config: RunConfig) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(float(retry_after), 0.1)
            except ValueError:
                pass
    base_seconds = max(config.retry_backoff_ms, 50) / 1000.0
    return base_seconds * (2 ** attempt)


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    redacted = {}
    for k, v in headers.items():
        if k.lower() in {"authorization", "cookie", "x-api-key", "x-auth-token"}:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def _format_request(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for k, v in _redact_headers(headers).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body.decode("utf-8", errors="ignore")[:2000])
    return "\n".join(lines)


def _format_response(status: int, headers: Dict[str, str], body: Optional[bytes]) -> str:
    lines = [f"HTTP/1.1 {status}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body.decode("utf-8", errors="ignore")[:2000])
    return "\n".join(lines)


def _split_http_message(message: str) -> Tuple[str, Dict[str, str], str]:
    lines = (message or "").splitlines()
    if not lines:
        return "", {}, ""
    start_line = lines[0]
    headers: Dict[str, str] = {}
    body_lines: List[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body and line.strip() == "":
            in_body = True
            continue
        if not in_body and ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
            continue
        if in_body:
            body_lines.append(line)

    return start_line, headers, "\n".join(body_lines)


def _shell_quote(value: str) -> str:
    return shlex.quote(str(value))


def _build_replay_curl(method: str, url: str, request: str) -> str:
    _, headers, body = _split_http_message(request)
    parts = ["curl", "-i", "-s", "-X", method.upper()]
    for key, value in headers.items():
        if key.lower() == "host":
            continue
        parts.extend(["-H", f"{key}: {value}"])
    if body:
        parts.extend(["--data-raw", body])
    parts.append(url)
    return " ".join(_shell_quote(part) for part in parts)


def _summarize_request_artifacts(method: str, url: str, request: str) -> str:
    _, headers, body = _split_http_message(request)
    parts = [
        f"Method: {method.upper()}",
        f"URL: {url}",
        f"Headers: {len(headers)}",
        f"Body: {'present' if body else 'empty'}",
    ]
    if body:
        parts.append(f"Body bytes: {len(body.encode('utf-8', errors='ignore'))}")
    return "\n".join(parts)


def _summarize_response_artifacts(response: str) -> str:
    start_line, headers, body = _split_http_message(response)
    content_type = headers.get("Content-Type") or headers.get("content-type") or "unknown"
    preview = body[:180].replace("\n", " ").strip()
    parts = [
        f"Status: {start_line or 'unknown'}",
        f"Content-Type: {content_type}",
        f"Body bytes: {len(body.encode('utf-8', errors='ignore')) if body else 0}",
    ]
    if preview:
        parts.append(f"Body preview: {preview}")
    return "\n".join(parts)


def _developer_notes_for_finding(ftype: str, evidence: str, recommendation: str) -> str:
    normalized = (ftype or "").lower()
    if "cross-user access control" in normalized or "bola" in normalized or "idor" in normalized:
        return (
            "This looks like an object-level access control failure.\n"
            "Compare the same resource with User A and User B, then confirm the server is enforcing ownership and tenant checks server-side.\n"
            f"Why it mattered here: {evidence}"
        )
    if "workflow" in normalized or "business logic" in normalized or "replay" in normalized:
        return (
            "This finding came from an authenticated workflow test, not a simple payload mutation.\n"
            "Check whether the endpoint is validating prerequisite steps, current state, and idempotency on the server.\n"
            f"Suggested fix direction: {recommendation}"
        )
    if "oast" in normalized or "ssrf" in normalized:
        return (
            "This finding has callback evidence, so treat it as a real outbound interaction.\n"
            "Review every server-side fetch, webhook, document parser, or template sink that can make network requests."
        )
    return (
        "Use the replay command to reproduce the behavior exactly, then compare it with the expected protected response.\n"
        f"Suggested fix direction: {recommendation}"
    )


def _verification_steps_for_finding(ftype: str, request_url: str, endpoint: EndpointInfo) -> List[str]:
    normalized = (ftype or "").lower()
    steps = [
        f"Replay the stored request against {request_url or endpoint.path} and confirm the same response.",
        "Compare the actual response with the expected protected or normal application behavior.",
    ]
    if "cross-user access control" in normalized or "bola" in normalized or "idor" in normalized:
        steps.append("Repeat the same request with two different user sessions and verify ownership is enforced server-side.")
    elif "workflow" in normalized or "business logic" in normalized or "replay" in normalized:
        steps.append("Re-run the same workflow step out of order or twice and confirm the server now blocks it.")
    else:
        steps.append("Apply the server-side fix, then rerun the replay command and confirm the behavior is gone.")
    return steps


def _baseline_delta(state: ScanState, ep_key: str, status: int, body_len: int) -> Tuple[int, int]:
    baseline = state.baselines.get(ep_key)
    if not baseline:
        return 0, 0
    status_delta = 1 if baseline.get("status") != status else 0
    len_delta = abs(body_len - (baseline.get("len") or 0))
    return status_delta, len_delta


def _try_parse_json(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except Exception:
        return None


def _json_diff(a: Any, b: Any) -> Dict[str, Any]:
    if not isinstance(a, dict) or not isinstance(b, dict):
        return {"added": [], "removed": [], "changed": []}
    added = [k for k in b.keys() if k not in a]
    removed = [k for k in a.keys() if k not in b]
    changed = [k for k in a.keys() if k in b and a[k] != b[k]]
    return {"added": added, "removed": removed, "changed": changed}


def _fuzzy_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(a=a, b=b).ratio()


def _extract_params_from_url(url: str) -> List[str]:
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())


def _request_from_burp_item(item: ET.Element) -> Optional[RequestRecord]:
    url_el = item.find("url")
    method_el = item.find("method")
    if url_el is None or method_el is None:
        return None
    url = url_el.text or ""
    method = (method_el.text or "GET").upper()

    headers: Dict[str, str] = {}
    body: Optional[bytes] = None

    req_el = item.find("request")
    if req_el is not None and req_el.text:
        raw = req_el.text
        if req_el.get("base64", "false").lower() == "true":
            try:
                raw = base64.b64decode(raw).decode("utf-8", errors="ignore")
            except Exception:
                raw = ""
        parts = raw.split("\r\n\r\n", 1)
        head = parts[0]
        body = parts[1].encode("utf-8", errors="ignore") if len(parts) > 1 else None
        lines = head.split("\r\n")
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

    status = None
    status_el = item.find("status")
    if status_el is not None and status_el.text and status_el.text.isdigit():
        status = int(status_el.text)

    return RequestRecord(method=method, url=url, headers=headers, body=body, status=status, source="traffic")


def _parse_burp_xml(content: bytes) -> List[RequestRecord]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Burp XML: {exc}")
    records = []
    for item in root.findall(".//item"):
        rec = _request_from_burp_item(item)
        if rec:
            records.append(rec)
    return records


def _parse_har(content: bytes) -> List[RequestRecord]:
    try:
        data = json.loads(content.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid HAR JSON: {exc}")
    entries = data.get("log", {}).get("entries", [])
    records = []
    for e in entries:
        req = e.get("request", {})
        res = e.get("response", {})
        url = req.get("url")
        method = (req.get("method") or "GET").upper()
        headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])}
        body = None
        post = req.get("postData")
        if post:
            text = post.get("text")
            if text is not None:
                body = text.encode("utf-8", errors="ignore")
        status = res.get("status")
        response_headers = {h.get("name", ""): h.get("value", "") for h in res.get("headers", [])}
        response_body = None
        content_obj = res.get("content")
        if content_obj and isinstance(content_obj.get("text"), str):
            response_body = content_obj.get("text").encode("utf-8", errors="ignore")
        if url:
            records.append(RequestRecord(method=method, url=url, headers=headers, body=body, status=status, response_headers=response_headers, response_body=response_body, source="traffic"))
    return records


def _parse_mitmproxy_json(content: bytes) -> List[RequestRecord]:
    try:
        data = json.loads(content.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid mitmproxy JSON: {exc}")

    records = []
    flows = data
    if isinstance(data, dict) and "flows" in data:
        flows = data["flows"]
    if not isinstance(flows, list):
        raise HTTPException(status_code=400, detail="Unsupported mitmproxy JSON format")

    for f in flows:
        req = f.get("request") or {}
        res = f.get("response") or {}
        url = req.get("url") or req.get("pretty_url")
        if not url:
            continue
        method = (req.get("method") or "GET").upper()
        headers = req.get("headers") or {}
        if isinstance(headers, list):
            headers = {h[0]: h[1] for h in headers if isinstance(h, list) and len(h) == 2}
        body = None
        content = req.get("content")
        if isinstance(content, str):
            body = content.encode("utf-8", errors="ignore")
        elif isinstance(content, list):
            try:
                body = bytes(content)
            except Exception:
                body = None
        status = res.get("status_code")
        response_headers = res.get("headers") or {}
        if isinstance(response_headers, list):
            response_headers = {h[0]: h[1] for h in response_headers if isinstance(h, list) and len(h) == 2}
        response_body = None
        rcontent = res.get("content")
        if isinstance(rcontent, str):
            response_body = rcontent.encode("utf-8", errors="ignore")
        records.append(RequestRecord(method=method, url=url, headers=headers, body=body, status=status, response_headers=response_headers, response_body=response_body, source="traffic"))
    return records


def _parse_jsonl(content: bytes) -> List[RequestRecord]:
    """Parse JSONL traffic: one JSON object per line with method/url/headers/body fields."""
    records: List[RequestRecord] = []
    lines = content.decode("utf-8", errors="ignore").splitlines()
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("request", {}).get("url")
        if not url:
            continue
        method = (obj.get("method") or obj.get("request", {}).get("method") or "GET").upper()
        headers = obj.get("headers") or obj.get("request", {}).get("headers") or {}
        if isinstance(headers, list):
            # list of [name, value] pairs or [{name:, value:}]
            h: Dict[str, str] = {}
            for item in headers:
                if isinstance(item, list) and len(item) == 2:
                    h[item[0]] = item[1]
                elif isinstance(item, dict):
                    h[item.get("name", "")] = item.get("value", "")
            headers = h
        body_raw = obj.get("body") or obj.get("request", {}).get("body")
        body: Optional[bytes] = None
        if isinstance(body_raw, str):
            body = body_raw.encode("utf-8", errors="ignore")
        elif isinstance(body_raw, dict):
            body = json.dumps(body_raw).encode("utf-8")
        status = obj.get("status") or (obj.get("response") or {}).get("status")
        resp_headers = (obj.get("response") or {}).get("headers") or {}
        if isinstance(resp_headers, list):
            rh: Dict[str, str] = {}
            for item in resp_headers:
                if isinstance(item, list) and len(item) == 2:
                    rh[item[0]] = item[1]
                elif isinstance(item, dict):
                    rh[item.get("name", "")] = item.get("value", "")
            resp_headers = rh
        records.append(RequestRecord(
            method=method,
            url=url,
            headers=headers,
            body=body,
            status=status,
            response_headers=resp_headers,
            source="traffic",
        ))
    return records


def _parse_raw_http(text: str) -> List[RequestRecord]:
    """Parse one or more raw HTTP/1.1 request blocks separated by blank lines."""
    # Split on double-newline preceded by a new request line
    blocks: List[str] = []
    current: List[str] = []
    for line in text.splitlines():
        if re.match(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+', line) and current:
            blocks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current))

    records: List[RequestRecord] = []
    for block in blocks:
        parts = block.split("\n\n", 1)
        head_section = parts[0]
        body_text = parts[1] if len(parts) > 1 else ""
        head_lines = head_section.splitlines()
        if not head_lines:
            continue
            
        # Strictly validate that the block starts with a recognized HTTP method
        if not re.match(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+', head_lines[0].strip(), re.IGNORECASE):
            continue
            
        request_line = head_lines[0].split()
        if len(request_line) < 2:
            continue
        method = request_line[0].upper()
        path = request_line[1]
        headers: Dict[str, str] = {}
        host = "localhost"
        for hl in head_lines[1:]:
            if ":" in hl:
                k, v = hl.split(":", 1)
                headers[k.strip()] = v.strip()
                if k.strip().lower() == "host":
                    host = v.strip()
        scheme = "https" if "443" in host else "http"
        url = f"{scheme}://{host}{path}"
        body = body_text.encode("utf-8", errors="ignore") if body_text.strip() else None
        records.append(RequestRecord(method=method, url=url, headers=headers, body=body, source="traffic"))
    return records


def _detect_format(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".har"):
        return "har"
    if lower.endswith(".xml"):
        return "burp"
    if lower.endswith(".jsonl") or lower.endswith(".ndjson"):
        return "jsonl"
    if lower.endswith(".json"):
        return "mitmproxy"
    if lower.endswith(".txt"):
        return "raw_http"
    return "unknown"


def _parse_records(file: UploadFile, content: bytes) -> Tuple[str, List[RequestRecord]]:
    fmt = _detect_format(file.filename or "")
    if fmt == "har":
        return fmt, _apply_record_source_defaults(_parse_har(content), "traffic")
    if fmt == "burp":
        return fmt, _apply_record_source_defaults(_parse_burp_xml(content), "traffic")
    if fmt == "jsonl":
        return fmt, _apply_record_source_defaults(_parse_jsonl(content), "traffic")
    if fmt == "raw_http":
        return fmt, _apply_record_source_defaults(_parse_raw_http(content.decode("utf-8", errors="ignore")), "traffic")
    if fmt == "mitmproxy":
        return fmt, _apply_record_source_defaults(_parse_mitmproxy_json(content), "traffic")
    # Fallback: try JSON lines, then mitmproxy JSON, then HAR, else Burp XML
    recs = _parse_jsonl(content)
    if recs:
        return "jsonl", _apply_record_source_defaults(recs, "traffic")
    try:
        return "mitmproxy", _apply_record_source_defaults(_parse_mitmproxy_json(content), "traffic")
    except HTTPException:
        try:
            return "har", _apply_record_source_defaults(_parse_har(content), "traffic")
        except HTTPException:
            return "burp", _apply_record_source_defaults(_parse_burp_xml(content), "traffic")


def _build_endpoints(records: List[RequestRecord]) -> Dict[str, EndpointInfo]:
    buckets: Dict[Tuple[str, str, str], List[RequestRecord]] = {}
    for r in records:
        parsed = urlparse(r.url)
        host = parsed.netloc
        path = _normalize_path(parsed.path or "/")
        key = (host, r.method, path)
        buckets.setdefault(key, []).append(r)

    endpoints: Dict[str, EndpointInfo] = {}
    for (host, method, path), recs in buckets.items():
        params = set()
        body_fields = set()
        status_codes = set()
        auth_required = False
        sources = set()
        source_statuses: Dict[str, str] = {}
        for r in recs:
            params.update(_extract_params_from_url(r.url))
            ct = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_keys, _ = _parse_body(ct, r.body)
            body_fields.update(body_keys)
            if r.status:
                status_codes.add(r.status)
            if _detect_auth(r.headers):
                auth_required = True
            source = _normalize_source_label(getattr(r, "source", None))
            sources.add(source)
            status = _normalize_discovery_status(getattr(r, "discovery_status", None)) or _default_discovery_status(source)
            if status:
                source_statuses[source] = _preferred_discovery_status(source_statuses.get(source), status) or status

        all_sources = _sorted_sources(list(sources))
        primary_source = _primary_source(all_sources)
        discovery_status = source_statuses.get(primary_source) or _default_discovery_status(primary_source)
        if discovery_status:
            source_statuses.setdefault(primary_source, discovery_status)
        endpoint_id = f"ep-{uuid.uuid4().hex[:8]}"
        ep = EndpointInfo(
            id=endpoint_id,
            method=method,
            path=path,
            host=host,
            status_codes=sorted(list(status_codes)) or [200],
            auth_required=auth_required,
            params=sorted(list(params)),
            body_fields=sorted(list(body_fields)),
            schema_confidence=_schema_confidence(method, len(params), len(body_fields), len(recs)),
            fuzz_cases=0,
            primary_source=primary_source,
            all_sources=all_sources,
            discovery_status=discovery_status,
            source_statuses=dict(sorted(source_statuses.items(), key=lambda item: (-SOURCE_PRIORITY.get(item[0], 0), item[0]))),
        )
        if recs:
            # Physically generate the exact permutation matrix to get 100% real numbers
            dummy_config = RunConfig(
                allowlist=[host],
                target_base_url="",
                categories=["sqli", "xss", "ssti", "cors", "auth", "hidden_params", "error_leak"],
                aggressive=True
            )
            exact_cases = _build_cases(recs[0], ep, dummy_config)
            ep.fuzz_cases = len(exact_cases)
            
        endpoints[endpoint_id] = ep
    return endpoints


def _serialize_endpoint(endpoint: EndpointInfo) -> Dict[str, Any]:
    return {
        "id": endpoint.id,
        "method": endpoint.method,
        "path": endpoint.path,
        "host": endpoint.host,
        "statusCodes": endpoint.status_codes,
        "authRequired": endpoint.auth_required,
        "paramCount": len(endpoint.params),
        "bodyFields": endpoint.body_fields,
        "schemaConfidence": endpoint.schema_confidence,
        "fuzzCases": endpoint.fuzz_cases,
        "primary_source": endpoint.primary_source,
        "all_sources": endpoint.all_sources,
        "discovery_status": endpoint.discovery_status,
        "source_statuses": endpoint.source_statuses,
    }


def _build_robots_allowlist(host: str) -> List[str]:
    if host in ROBOTS_CACHE:
        return ROBOTS_CACHE[host]
    disallow: List[str] = []
    try:
        url = f"https://{host}/robots.txt"
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code >= 200 and resp.status_code < 300:
            ua_match = False
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()
                    ua_match = ua == "*"
                elif ua_match and line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallow.append(path)
    except Exception:
        disallow = []
    ROBOTS_CACHE[host] = disallow
    return disallow


def _is_disallowed(path: str, disallow: List[str]) -> bool:
    for d in disallow:
        if path.startswith(d):
            return True
    return False


def _payloads(config: RunConfig) -> Dict[str, List[str]]:
    if config.aggressive:
        return {
            "sqli": [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "1' AND SLEEP(3)--",
                "1 AND SLEEP(3)",
                "' OR sleep(3)='",
                "1; WAITFOR DELAY '0:0:3'--",
                "1'); WAITFOR DELAY '0:0:3'--",
                "pg_sleep(3)--",
                "' OR pg_sleep(3)--",
                "admin' --",
                "admin' #",
                "' OR 'x'='x",
                "' UNION SELECT NULL,NULL,NULL--",
                "1 UNION ALL SELECT 1,2,3,4,5,6,name FROM sysObjects WHERE xtype = 'U' --",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "\" onmouseover=\"alert(1)\" x=\"",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "'><script>alert(1)</script>",
                "<body onload=alert(1)>",
                "<iframe src=\"javascript:alert(1)\">",
                "<details open ontoggle=alert(1)>",
                "<audio src/onerror=alert(1)>",
                "<object data=\"javascript:alert(1)\">",
                "\" autofocus onfocus=alert(1) x=\"",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "*{7*7}",
                "#{7*7}",
                "{{config.items()}}",
                "{{self.__dict__}}",
                "{{ ''.__class__.__mro__[2].__subclasses__() }}",
                "<% out.println(7*7); %>",
                "${T(java.lang.System).getenv()}",
                "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}",
            ],
        }
    # Safe defaults: non-exploit markers
    return {
        "sqli": ["aase_probe", "aase_test"],
        "xss": ["aase_probe", "aase_test"],
        "ssti": ["aase_probe", "aase_test"],
    }


def _body_payloads(config: RunConfig) -> Dict[str, List[str]]:
    return _payloads(config)


def _build_hidden_param_fuzz_cases(rec: RequestRecord, endpoint: EndpointInfo, config: RunConfig) -> List[Dict[str, Any]]:
    parsed = urlparse(rec.url)
    base_url = _apply_target_base(rec.url, config.target_base_url)
    headers = dict(rec.headers)

    if config.auth:
        if config.auth.bearer:
            headers["Authorization"] = f"Bearer {config.auth.bearer}"
        for k, v in config.auth.headers.items():
            headers[k] = v
        if config.auth.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in config.auth.cookies.items()])
            existing = headers.get("Cookie")
            headers["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str

    for k, v in config.custom_headers.items():
        headers[k] = v
    if config.custom_cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in config.custom_cookies.items()])
        existing = headers.get("Cookie")
        headers["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str

    payloads = _payloads(config)
    params_to_try = [
        "id", "user", "username", "email", "q", "query", "search", "filter", "sort",
        "order", "page", "limit", "offset", "callback", "redirect", "next",
    ]

    cases: List[Dict[str, Any]] = []
    for category, plist in payloads.items():
        if category not in (config.categories or []):
            continue
        for p in params_to_try:
            for val in plist:
                q = parse_qs(parsed.query)
                q[p] = [val]
                new_query = "&".join([f"{k}={v[0]}" for k, v in q.items()])
                fuzz_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                fuzz_url = _apply_target_base(fuzz_url, config.target_base_url)
                cases.append({
                    "id": f"hidden_param_{category}",
                    "method": rec.method,
                    "url": fuzz_url,
                    "headers": headers,
                    "body": rec.body,
                    "ep_key": endpoint.id,
                    "category": category,
                })

    return cases


def _build_body_param_fuzz_cases(rec: RequestRecord, endpoint: EndpointInfo, config: RunConfig) -> List[Dict[str, Any]]:
    headers = dict(rec.headers)
    if config.auth:
        if config.auth.bearer:
            headers["Authorization"] = f"Bearer {config.auth.bearer}"
        for k, v in config.auth.headers.items():
            headers[k] = v
        if config.auth.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in config.auth.cookies.items()])
            existing = headers.get("Cookie")
            headers["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str

    for k, v in config.custom_headers.items():
        headers[k] = v
    if config.custom_cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in config.custom_cookies.items()])
        existing = headers.get("Cookie")
        headers["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str

    ct = headers.get("Content-Type") or headers.get("content-type") or ""
    body_keys, parsed_body = _parse_body(ct, rec.body)
    if parsed_body is None or not isinstance(parsed_body, dict):
        return []

    payloads = _body_payloads(config)
    params_to_try = body_keys or ["id", "user", "email", "q", "search"]

    cases: List[Dict[str, Any]] = []
    for category, plist in payloads.items():
        if category not in (config.categories or []):
            continue
        for p in params_to_try:
            for val in plist:
                new_body = dict(parsed_body)
                new_body[p] = val
                body_bytes = json.dumps(new_body).encode("utf-8", errors="ignore")
                new_headers = dict(headers)
                new_headers["Content-Type"] = "application/json"
                cases.append({
                    "id": f"body_param_{category}",
                    "method": rec.method,
                    "url": _apply_target_base(rec.url, config.target_base_url),
                    "headers": new_headers,
                    "body": body_bytes,
                    "ep_key": endpoint.id,
                    "category": category,
                })

    return cases

# -----------------------------
# API
# -----------------------------

@app.post("/api/ingest", response_model=IngestResponse)
async def ingest(
    file: UploadFile = File(...),
    auth_config: Optional[str] = Form(None),
):
    content = await file.read()
    fmt, records = _parse_records(file, content)
    if not records:
        raise HTTPException(status_code=400, detail="No requests found in capture")

    endpoints = _build_endpoints(records)
    hosts = sorted({urlparse(r.url).netloc for r in records if r.url})

    scan_id = uuid.uuid4().hex
    state = ScanState(
        scan_id=scan_id,
        file_name=file.filename or "capture",
        format=fmt,
        records=records,
        endpoints=endpoints,
    )

    # Attach auth config (optional) to state for later use
    if auth_config:
        try:
            auth_data = json.loads(auth_config)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="auth_config must be valid JSON")
        try:
            state.stored_auth = AuthConfig(**auth_data)
        except Exception:
            raise HTTPException(status_code=400, detail="auth_config does not match expected schema")

    SCANS[scan_id] = state

    endpoint_list = [_serialize_endpoint(endpoint) for endpoint in endpoints.values()]
    capabilities = _scan_capabilities(records, endpoints)

    return IngestResponse(
        scan_id=scan_id,
        fileName=state.file_name,
        format=fmt,
        transactions=len(records),
        hosts=hosts,
        endpoints=endpoint_list,
        capabilities=capabilities,
    )

@app.post("/api/scan/{scan_id}/run")
async def run_scan(scan_id: str, body: RunRequest, background: BackgroundTasks):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if state.is_running:
        raise HTTPException(status_code=400, detail="Scan already running")

    selected = set(body.selected_endpoints)
    if not selected:
        raise HTTPException(status_code=400, detail="No endpoints selected")

    config = body.config
    if config.auth is None and state.stored_auth is not None:
        config.auth = state.stored_auth
    _validate_scan_request(state, selected, config)

    state.is_running = True
    state.total_cases = 0
    state.cases_run = 0
    state.findings = []
    state.report_findings = []
    state.baselines = {}
    state.dry_run_log = []
    state.last_error = None
    state.is_cancelled = False
    state.cancel_requested = False
    state.cancel_reason = None

    async def _runner():
        try:
            await _execute_scan(state, selected, config)
        except asyncio.CancelledError:
            state.is_cancelled = True
            state.last_error = state.cancel_reason or "Scan cancelled by user"
        except Exception as exc:
            state.last_error = str(exc)
            logger.exception("Scan runner crashed for %s", scan_id)
        finally:
            state.is_running = False
            state.run_task = None
            state.last_updated = time.time()

    state.run_task = asyncio.create_task(_runner())
    return {"status": "started"}


@app.post("/api/scan/{scan_id}/preview")
async def preview_scan(scan_id: str, body: RunRequest):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    selected = set(body.selected_endpoints)
    if not selected:
        raise HTTPException(status_code=400, detail="No endpoints selected")

    config = body.config
    if config.auth is None and state.stored_auth is not None:
        config.auth = state.stored_auth
    _validate_scan_request(state, selected, config)

    _, baseline_cases, standard_cases, race_bursts, endpoint_case_counts = _prepare_scan_plan(
        state, selected, config
    )

    total_cases = len(baseline_cases) + len(standard_cases) + sum(len(burst) for _, burst in race_bursts)
    return {
        "totalCases": total_cases,
        "endpointCases": endpoint_case_counts,
    }


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not state.is_running:
        return {"status": "idle", "isCancelled": state.is_cancelled}

    state.cancel_requested = True
    state.cancel_reason = "Scan cancelled by user"
    if state.run_task and not state.run_task.done():
        state.run_task.cancel()
    return {"status": "cancelling", "isCancelled": True}

@app.post("/api/recon", response_model=IngestResponse)
async def auto_recon(req: ReconRequest):
    """
    Auto-Recon Phase 4: Actively spiders the target to generate a scan state without a HAR file.
    """
    try:
        from backend.modules.auto_recon import AutoReconEngine
    except ImportError:
        from modules.auto_recon import AutoReconEngine
    
    target_url = req.target_url
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
        
    engine = AutoReconEngine(
        target_url,
        max_depth=req.max_depth,
        max_requests=req.max_requests,
        concurrency=req.concurrency,
    )
    records = await engine.execute_recon()
    
    if not records:
        raise HTTPException(status_code=400, detail="Auto-Recon failed to discover any valid endpoints.")

    # Convert generic dict to actual EndpointInfo models
    endpoints_raw = _build_endpoints(records)
    
    scan_id = str(uuid.uuid4())
    state = ScanState(
        scan_id=scan_id,
        file_name=f"AutoRecon: {urlparse(target_url).netloc}",
        format="auto_recon",
        records=records,
        endpoints=endpoints_raw,
    )
    SCANS[scan_id] = state

    hosts = {e.host for e in endpoints_raw.values()}
    
    endpoint_list = [_serialize_endpoint(endpoint) for endpoint in endpoints_raw.values()]
    capabilities = _scan_capabilities(records, endpoints_raw)

    return IngestResponse(
        scan_id=scan_id,
        fileName=state.file_name,
        format="auto_recon",
        transactions=len(state.records),
        hosts=list(hosts),
        endpoints=endpoint_list,
        capabilities=capabilities,
    )

@app.get("/api/scan/{scan_id}/status", response_model=ScanStatus)
async def scan_status(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    progress = int((state.cases_run / state.total_cases) * 100) if state.total_cases else 0
    return ScanStatus(
        isRunning=state.is_running,
        isCancelled=state.is_cancelled,
        progress=progress,
        casesRun=state.cases_run,
        totalCases=state.total_cases,
        findings=state.findings,
        dry_run_log=state.dry_run_log,
        lastError=state.last_error,
    )

@app.get("/api/scan/{scan_id}/report")
async def scan_report(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"findings": state.report_findings}


class PasteRequest(BaseModel):
    text: str
    auth_config: Optional[Dict[str, Any]] = None


@app.post("/api/ingest/paste", response_model=IngestResponse)
async def ingest_paste(body: PasteRequest):
    """Accept raw HTTP, JSON arrays, JSONL traces, or pasted HAR/mitmproxy JSON and ingest as a scan."""
    records = []
    fmt = "raw_http"
    text = body.text.strip()
    
    if text.startswith("[") and text.endswith("]"):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                for obj in arr:
                    if not isinstance(obj, dict):
                        continue
                    url = obj.get("url") or obj.get("request", {}).get("url")
                    if not url:
                        continue
                    method = (obj.get("method") or obj.get("request", {}).get("method") or "GET").upper()
                    
                    headers = obj.get("headers") or obj.get("request", {}).get("headers") or {}
                    if isinstance(headers, list):
                        h: Dict[str, str] = {}
                        for item in headers:
                            if isinstance(item, list) and len(item) == 2:
                                h[item[0]] = item[1]
                            elif isinstance(item, dict):
                                h[item.get("name", "")] = item.get("value", "")
                        headers = h
                        
                    body_raw = obj.get("body") or obj.get("request", {}).get("body")
                    req_body: Optional[bytes] = None
                    if isinstance(body_raw, str):
                        req_body = body_raw.encode("utf-8", errors="ignore")
                    elif isinstance(body_raw, dict):
                        req_body = json.dumps(body_raw).encode("utf-8")
                        
                    status = obj.get("status") or (obj.get("response") or {}).get("status")
                    
                    resp_headers = (obj.get("response") or {}).get("headers") or {}
                    if isinstance(resp_headers, list):
                        rh: Dict[str, str] = {}
                        for item in resp_headers:
                            if isinstance(item, list) and len(item) == 2:
                                rh[item[0]] = item[1]
                            elif isinstance(item, dict):
                                rh[item.get("name", "")] = item.get("value", "")
                        resp_headers = rh
                        
                    records.append(RequestRecord(
                        method=method, url=url, headers=headers, body=req_body,
                        status=status, response_headers=resp_headers, source="traffic"
                    ))
                    fmt = "json_array"
        except Exception:
            pass

    if not records and text:
        try:
            records = _apply_record_source_defaults(_parse_jsonl(body.text.encode("utf-8", errors="ignore")), "traffic")
            if records:
                fmt = "jsonl"
        except HTTPException:
            records = []

    if not records and text.startswith("{"):
        content = body.text.encode("utf-8", errors="ignore")
        try:
            records = _apply_record_source_defaults(_parse_har(content), "traffic")
            if records:
                fmt = "har"
        except HTTPException:
            try:
                records = _apply_record_source_defaults(_parse_mitmproxy_json(content), "traffic")
                if records:
                    fmt = "mitmproxy"
            except HTTPException:
                records = []

    if not records:
        records = _apply_record_source_defaults(_parse_raw_http(body.text), "traffic")
    if not records:
        raise HTTPException(status_code=400, detail="No valid HTTP requests found in pasted text")

    endpoints = _build_endpoints(records)
    hosts = sorted({urlparse(r.url).netloc for r in records if r.url})

    scan_id = uuid.uuid4().hex
    state = ScanState(
        scan_id=scan_id,
        file_name="pasted_traffic.txt",
        format=fmt,
        records=records,
        endpoints=endpoints,
    )

    if body.auth_config:
        try:
            state.stored_auth = AuthConfig(**body.auth_config)
        except Exception:
            raise HTTPException(status_code=400, detail="auth_config does not match expected schema")

    SCANS[scan_id] = state

    endpoint_list = [_serialize_endpoint(endpoint) for endpoint in endpoints.values()]
    capabilities = _scan_capabilities(records, endpoints)
    return IngestResponse(
        scan_id=scan_id, fileName="pasted_traffic.txt", format=fmt,
        transactions=len(records), hosts=hosts, endpoints=endpoint_list, capabilities=capabilities,
    )


@app.get("/api/scan/{scan_id}/events")
async def scan_events(scan_id: str, request: Request):
    """SSE endpoint streaming live scan progress events."""
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator() -> AsyncGenerator[str, None]:
        last_signature = None
        while True:
            if await request.is_disconnected():
                break
            progress = int((state.cases_run / state.total_cases) * 100) if state.total_cases else 0
            signature = (progress, len(state.findings), state.last_error, state.is_cancelled, state.is_running)
            if signature != last_signature:
                payload = json.dumps({
                    "isRunning": state.is_running,
                    "isCancelled": state.is_cancelled,
                    "progress": progress,
                    "casesRun": state.cases_run,
                    "totalCases": state.total_cases,
                    "findings": state.findings,
                    "lastError": state.last_error,
                })
                yield f"data: {payload}\n\n"
                last_signature = signature
            if not state.is_running and (
                state.is_cancelled or (state.cases_run >= state.total_cases and state.total_cases > 0)
            ):
                yield "data: {\"done\": true}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/scan/{scan_id}/export.json")
async def export_json(scan_id: str):
    """Download full findings report as JSON."""
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    payload = {
        "meta": {
            "scan_id": scan_id,
            "file_name": state.file_name,
            "format": state.format,
            "started_at": state.started_at,
            "total_cases": state.total_cases,
            "endpoints_count": len(state.endpoints),
        },
        "findings": state.report_findings,
    }
    content = json.dumps(payload, indent=2)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=aase_report_{scan_id}.json"},
    )


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


@app.get("/api/scan/{scan_id}/export.html", response_class=HTMLResponse)
async def export_html(scan_id: str):
    """Download an executive-grade HTML vulnerability report."""
    try:
        from backend.modules.report_generator import generate_executive_report
    except ImportError:
        from modules.report_generator import generate_executive_report
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    html = generate_executive_report(scan_id, state)

    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f"attachment; filename=aase_executive_report_{scan_id}.html"},
    )


# -----------------------------
# Power Feature Routes
# -----------------------------

@app.post("/api/scan/{scan_id}/openapi")
async def upload_openapi(scan_id: str, file: UploadFile = File(...)):
    """Upload an OpenAPI/Swagger spec for Shadow API analysis."""
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    content = await file.read()
    fname = file.filename or "spec"
    fmt = "yaml" if fname.endswith((".yaml", ".yml")) else "json"

    try:
        spec_endpoints = parse_openapi_spec(content, fmt)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    report = diff_traffic_vs_spec(state.endpoints, spec_endpoints)

    state.shadow_report = {
        "undocumented": report.undocumented,
        "unimplemented": report.unimplemented,
        "param_mismatches": report.param_mismatches,
        "total_spec_endpoints": report.total_spec_endpoints,
        "total_traffic_endpoints": report.total_traffic_endpoints,
        "coverage_percent": report.coverage_percent,
    }
    state.openapi_spec = content
    state.openapi_fmt = fmt

    return state.shadow_report


@app.get("/api/scan/{scan_id}/patches")
async def get_patches(scan_id: str):
    """Generate auto-remediation patches for all findings."""
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    patches = generate_patches(state.report_findings)
    return {"patches": patches, "total": len(patches)}


@app.get("/api/scan/{scan_id}/shadow-report")
async def get_shadow_report(scan_id: str):
    """Get the Shadow API diff report."""
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not state.shadow_report:
        return {"message": "No OpenAPI spec uploaded yet", "undocumented": [], "unimplemented": [], "param_mismatches": []}
    return state.shadow_report


@app.get("/api/scan/{scan_id}/attack-graph")
async def get_attack_graph(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if state.attack_graph_cache is None:
        graph = build_attack_graph(state.records, state.endpoints)
        state.attack_graph_cache = {
            "nodes": list(graph.nodes.values()),
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relation": edge.relation,
                    "evidence": edge.evidence,
                    "weight": edge.weight,
                }
                for edge in graph.edges
            ],
            "paths": graph.paths,
        }
    return state.attack_graph_cache


@app.api_route("/api/oast/{token}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def oast_callback(token: str, request: Request):
    body = await request.body()
    event = OASTEngine.record_callback(
        token,
        request.method,
        dict(request.headers),
        body,
        request.client.host if request.client else "",
    )
    if not event:
        raise HTTPException(status_code=404, detail="Unknown OAST token")

    scan_id = event.get("scan_id")
    state = SCANS.get(scan_id or "")
    if state and not event.get("finding_emitted"):
        endpoint = state.endpoints.get(event.get("endpoint_id"))
        if endpoint is None:
            parsed = urlparse(event.get("request_url") or state.file_name)
            endpoint = EndpointInfo(
                id=f"oast-{token[:6]}",
                method="POST",
                path=event.get("endpoint_path") or parsed.path or "/",
                host=parsed.netloc or "",
                status_codes=[200],
                auth_required=False,
                params=[],
                body_fields=[],
                schema_confidence=50.0,
                fuzz_cases=0,
                primary_source="unknown",
                all_sources=["unknown"],
            )
        callback_info = event["callbacks"][-1] if event.get("callbacks") else {}
        vector_type = str(event.get("vector_type") or "blind_callback")
        evidence = (
            f"OAST callback received for {vector_type} from {callback_info.get('client_ip', 'unknown')} "
            f"using {callback_info.get('method', 'GET')}"
        )
        _add_finding(
            state,
            "HIGH",
            "Confirmed Blind Callback/OAST",
            endpoint,
            evidence,
            f"OAST token: {token}\nCallback URL: {event.get('callback_url', '')}",
            json.dumps(callback_info, indent=2),
            "Treat this as a confirmed blind interaction. Investigate SSRF, blind XXE, template injection, or JNDI sinks that consumed the callback payload.",
            "CWE-918",
            request_url=event.get("request_url"),
            cvss=8.6,
        )
        event["finding_emitted"] = True

    return {"ok": True, "token": token}


@app.get("/api/scan/{scan_id}/oast")
async def get_oast_events(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"events": OASTEngine.get_scan_events(scan_id)}


# -----------------------------
# Scan engine
# -----------------------------

def _prepare_scan_plan(
    state: ScanState,
    selected: set[str],
    config: RunConfig,
) -> Tuple[
    Dict[str, EndpointInfo],
    List[Tuple[EndpointInfo, Dict[str, Any]]],
    List[Tuple[EndpointInfo, Dict[str, Any]]],
    List[Tuple[EndpointInfo, List[Dict[str, Any]]]],
    Dict[str, int],
]:
    endpoint_map = {eid: state.endpoints[eid] for eid in selected if eid in state.endpoints}
    if not endpoint_map:
        return {}, [], [], [], {}

    auth_dict = _auth_dict(config.auth)

    baseline_cases: List[Tuple[EndpointInfo, Dict[str, Any]]] = []
    standard_cases: List[Tuple[EndpointInfo, Dict[str, Any]]] = []
    race_bursts: List[Tuple[EndpointInfo, List[Dict[str, Any]]]] = []
    endpoint_case_counts: Dict[str, int] = {eid: 0 for eid in endpoint_map}

    def _add_case(endpoint: EndpointInfo, case: Dict[str, Any]) -> None:
        endpoint_case_counts[endpoint.id] = endpoint_case_counts.get(endpoint.id, 0) + 1
        if case.get("id") == "baseline":
            baseline_cases.append((endpoint, case))
        else:
            standard_cases.append((endpoint, case))

    for endpoint in endpoint_map.values():
        rec = _pick_record(state.records, endpoint)
        if not rec:
            continue

        for case in _build_cases(rec, endpoint, config, scan_id=state.scan_id):
            _add_case(endpoint, case)

        if config.enable_mutations and rec.body:
            for case in build_mutation_cases(rec, endpoint, auth_dict, config.target_base_url):
                _add_case(endpoint, case)

    if config.enable_bola and config.bola_config:
        ua = config.bola_config.user_a_auth
        ub = config.bola_config.user_b_auth
        if ua and ub:
            ua_dict = {"bearer": ua.bearer, "headers": dict(ua.headers), "cookies": dict(ua.cookies)}
            ub_dict = {"bearer": ub.bearer, "headers": dict(ub.headers), "cookies": dict(ub.cookies)}
            for case in build_bola_cases(state.records, state.endpoints, ua_dict, ub_dict, config.target_base_url):
                endpoint = state.endpoints.get(case.get("ep_key"))
                if endpoint and endpoint.id in endpoint_map:
                    _add_case(endpoint, case)

    if config.enable_stateful or config.enable_attack_graph:
        chains = discover_chains(state.records, state.endpoints)
        if config.enable_attack_graph:
            chains.extend(build_graph_chains(state.records, state.endpoints))
        seen_chain_keys = set()
        for chain in chains:
            chain_key = tuple((step.method, step.path, step.endpoint_id) for step in chain.steps)
            if chain_key in seen_chain_keys:
                continue
            seen_chain_keys.add(chain_key)
            for case in build_stateful_cases(chain, auth_dict, config.target_base_url):
                endpoint = state.endpoints.get(case.get("ep_key"))
                if endpoint and endpoint.id in endpoint_map:
                    _add_case(endpoint, case)

    if config.enable_race:
        for eid in identify_race_targets(state.endpoints):
            if eid not in endpoint_map:
                continue
            endpoint = endpoint_map[eid]
            rec = _pick_record(state.records, endpoint)
            if not rec:
                continue
            burst = build_race_burst(rec, endpoint, auth_dict, config.target_base_url, config.burst_size)
            if burst:
                endpoint_case_counts[endpoint.id] = endpoint_case_counts.get(endpoint.id, 0) + len(burst)
                race_bursts.append((endpoint, burst))

    if config.enable_graphql:
        for gql_ep in detect_graphql_endpoints(state.records, state.endpoints):
            endpoint = state.endpoints.get(gql_ep.endpoint_id)
            if not endpoint or endpoint.id not in endpoint_map:
                continue
            for case in build_graphql_fuzz_cases(gql_ep, None, auth_dict, config.target_base_url):
                _add_case(endpoint, case)

        for ws_ep in detect_ws_endpoints(state.records, state.endpoints):
            endpoint = state.endpoints.get(ws_ep.endpoint_id)
            if not endpoint or endpoint.id not in endpoint_map:
                continue
            for case in build_ws_fuzz_cases(ws_ep, auth_dict, config.target_base_url):
                _add_case(endpoint, case)

    return endpoint_map, baseline_cases, standard_cases, race_bursts, endpoint_case_counts


async def _request_with_retries(
    state: ScanState,
    client: httpx.AsyncClient,
    case: Dict[str, Any],
    headers: Dict[str, str],
    config: RunConfig,
    session_manager: Optional[AuthSessionManager],
) -> httpx.Response:
    attempts = max(0, config.max_retries)
    last_exception: Optional[Exception] = None

    for attempt in range(attempts + 1):
        _check_cancelled(state)
        try:
            effective_headers = session_manager.apply(headers) if session_manager else headers
            response = await client.request(
                case["method"],
                case["url"],
                headers=effective_headers,
                content=case.get("body"),
            )
            if session_manager:
                session_manager.capture_response(response)

            if response.status_code in (401, 403) and session_manager and attempt < attempts:
                refreshed = await session_manager.maybe_refresh(client, response)
                if refreshed:
                    await asyncio.sleep(max(config.retry_backoff_ms, 50) / 1000.0)
                    continue

            if response.status_code in RETRYABLE_STATUS_CODES and attempt < attempts:
                await asyncio.sleep(_retry_delay_seconds(response, attempt, config))
                continue

            return response
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_exception = exc
            if attempt >= attempts:
                raise
            await asyncio.sleep(_retry_delay_seconds(None, attempt, config))

    raise last_exception or RuntimeError(f"Request failed for {case.get('method')} {case.get('url')}")

async def _execute_scan(state: ScanState, selected: set[str], config: RunConfig) -> None:
    endpoint_map, baseline_cases, standard_cases, race_bursts, _ = _prepare_scan_plan(state, selected, config)
    if not endpoint_map:
        return

    state.total_cases = len(baseline_cases) + len(standard_cases) + sum(len(burst) for _, burst in race_bursts)

    limiter = asyncio.Semaphore(max(1, config.concurrency))
    session_manager = AuthSessionManager(
        base_auth=_auth_dict(config.auth),
        login_config=config.login_config.model_dump() if config.enable_auto_login and config.login_config else None,
    )

    waf_engine = ShadowRunnerWAF() if config.enable_waf_evasion else None

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        if config.enable_auto_login and config.login_config:
            logger.info("Executing pre-scan authenticated session bootstrap")
            session_ready = await session_manager.bootstrap(client)
            if not session_ready:
                harvested_auth = await execute_auto_login(
                    config.login_config.login_url,
                    config.login_config.username,
                    config.login_config.password,
                )
                if harvested_auth:
                    session_manager.seed(harvested_auth)
                    session_ready = True
            if session_ready and not config.auth:
                config.auth = AuthConfig()
                config.auth.bearer = session_manager.state.bearer
                config.auth.headers.update(session_manager.state.headers)
                config.auth.cookies.update(session_manager.state.cookies)

        async def _worker(endpoint, case):
            async with limiter:
                _check_cancelled(state)
                try:
                    if config.dry_run:
                        await asyncio.sleep(config.concurrency / max(0.1, config.rate_limit))
                        state.dry_run_log.append({
                            "id": case.get("id", "unknown"),
                            "method": case.get("method"),
                            "url": case.get("url"),
                            "ep_key": case.get("ep_key"),
                            "skipped": True,
                        })
                        state.cases_run += 1
                        return

                    parsed = urlparse(case["url"])
                    if config.respect_robots:
                        disallow = _build_robots_allowlist(parsed.netloc)
                        if _is_disallowed(parsed.path or "/", disallow):
                            state.cases_run += 1
                            return

                    if not _host_in_allowlist(parsed.netloc, config.allowlist):
                        state.cases_run += 1
                        return

                    req_headers = dict(case["headers"])
                    if waf_engine:
                        req_headers = waf_engine.get_evasion_headers(req_headers)

                    resp = await _request_with_retries(
                        state,
                        client,
                        case,
                        req_headers,
                        config,
                        session_manager if session_manager.has_auth() or config.enable_auto_login else None,
                    )

                    if waf_engine:
                        waf_engine.analyze_response(resp.status_code)

                    await _analyze_case(state, endpoint, case, resp)
                    state.cases_run += 1

                    if waf_engine and waf_engine.is_evasion_active:
                        await waf_engine.apply_jitter(config.rate_limit)
                    else:
                        await asyncio.sleep(config.concurrency / max(0.1, config.rate_limit))
                except asyncio.CancelledError:
                    raise
                except Exception as _exc:
                    state.last_error = f"{case.get('method')} {case.get('url')}: {_exc}"
                    logger.exception("Worker error on %s %s", case.get("method"), case.get("url"))
                    state.cases_run += 1

        async def _run_case_batch(case_batch: List[Tuple[EndpointInfo, Dict[str, Any]]]) -> None:
            _check_cancelled(state)
            tasks = [_worker(ep, case) for ep, case in case_batch]
            if tasks:
                await asyncio.gather(*tasks)

        async def _run_race_burst(endpoint: EndpointInfo, burst: List[Dict[str, Any]]) -> None:
            async with limiter:
                _check_cancelled(state)
                try:
                    if config.dry_run:
                        for case in burst:
                            state.dry_run_log.append({
                                "id": case.get("id", "unknown"),
                                "method": case.get("method"),
                                "url": case.get("url"),
                                "ep_key": case.get("ep_key"),
                                "skipped": True,
                            })
                            state.cases_run += 1
                        return

                    parsed = urlparse(burst[0]["url"])
                    if config.respect_robots:
                        disallow = _build_robots_allowlist(parsed.netloc)
                        if _is_disallowed(parsed.path or "/", disallow):
                            state.cases_run += len(burst)
                            return

                    if not _host_in_allowlist(parsed.netloc, config.allowlist):
                        state.cases_run += len(burst)
                        return

                    prepared_burst = []
                    for case in burst:
                        req_headers = dict(case["headers"])
                        if session_manager.has_auth():
                            req_headers = session_manager.apply(req_headers)
                        if waf_engine:
                            req_headers = waf_engine.get_evasion_headers(req_headers)
                        prepared_burst.append({**case, "headers": req_headers})

                    results = await execute_race_burst(client, prepared_burst)
                    for _, resp in results:
                        if resp is not None and waf_engine:
                            waf_engine.analyze_response(resp.status_code)
                    state.cases_run += len(results)

                    finding = analyze_race_results(results)
                    if finding:
                        sample_case, sample_resp = next(
                            ((case, resp) for case, resp in results if resp is not None),
                            (prepared_burst[0], None),
                        )
                        response_dump = (
                            _format_response(sample_resp.status_code, dict(sample_resp.headers), sample_resp.content)
                            if sample_resp is not None
                            else "No HTTP response captured"
                        )
                        _add_finding(
                            state,
                            finding["severity"],
                            finding["type"],
                            endpoint,
                            finding["evidence"],
                            _format_request(sample_case["method"], sample_case["url"], sample_case["headers"], sample_case.get("body")),
                            response_dump,
                            finding["recommendation"],
                            finding["cwe"],
                            request_url=sample_case["url"],
                            cvss=finding.get("cvss"),
                        )

                    if waf_engine and waf_engine.is_evasion_active:
                        await waf_engine.apply_jitter(config.rate_limit)
                    else:
                        await asyncio.sleep(config.concurrency / max(0.1, config.rate_limit))
                except asyncio.CancelledError:
                    raise
                except Exception as _exc:
                    state.last_error = f"race burst {endpoint.method} {endpoint.path}: {_exc}"
                    logger.exception("Race burst error on %s %s", endpoint.method, endpoint.path)
                    state.cases_run += len(burst)

        await _run_case_batch(baseline_cases)
        _check_cancelled(state)
        await _run_case_batch(standard_cases)
        for endpoint, burst in race_bursts:
            _check_cancelled(state)
            await _run_race_burst(endpoint, burst)


def _pick_record(records: List[RequestRecord], endpoint: EndpointInfo) -> Optional[RequestRecord]:
    for r in records:
        parsed = urlparse(r.url)
        if parsed.netloc == endpoint.host and r.method == endpoint.method:
            if _normalize_path(parsed.path or "/") == endpoint.path:
                return r
    return None


def _apply_target_base(url: str, target_base: Optional[str]) -> str:
    if not target_base:
        return url
    parsed = urlparse(url)
    base = urlparse(target_base)
    if not base.scheme or not base.netloc:
        return url
    return urlunparse((base.scheme, base.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def _build_cases(
    rec: RequestRecord,
    endpoint: EndpointInfo,
    config: RunConfig,
    scan_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    parsed = urlparse(rec.url)
    base_url = _apply_target_base(rec.url, config.target_base_url)

    headers = dict(rec.headers)
    # Apply auth
    if config.auth:
        if config.auth.bearer:
            headers["Authorization"] = f"Bearer {config.auth.bearer}"
        for k, v in config.auth.headers.items():
            headers[k] = v
        if config.auth.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in config.auth.cookies.items()])
            existing = headers.get("Cookie")
            headers["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str

    for k, v in config.custom_headers.items():
        headers[k] = v
    if config.custom_cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in config.custom_cookies.items()])
        existing = headers.get("Cookie")
        headers["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str

    cases = []

    categories = set(config.categories or [])

    # Baseline
    cases.append({
        "id": "baseline",
        "method": rec.method,
        "url": base_url,
        "headers": headers,
        "body": rec.body,
        "ep_key": endpoint.id,
    })

    # Hidden parameter probe (safe)
    if "hidden_params" in categories or not categories:
        q = parse_qs(parsed.query)
        q["aase_probe"] = ["1"]
        new_query = "&".join([f"{k}={v[0]}" for k, v in q.items()])
        probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        probe_url = _apply_target_base(probe_url, config.target_base_url)
        cases.append({
            "id": "hidden_param",
            "method": rec.method,
            "url": probe_url,
            "headers": headers,
            "body": rec.body,
            "ep_key": endpoint.id,
        })

    # CORS probe
    if "cors" in categories or not categories:
        cors_headers = dict(headers)
        cors_headers["Origin"] = "https://example.com"
        cases.append({
            "id": "cors_probe",
            "method": rec.method,
            "url": base_url,
            "headers": cors_headers,
            "body": rec.body,
            "ep_key": endpoint.id,
        })

    # Auth bypass probe
    if endpoint.auth_required and ("auth" in categories or not categories):
        noauth_headers = dict(headers)
        noauth_headers.pop("Authorization", None)
        noauth_headers.pop("Cookie", None)
        cases.append({
            "id": "auth_bypass",
            "method": rec.method,
            "url": base_url,
            "headers": noauth_headers,
            "body": rec.body,
            "ep_key": endpoint.id,
        })

    # Query parameter fuzzing with payloads (gated by aggressive or specific categories)
    if config.aggressive or "sqli" in categories or "xss" in categories or "ssti" in categories:
        cases.extend(_build_hidden_param_fuzz_cases(rec, endpoint, config))

    # Body parameter fuzzing (JSON / form)
    if config.aggressive or "sqli" in categories or "xss" in categories or "ssti" in categories:
        cases.extend(_build_body_param_fuzz_cases(rec, endpoint, config))

    if getattr(config, "enable_oast", False) and scan_id:
        engine = OASTEngine(scan_id, config.oast_callback_base_url)
        cases.append({
            "id": "oast_header_inject",
            "method": rec.method,
            "url": base_url,
            "headers": engine.inject_oast_headers(headers, endpoint.id, endpoint.path, request_url=base_url),
            "body": rec.body,
            "ep_key": endpoint.id,
        })

        if rec.body:
            ct = headers.get("Content-Type") or headers.get("content-type") or ""
            if "application/json" in ct.lower():
                try:
                    parsed_body = json.loads(rec.body.decode("utf-8"))
                    if isinstance(parsed_body, dict):
                        new_body = engine.inject_oast_body(
                            parsed_body,
                            endpoint.id,
                            endpoint.path,
                            request_url=base_url,
                        )
                        cases.append({
                            "id": "oast_body_inject",
                            "method": rec.method,
                            "url": base_url,
                            "headers": engine.inject_oast_headers(headers, endpoint.id, endpoint.path, request_url=base_url),
                            "body": json.dumps(new_body).encode("utf-8"),
                            "ep_key": endpoint.id,
                        })
                except Exception:
                    pass

    return cases


def _now_ts() -> str:
    return time.strftime("%H:%M:%S", time.localtime())


def _add_finding(state: ScanState, severity: str, ftype: str, endpoint: EndpointInfo, evidence: str,
                 request: str, response: str, recommendation: str, cwe: str,
                 request_url: Optional[str] = None, cvss: Optional[float] = None) -> None:
    fid = f"F-{uuid.uuid4().hex[:6]}"
    replay_url = request_url or ""
    replay_curl = _build_replay_curl(endpoint.method, replay_url, request) if replay_url else ""
    developer_notes = _developer_notes_for_finding(ftype, evidence, recommendation)
    verification_steps = _verification_steps_for_finding(ftype, replay_url, endpoint)
    request_summary = _summarize_request_artifacts(endpoint.method, replay_url, request) if replay_url else ""
    response_summary = _summarize_response_artifacts(response)
    state.findings.append({
        "id": fid,
        "severity": severity,
        "type": ftype,
        "endpoint": endpoint.path,
        "method": endpoint.method,
        "evidence": evidence,
        "timestamp": _now_ts(),
    })
    state.report_findings.append({
        "id": fid,
        "severity": severity,
        "type": ftype,
        "endpoint": endpoint.path,
        "method": endpoint.method,
        "host": endpoint.host,
        "cvss": cvss if cvss is not None else (8.0 if severity == "CRITICAL" else 6.0 if severity == "HIGH" else 4.5 if severity == "MEDIUM" else 3.1),
        "evidence": evidence,
        "request": request,
        "response": response,
        "request_url": replay_url,
        "replay_curl": replay_curl,
        "request_summary": request_summary,
        "response_summary": response_summary,
        "developer_notes": developer_notes,
        "verification_steps": verification_steps,
        "recommendation": recommendation,
        "cwe": cwe,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
    })


async def _analyze_case(state: ScanState, endpoint: EndpointInfo, case: Dict[str, Any], resp: httpx.Response) -> None:
    case_id = case["id"]
    body = resp.content or b""
    text = body.decode("utf-8", errors="ignore")
    ep_key = case.get("ep_key", endpoint.id)

    if case_id == "cors_probe":
        acao = resp.headers.get("access-control-allow-origin", "")
        accred = resp.headers.get("access-control-allow-credentials", "")
        if acao == "*" and accred.lower() == "true":
            _add_finding(
                state,
                "LOW",
                "Permissive CORS",
                endpoint,
                "Access-Control-Allow-Origin: * with credentials enabled",
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                "Restrict CORS to trusted origins and avoid wildcard with credentials.",
                "CWE-942",
                request_url=case["url"],
                cvss=4.3,
            )

    if case_id == "auth_bypass":
        if resp.status_code < 400:
            baseline = state.baselines.get(ep_key)
            base_text = (baseline or {}).get("text", "")
            similarity = _fuzzy_ratio(base_text, text[:4000]) if base_text else 0.0
            is_confirmed = bool(baseline and baseline.get("status", 500) < 400 and similarity >= 0.6)
            _add_finding(
                state,
                "CRITICAL" if is_confirmed else "HIGH",
                "Confirmed Auth Bypass" if is_confirmed else "Possible Auth Bypass",
                endpoint,
                (
                    f"Unauthenticated request returned {resp.status_code} with {similarity:.0%} similarity "
                    f"to the authenticated baseline"
                    if baseline else
                    f"Unauthenticated request returned {resp.status_code}"
                ),
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                "Ensure authentication is enforced on protected endpoints.",
                "CWE-306",
                request_url=case["url"],
                cvss=9.1 if is_confirmed else 8.8,
            )

    if case_id == "hidden_param":
        # Heuristic: if response status changes or body length changes significantly
        baseline = state.baselines.get(ep_key)
        if baseline:
            delta = abs(len(body) - baseline.get("len", 0))
            if delta > max(200, baseline.get("len", 0) * 0.2):
                _add_finding(
                    state,
                    "INFO",
                    "Hidden Parameter Behavior",
                    endpoint,
                    f"Adding aase_probe changed response length by {delta} bytes",
                    _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                    _format_response(resp.status_code, dict(resp.headers), body),
                    "Review server handling of unknown parameters for unexpected behavior.",
                    "CWE-20",
                    request_url=case["url"],
                    cvss=2.0,
                )
        elif resp.status_code >= 400:
            _add_finding(
                state,
                "INFO",
                "Hidden Parameter Behavior",
                endpoint,
                f"Adding aase_probe changed response status to {resp.status_code}",
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                "Review server handling of unknown parameters for unexpected behavior.",
                "CWE-20",
                request_url=case["url"],
                cvss=2.0,
            )

    if case_id.startswith("hidden_param_"):
        category = case.get("category", "unknown")
        # Heuristic: 5xx or big response delta indicates potential injection surface
        baseline = state.baselines.get(ep_key)
        base_text = (baseline or {}).get("text", "")
        if resp.status_code >= 500:
            _add_finding(
                state,
                "MEDIUM",
                f"Potential {category.upper()} Surface",
                endpoint,
                f"{category.upper()} probe triggered {resp.status_code}",
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                "Review server-side input handling and sanitization. Verify no injection is possible.",
                "CWE-20",
                request_url=case["url"],
                cvss=5.0,
            )
        elif baseline:
            delta = abs(len(body) - baseline.get("len", 0))
            ratio = _fuzzy_ratio(base_text, text[:4000]) if base_text else 1.0
            if delta > max(500, baseline.get("len", 0) * 0.3) or ratio < 0.7:
                _add_finding(
                    state,
                    "LOW",
                    f"Potential {category.upper()} Reflection",
                    endpoint,
                    f"{category.upper()} probe changed response (len Δ {delta} bytes, similarity {ratio:.2f})",
                    _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                    _format_response(resp.status_code, dict(resp.headers), body),
                    "Check for reflected input and ensure proper encoding/sanitization.",
                    "CWE-79" if category == "xss" else "CWE-89" if category == "sqli" else "CWE-1336",
                    request_url=case["url"],
                    cvss=3.6,
                )

    # Baseline content checks
    if case_id == "baseline":
        # store baseline reference for endpoint
        base_text = text[:4000]
        base_json = _try_parse_json(base_text)
        state.baselines[ep_key] = {
            "status": resp.status_code,
            "len": len(body),
            "text": base_text,
            "json": base_json,
        }
        # Verbose error detection
        if "exception" in text.lower() or "stack trace" in text.lower():
            _add_finding(
                state,
                "LOW",
                "Verbose Error",
                endpoint,
                "Response contains stack trace or exception text",
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                "Disable detailed errors in production and return generic error messages.",
                "CWE-209",
                request_url=case["url"],
                cvss=3.7,
            )

    if case_id.startswith("body_param_"):
        category = case.get("category", "unknown")
        status_delta, len_delta = _baseline_delta(state, ep_key, resp.status_code, len(body))
        baseline = state.baselines.get(ep_key)
        base_text = (baseline or {}).get("text", "")
        ratio = _fuzzy_ratio(base_text, text[:4000]) if base_text else 1.0
        base_json = (baseline or {}).get("json")
        cur_json = _try_parse_json(text[:4000])
        json_diff = _json_diff(base_json, cur_json) if base_json is not None and cur_json is not None else {"added": [], "removed": [], "changed": []}
        if resp.status_code >= 500 or status_delta == 1:
            _add_finding(
                state,
                "MEDIUM",
                f"Potential {category.upper()} Body Injection",
                endpoint,
                f"{category.upper()} body probe changed status to {resp.status_code}",
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                "Review server-side input handling and sanitization for request bodies.",
                "CWE-20",
                request_url=case["url"],
                cvss=5.0,
            )
        elif len_delta > 0 and (len_delta > max(500, (state.baselines.get(ep_key, {}).get("len", 0)) * 0.3) or ratio < 0.7 or json_diff["added"] or json_diff["removed"] or json_diff["changed"]):
            _add_finding(
                state,
                "LOW",
                f"Potential {category.upper()} Body Reflection",
                endpoint,
                f"{category.upper()} body probe changed response (len Δ {len_delta} bytes, similarity {ratio:.2f}, json diff: +{len(json_diff['added'])}/-{len(json_diff['removed'])}/~{len(json_diff['changed'])})",
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                "Check for reflected input and ensure proper encoding/sanitization.",
                "CWE-79" if category == "xss" else "CWE-89" if category == "sqli" else "CWE-1336",
                request_url=case["url"],
                cvss=3.6,
            )

    # ------ Power Module Analysis ------

    # BOLA/IDOR Detection
    if case_id == "bola_probe":
        baseline = state.baselines.get(ep_key)
        baseline_body = baseline.get("text", "").encode() if baseline else None
        result = analyze_bola_response(
            baseline_body,
            body,
            resp.status_code,
            case.get("bola_meta"),
        )
        if result:
            _add_finding(
                state, result["severity"], result["type"], endpoint,
                result["evidence"],
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                result["recommendation"], result["cwe"],
                request_url=case["url"],
                cvss=result.get("cvss"),
            )

    # Stateful fuzzing
    if case_id.startswith("stateful_"):
        result = analyze_stateful_response(case, resp.status_code, body)
        if result:
            _add_finding(
                state, result["severity"], result["type"], endpoint,
                result["evidence"],
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                result["recommendation"], result["cwe"],
                request_url=case["url"],
                cvss=result.get("cvss"),
            )

    # AST Mutations
    if case_id.startswith("mutation_"):
        baseline = state.baselines.get(ep_key)
        result = analyze_mutation_response(
            case, resp.status_code, body,
            baseline.get("status") if baseline else None,
            baseline.get("len") if baseline else None,
        )
        if result:
            _add_finding(
                state, result["severity"], result["type"], endpoint,
                result["evidence"],
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                result["recommendation"], result["cwe"],
                request_url=case["url"],
                cvss=result.get("cvss"),
            )

    # GraphQL
    if case_id.startswith("graphql_"):
        result = analyze_graphql_response(case, resp.status_code, body)
        if result:
            _add_finding(
                state, result["severity"], result["type"], endpoint,
                result["evidence"],
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                result["recommendation"], result["cwe"],
                request_url=case["url"],
                cvss=result.get("cvss"),
            )

    # WebSocket
    if case_id.startswith("ws_"):
        result = analyze_ws_response(case, resp.status_code, body)
        if result:
            _add_finding(
                state, result["severity"], result["type"], endpoint,
                result["evidence"],
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                result["recommendation"], result["cwe"],
                request_url=case["url"],
                cvss=result.get("cvss"),
            )

# -----------------------------
# Safety note
# -----------------------------
# This backend enforces allowlists and can respect robots.txt for bug bounty safety.
# Aggressive mode enables common payloads for controlled environments only.
