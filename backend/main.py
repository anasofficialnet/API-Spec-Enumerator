from __future__ import annotations

import asyncio
import base64
import json
import re
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

# -----------------------------
# Models
# -----------------------------

class AuthConfig(BaseModel):
    bearer: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)

class RunConfig(BaseModel):
    allowlist: List[str] = Field(default_factory=list)
    target_base_url: Optional[str] = None
    rate_limit: float = 2.0
    concurrency: int = 1
    respect_robots: bool = True
    aggressive: bool = False
    auth: Optional[AuthConfig] = None
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    custom_cookies: Dict[str, str] = Field(default_factory=dict)
    dry_run: bool = False
    categories: List[str] = Field(default_factory=list)

class IngestResponse(BaseModel):
    scan_id: str
    fileName: str
    format: str
    transactions: int
    hosts: List[str]
    endpoints: List[Dict[str, Any]]

class RunRequest(BaseModel):
    selected_endpoints: List[str]
    config: RunConfig

class ScanStatus(BaseModel):
    isRunning: bool
    progress: int
    casesRun: int
    totalCases: int
    findings: List[Dict[str, Any]]
    dry_run_log: Optional[List[Dict[str, Any]]] = None

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
    h = _lower_headers(headers)
    if "authorization" in h:
        return True
    if "cookie" in h and h["cookie"].strip():
        return True
    return False


def _schema_confidence(sample_count: int) -> float:
    # Simple heuristic: more samples -> higher confidence
    return min(99.0, 70.0 + sample_count * 3.0)


def _estimate_fuzz_cases(param_count: int, body_fields: int) -> int:
    return max(10, (param_count + body_fields) * 4 + 6)


def _safe_host(host: str) -> str:
    return host.lower().split(":")[0]


def _host_in_allowlist(host: str, allowlist: List[str]) -> bool:
    h = _safe_host(host)
    for a in allowlist:
        a = _safe_host(a)
        if h == a or h.endswith("." + a):
            return True
    return False


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

    return RequestRecord(method=method, url=url, headers=headers, body=body, status=status)


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
            records.append(RequestRecord(method=method, url=url, headers=headers, body=body, status=status, response_headers=response_headers, response_body=response_body))
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
        records.append(RequestRecord(method=method, url=url, headers=headers, body=body, status=status, response_headers=response_headers, response_body=response_body))
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
        records.append(RequestRecord(method=method, url=url, headers=headers, body=body))
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
        return fmt, _parse_har(content)
    if fmt == "burp":
        return fmt, _parse_burp_xml(content)
    if fmt == "jsonl":
        return fmt, _parse_jsonl(content)
    if fmt == "raw_http":
        return fmt, _parse_raw_http(content.decode("utf-8", errors="ignore"))
    if fmt == "mitmproxy":
        return fmt, _parse_mitmproxy_json(content)
    # Fallback: try JSON lines, then mitmproxy JSON, then HAR, else Burp XML
    recs = _parse_jsonl(content)
    if recs:
        return "jsonl", recs
    try:
        return "mitmproxy", _parse_mitmproxy_json(content)
    except HTTPException:
        try:
            return "har", _parse_har(content)
        except HTTPException:
            return "burp", _parse_burp_xml(content)


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
        for r in recs:
            params.update(_extract_params_from_url(r.url))
            ct = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_keys, _ = _parse_body(ct, r.body)
            body_fields.update(body_keys)
            if r.status:
                status_codes.add(r.status)
            if _detect_auth(r.headers):
                auth_required = True
        endpoint_id = f"ep-{uuid.uuid4().hex[:8]}"
        endpoints[endpoint_id] = EndpointInfo(
            id=endpoint_id,
            method=method,
            path=path,
            host=host,
            status_codes=sorted(list(status_codes)) or [200],
            auth_required=auth_required,
            params=sorted(list(params)),
            body_fields=sorted(list(body_fields)),
            schema_confidence=_schema_confidence(len(recs)),
            fuzz_cases=_estimate_fuzz_cases(len(params), len(body_fields)),
        )
    return endpoints


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
            ],
            "xss": [
                "<script>alert(1)</script>",
                "\" onmouseover=\"alert(1)\" x=\"",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
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

    endpoint_list = [
        {
            "id": e.id,
            "method": e.method,
            "path": e.path,
            "host": e.host,
            "statusCodes": e.status_codes,
            "authRequired": e.auth_required,
            "paramCount": len(e.params),
            "bodyFields": e.body_fields,
            "schemaConfidence": e.schema_confidence,
            "fuzzCases": e.fuzz_cases,
        }
        for e in endpoints.values()
    ]

    return IngestResponse(
        scan_id=scan_id,
        fileName=state.file_name,
        format=fmt,
        transactions=len(records),
        hosts=hosts,
        endpoints=endpoint_list,
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
    if not config.allowlist:
        raise HTTPException(status_code=400, detail="Allowlist is required")
    if config.auth is None and state.stored_auth is not None:
        config.auth = state.stored_auth

    state.is_running = True
    state.cases_run = 0
    state.findings = []
    state.report_findings = []

    async def _runner():
        try:
            await _execute_scan(state, selected, config)
        finally:
            state.is_running = False
            state.last_updated = time.time()

    background.add_task(_runner)
    return {"status": "started"}

@app.get("/api/scan/{scan_id}/status", response_model=ScanStatus)
async def scan_status(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    progress = int((state.cases_run / state.total_cases) * 100) if state.total_cases else 0
    return ScanStatus(
        isRunning=state.is_running,
        progress=progress,
        casesRun=state.cases_run,
        totalCases=state.total_cases,
        findings=state.findings,
        dry_run_log=state.dry_run_log,
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
    """Accept raw HTTP text (one or more request blocks) and ingest as a scan."""
    records = _parse_raw_http(body.text)
    if not records:
        raise HTTPException(status_code=400, detail="No valid HTTP requests found in pasted text")

    endpoints = _build_endpoints(records)
    hosts = sorted({urlparse(r.url).netloc for r in records if r.url})

    scan_id = uuid.uuid4().hex
    state = ScanState(
        scan_id=scan_id,
        file_name="pasted_traffic.txt",
        format="raw_http",
        records=records,
        endpoints=endpoints,
    )

    if body.auth_config:
        try:
            state.stored_auth = AuthConfig(**body.auth_config)
        except Exception:
            raise HTTPException(status_code=400, detail="auth_config does not match expected schema")

    SCANS[scan_id] = state

    endpoint_list = [
        {
            "id": e.id, "method": e.method, "path": e.path, "host": e.host,
            "statusCodes": e.status_codes, "authRequired": e.auth_required,
            "paramCount": len(e.params), "bodyFields": e.body_fields,
            "schemaConfidence": e.schema_confidence, "fuzzCases": e.fuzz_cases,
        }
        for e in endpoints.values()
    ]
    return IngestResponse(
        scan_id=scan_id, fileName="pasted_traffic.txt", format="raw_http",
        transactions=len(records), hosts=hosts, endpoints=endpoint_list,
    )


@app.get("/api/scan/{scan_id}/events")
async def scan_events(scan_id: str, request: Request):
    """SSE endpoint streaming live scan progress events."""
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator() -> AsyncGenerator[str, None]:
        last_sent = -1
        while True:
            if await request.is_disconnected():
                break
            progress = int((state.cases_run / state.total_cases) * 100) if state.total_cases else 0
            if progress != last_sent:
                payload = json.dumps({
                    "isRunning": state.is_running,
                    "progress": progress,
                    "casesRun": state.cases_run,
                    "totalCases": state.total_cases,
                    "findings": state.findings,
                })
                yield f"data: {payload}\n\n"
                last_sent = progress
            if not state.is_running and state.cases_run >= state.total_cases and state.total_cases > 0:
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
    """Download a single-file HTML vulnerability report."""
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    sev_colors = {
        "CRITICAL": "#FF4F4F", "HIGH": "#FF8C42", "MEDIUM": "#FFD166",
        "LOW": "#00E676", "INFO": "#4FC3F7",
    }
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    findings_html = ""
    for i, f in enumerate(sorted(state.report_findings,
                                  key=lambda x: sev_order.index(x.get("severity", "INFO")) if x.get("severity") in sev_order else 99)):
        color = sev_colors.get(f.get("severity", "INFO"), "#4FC3F7")
        findings_html += f"""
        <div class="finding">
          <div class="finding-header" style="border-left:4px solid {color}">
            <span class="badge" style="background:{color}20;color:{color};border:1px solid {color}40">{_html_escape(f.get('severity','?'))}</span>
            <span class="finding-title">{_html_escape(f.get('type','Unknown'))}</span>
            <span class="finding-meta">{_html_escape(f.get('method',''))} {_html_escape(f.get('endpoint',''))} &nbsp;·&nbsp; {_html_escape(f.get('host',''))}</span>
            <span class="cvss" style="color:{color}">CVSS {f.get('cvss', 0):.1f}</span>
            <span class="cwe">{_html_escape(f.get('cwe',''))}</span>
          </div>
          <div class="finding-body">
            <p class="evidence">{_html_escape(f.get('evidence',''))}</p>
            <details><summary>Request</summary><pre>{_html_escape(f.get('request',''))}</pre></details>
            <details><summary>Response</summary><pre>{_html_escape(f.get('response',''))}</pre></details>
            <details open><summary>Remediation</summary><pre>{_html_escape(f.get('recommendation',''))}</pre></details>
          </div>
        </div>"""

    total = len(state.report_findings)
    counts = {s: sum(1 for f in state.report_findings if f.get("severity") == s) for s in sev_order}

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AASE Security Report — {_html_escape(scan_id)}</title>
<style>
  body{{font-family:monospace;background:#080C0A;color:#E8F5E9;margin:0;padding:0}}
  .confidential{{background:#FF4F4F;color:#fff;text-align:center;padding:8px;font-weight:bold;font-size:12px;letter-spacing:4px}}
  .header{{background:#0D1410;border-bottom:1px solid #00E67620;padding:32px 48px}}
  .header h1{{margin:0;font-size:24px;color:#00E676}}
  .header p{{margin:4px 0;color:#5A7A65;font-size:11px}}
  .summary{{display:flex;gap:16px;padding:24px 48px;flex-wrap:wrap}}
  .sev-card{{background:#0D1410;border:1px solid #00E67620;border-radius:6px;padding:16px 24px;min-width:100px;text-align:center}}
  .sev-num{{font-size:32px;font-weight:900;line-height:1}}
  .sev-label{{font-size:10px;color:#5A7A65;text-transform:uppercase;letter-spacing:2px;margin-top:4px}}
  .findings{{padding:0 48px 48px}}
  .finding{{background:#0D1410;border:1px solid #00E67615;border-radius:6px;margin-bottom:12px;overflow:hidden}}
  .finding-header{{display:flex;align-items:center;gap:12px;padding:12px 16px;flex-wrap:wrap}}
  .badge{{font-size:10px;padding:2px 8px;border-radius:4px;font-weight:bold;text-transform:uppercase;letter-spacing:1px}}
  .finding-title{{font-weight:bold;font-size:13px}}
  .finding-meta{{color:#5A7A65;font-size:11px;flex:1}}
  .cvss{{font-size:12px;font-weight:bold}}
  .cwe{{font-size:10px;color:#5A7A65}}
  .finding-body{{padding:0 16px 16px;border-top:1px solid #00E67610}}
  .evidence{{color:#E8F5E9;font-size:12px;margin:12px 0}}
  details{{margin:8px 0}}
  summary{{cursor:pointer;color:#5A7A65;font-size:11px;text-transform:uppercase;letter-spacing:1px}}
  pre{{background:#000;border:1px solid #00E67615;border-radius:4px;padding:12px;font-size:11px;overflow-x:auto;white-space:pre-wrap;color:#E8F5E9;margin:8px 0}}
  .footer{{text-align:center;padding:24px;color:#2E4A38;font-size:10px;border-top:1px solid #00E67610}}
</style>
</head>
<body>
<div class="confidential">⚠ CONFIDENTIAL — SECURITY REPORT — NOT FOR PUBLIC DISTRIBUTION ⚠</div>
<div class="header">
  <h1>AASE Vulnerability Report</h1>
  <p>Scan ID: {_html_escape(scan_id)}</p>
  <p>File: {_html_escape(state.file_name)} &nbsp;|&nbsp; Format: {_html_escape(state.format)}</p>
  <p>Started: {_html_escape(state.started_at)} &nbsp;|&nbsp; Total cases: {state.total_cases} &nbsp;|&nbsp; Total findings: {total}</p>
</div>
<div class="summary">
  {"".join(f'<div class="sev-card"><div class="sev-num" style="color:{sev_colors[s]}">{counts[s]}</div><div class="sev-label">{s}</div></div>' for s in sev_order)}
</div>
<div class="findings">
  <h2 style="color:#5A7A65;font-size:12px;text-transform:uppercase;letter-spacing:3px;margin-bottom:16px">Findings ({total})</h2>
  {findings_html if findings_html else '<p style="color:#2E4A38;font-size:12px">No findings recorded.</p>'}
</div>
<div class="footer">Generated by AASE &mdash; API Attack Surface Enumerator &mdash; Handle as Confidential</div>
</body></html>"""

    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f"attachment; filename=aase_report_{scan_id}.html"},
    )


# -----------------------------
# Scan engine
# -----------------------------

async def _execute_scan(state: ScanState, selected: set[str], config: RunConfig) -> None:
    endpoint_map = {eid: state.endpoints[eid] for eid in selected if eid in state.endpoints}
    if not endpoint_map:
        return

    # Build cases once
    case_queue: List[Tuple[EndpointInfo, Dict[str, Any]]] = []
    for endpoint in endpoint_map.values():
        rec = _pick_record(state.records, endpoint)
        if not rec:
            continue
        cases = _build_cases(rec, endpoint, config)
        for c in cases:
            case_queue.append((endpoint, c))

    state.total_cases = len(case_queue)

    limiter = asyncio.Semaphore(max(1, config.concurrency))

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        for endpoint, case in case_queue:
            await limiter.acquire()
            try:
                if config.dry_run:
                    await asyncio.sleep(1.0 / max(0.1, config.rate_limit))
                    # Log the dry-run case so UI can track it
                    state.dry_run_log.append({
                        "id": case.get("id", "unknown"),
                        "method": case.get("method"),
                        "url": case.get("url"),
                        "ep_key": case.get("ep_key"),
                        "skipped": True,
                    })
                    state.cases_run += 1
                    limiter.release()
                    continue

                parsed = urlparse(case["url"])
                if config.respect_robots:
                    disallow = _build_robots_allowlist(parsed.netloc)
                    if _is_disallowed(parsed.path or "/", disallow):
                        state.cases_run += 1
                        limiter.release()
                        continue

                if not _host_in_allowlist(parsed.netloc, config.allowlist):
                    state.cases_run += 1
                    limiter.release()
                    continue

                resp = await client.request(
                    case["method"],
                    case["url"],
                    headers=case["headers"],
                    content=case.get("body"),
                )

                await _analyze_case(state, endpoint, case, resp)
                state.cases_run += 1
                await asyncio.sleep(1.0 / max(0.1, config.rate_limit))
            finally:
                limiter.release()


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


def _build_cases(rec: RequestRecord, endpoint: EndpointInfo, config: RunConfig) -> List[Dict[str, Any]]:
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

    # Hidden parameter fuzzing with payloads (gated by aggressive)
    if "hidden_params" in categories and (config.aggressive or "sqli" in categories or "xss" in categories or "ssti" in categories):
        cases.extend(_build_hidden_param_fuzz_cases(rec, endpoint, config))

    # Body parameter fuzzing (JSON / form)
    if "hidden_params" in categories and (config.aggressive or "sqli" in categories or "xss" in categories or "ssti" in categories):
        cases.extend(_build_body_param_fuzz_cases(rec, endpoint, config))

    return cases


def _now_ts() -> str:
    return time.strftime("%H:%M:%S", time.localtime())


def _add_finding(state: ScanState, severity: str, ftype: str, endpoint: EndpointInfo, evidence: str,
                 request: str, response: str, recommendation: str, cwe: str) -> None:
    fid = f"F-{uuid.uuid4().hex[:6]}"
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
        "cvss": 6.0 if severity in {"HIGH", "CRITICAL"} else 4.0,
        "evidence": evidence,
        "request": request,
        "response": response,
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
            )

    if case_id == "auth_bypass":
        # Heuristic: 2xx or 3xx without auth may indicate missing auth
        if resp.status_code < 400:
            _add_finding(
                state,
                "HIGH",
                "Possible Auth Bypass",
                endpoint,
                f"Unauthenticated request returned {resp.status_code}",
                _format_request(case["method"], case["url"], case["headers"], case.get("body")),
                _format_response(resp.status_code, dict(resp.headers), body),
                "Ensure authentication is enforced on protected endpoints.",
                "CWE-306",
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
            )

# -----------------------------
# Safety note
# -----------------------------
# This backend enforces allowlists and can respect robots.txt for bug bounty safety.
# Aggressive mode enables common payloads for controlled environments only.
