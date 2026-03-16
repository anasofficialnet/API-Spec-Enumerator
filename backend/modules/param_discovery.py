"""
AASE Parameter Discovery Module — Arjun-style param brute, Content-Type switching, method tampering.
"""
from __future__ import annotations
import asyncio, json, logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
import httpx

logger = logging.getLogger("aase.param_discovery")

COMMON_PARAMS = [
    "id","user","username","email","password","token","api_key","apikey","key","secret","auth",
    "session","jwt","access_token","refresh_token","client_id","client_secret","user_id","uid",
    "account","account_id","name","phone","role","admin","group","group_id","org_id","tenant_id",
    "q","query","search","filter","keyword","category","tag","type","status","state","active",
    "page","limit","offset","skip","size","per_page","sort","order","orderby","direction","cursor",
    "action","method","cmd","command","op","mode","create","update","delete","edit","remove","add",
    "file","filename","path","dir","upload","download","url","redirect","redirect_uri","redirect_url",
    "return_url","next","continue","goto","target","dest","callback","callback_url","success_url",
    "format","output","fields","include","exclude","expand","select","pretty","debug","verbose",
    "data","input","value","param","body","content","text","message","comment","description",
    "xml","json","html","template","render","view","config","settings","env","version","v",
    "lang","locale","width","height","color","theme","table","column","field","schema","db",
    "where","join","populate","code","pin","otp","amount","price","quantity","total","discount",
    "ip","host","port","domain","scope","permission","webhook","event","trigger","hash","signature",
    "nonce","source","origin","channel","platform","device","lat","lng","location",
]

@dataclass
class ParamFinding:
    endpoint: str; method: str; finding_type: str; detail: str
    param_name: Optional[str] = None; original_status: Optional[int] = None
    probe_status: Optional[int] = None; response_diff: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in ["endpoint","method","finding_type","detail","param_name","original_status","probe_status","response_diff"]}

@dataclass
class ParamDiscoveryResult:
    findings: List[ParamFinding] = field(default_factory=list)
    endpoints_scanned: int = 0; params_tested: int = 0
    errors: List[str] = field(default_factory=list)
    def to_dict(self) -> Dict[str, Any]:
        return {"findings": [f.to_dict() for f in self.findings], "endpoints_scanned": self.endpoints_scanned,
                "params_tested": self.params_tested, "total_findings": len(self.findings), "errors": self.errors}

async def _get_baseline(client: httpx.AsyncClient, url: str, method: str, headers: Dict[str, str]) -> Optional[Tuple[int, int, str]]:
    try:
        resp = await client.request(method, url, headers=headers)
        body = resp.text[:5000]
        return resp.status_code, len(body), body
    except Exception:
        return None

async def brute_force_params(client: httpx.AsyncClient, url: str, method: str, headers: Dict[str, str],
                              baseline: Tuple[int, int, str], sem: asyncio.Semaphore) -> List[ParamFinding]:
    findings: List[ParamFinding] = []
    base_status, base_len, base_body = baseline
    parsed = urlparse(url)
    existing_qs = parse_qs(parsed.query)
    for param in COMMON_PARAMS:
        async with sem:
            test_qs = dict(existing_qs); test_qs[param] = ["aase_probe_7x7"]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_qs, doseq=True), ""))
            try:
                resp = await client.request(method, test_url, headers=headers)
                resp_body = resp.text[:5000]
                status_diff = resp.status_code != base_status
                len_diff = abs(len(resp_body) - base_len) > 50
                reflected = param in resp_body and param not in base_body
                if status_diff or len_diff or reflected:
                    findings.append(ParamFinding(endpoint=url, method=method, finding_type="hidden_param",
                        detail=f"Parameter '{param}' changes response (status:{base_status}→{resp.status_code}, len:{base_len}→{len(resp_body)}, reflected:{reflected})",
                        param_name=param, original_status=base_status, probe_status=resp.status_code,
                        response_diff=f"Status:{base_status}→{resp.status_code}, Len:{base_len}→{len(resp_body)}"))
            except Exception:
                continue
    return findings

def _dict_to_xml(d: Dict[str, Any]) -> str:
    return "<root>" + "".join(f"<{k}>{v}</{k}>" for k, v in (d or {}).items()) + "</root>"

CT_VARIANTS = [
    ("application/json", lambda b: json.dumps(b) if b else "{}"),
    ("application/x-www-form-urlencoded", lambda b: urlencode(b) if isinstance(b, dict) else "key=value"),
    ("application/xml", lambda b: _dict_to_xml(b) if isinstance(b, dict) else "<root><key>value</key></root>"),
    ("text/plain", lambda b: str(b) if b else "test"),
]

async def test_content_type_switching(client: httpx.AsyncClient, url: str, method: str, headers: Dict[str, str],
                                       original_ct: Optional[str], body: Optional[Dict], sem: asyncio.Semaphore) -> List[ParamFinding]:
    findings: List[ParamFinding] = []
    if method.upper() not in {"POST", "PUT", "PATCH"}: return findings
    orig = (original_ct or "").lower()
    for ct, fn in CT_VARIANTS:
        if ct.lower() in orig: continue
        async with sem:
            try:
                h = dict(headers); h["Content-Type"] = ct
                b = fn(body); content = b.encode("utf-8") if isinstance(b, str) else b
                resp = await client.request(method, url, headers=h, content=content)
                if resp.status_code not in {400, 405, 415, 406, 422}:
                    findings.append(ParamFinding(endpoint=url, method=method, finding_type="content_type_accepted",
                        detail=f"Accepts Content-Type: {ct} (status {resp.status_code}). Original: {orig or 'unknown'}.",
                        probe_status=resp.status_code, response_diff=f"Accepted {ct} → {resp.status_code}"))
            except Exception: pass
    return findings

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

async def test_method_tampering(client: httpx.AsyncClient, url: str, original_method: str,
                                 headers: Dict[str, str], sem: asyncio.Semaphore) -> List[ParamFinding]:
    findings: List[ParamFinding] = []
    for method in ALL_METHODS:
        if method.upper() == original_method.upper(): continue
        async with sem:
            try:
                resp = await client.request(method, url, headers=headers)
                if 200 <= resp.status_code < 400:
                    findings.append(ParamFinding(endpoint=url, method=original_method, finding_type="method_allowed",
                        detail=f"Accepts {method} (status {resp.status_code}) — only observed with {original_method}.",
                        probe_status=resp.status_code, response_diff=f"{method} → {resp.status_code}"))
            except Exception: pass
    return findings

async def run_param_discovery(endpoints: List[Dict[str, Any]], target_base_url: str,
                               auth_headers: Optional[Dict[str, str]] = None, rate_limit: float = 5.0, concurrency: int = 3) -> ParamDiscoveryResult:
    result = ParamDiscoveryResult()
    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "AASE-ParamDiscovery/1.0", "Accept": "application/json, text/html, */*"}
    if auth_headers: headers.update(auth_headers)
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        for ep in endpoints:
            url = ep.get("url", ""); method = ep.get("method", "GET").upper()
            if not url: continue
            result.endpoints_scanned += 1
            baseline = await _get_baseline(client, url, method, headers)
            if not baseline:
                result.errors.append(f"Unreachable: {method} {url}"); continue
            try:
                result.findings.extend(await brute_force_params(client, url, method, headers, baseline, sem=sem))
                result.params_tested += len(COMMON_PARAMS)
                result.findings.extend(await test_content_type_switching(client, url, method, headers, ep.get("content_type"), ep.get("body"), sem=sem))
                result.findings.extend(await test_method_tampering(client, url, method, headers, sem=sem))
                if rate_limit > 0: await asyncio.sleep(1.0 / rate_limit)
            except Exception as exc:
                result.errors.append(f"{method} {url}: {exc}")
    return result
