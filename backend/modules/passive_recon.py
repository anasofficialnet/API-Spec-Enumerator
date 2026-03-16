"""
AASE Passive Recon Enrichment Module
-------------------------------------
Gathers endpoint intelligence from passive sources WITHOUT touching the target:
  - Wayback Machine (web.archive.org CDX API)
  - CommonCrawl Index
  - AlienVault OTX
  - JavaScript file endpoint/secret extraction
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("aase.passive_recon")

# ---------- Regex patterns ----------

# JWT / API key / secret patterns found in JS files
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"(?:AKIA[0-9A-Z]{16})"),
    "aws_secret_key": re.compile(r"(?:(?:aws|AWS).{0,20}(?:secret|SECRET).{0,20}['\"][0-9a-zA-Z/+]{40}['\"])"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "github_token": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
    "generic_api_key": re.compile(r"(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", re.IGNORECASE),
    "bearer_token": re.compile(r"[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}

# API route patterns in JS files
JS_API_ROUTE_RE = re.compile(
    r"""(?:"""
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|axios|request|"""
    r"""\.(?:get|post|put|patch|delete))\s*\(\s*"""
    r"""(?:['"`])(/(?:api|v[1-9]|graphql|auth|user|admin|internal)[^'"`\s)]{0,200})['"`]"""
    r"""|"""
    r"""['"`](/(?:api|v[1-9]|graphql|auth|user|admin|internal)[^'"`\s]{0,200})['"`]"""
    r""")""",
    re.IGNORECASE,
)

URL_PATH_RE = re.compile(r"https?://[^\s\"'`<>]{5,300}")


# ---------- Data classes ----------

@dataclass
class PassiveURL:
    url: str
    source: str  # "wayback", "commoncrawl", "otx", "js_analysis"
    content_type: Optional[str] = None


@dataclass
class SecretFinding:
    secret_type: str
    value: str
    source_url: str
    context: str  # line snippet


@dataclass
class PassiveReconResult:
    domain: str
    urls: List[PassiveURL] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    js_secrets: List[SecretFinding] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    source_counts: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "urls": [{"url": u.url, "source": u.source, "content_type": u.content_type} for u in self.urls],
            "api_endpoints": self.api_endpoints,
            "js_secrets": [
                {"type": s.secret_type, "value": s.value[:8] + "***REDACTED***", "source_url": s.source_url, "context": s.context[:100]}
                for s in self.js_secrets
            ],
            "subdomains": self.subdomains,
            "source_counts": self.source_counts,
            "total_urls": len(self.urls),
            "total_api_endpoints": len(self.api_endpoints),
            "total_secrets": len(self.js_secrets),
            "errors": self.errors,
        }


# ---------- Passive sources ----------

async def fetch_wayback_urls(domain: str, client: httpx.AsyncClient, limit: int = 500) -> List[PassiveURL]:
    """Fetch historical URLs from the Wayback Machine CDX API."""
    urls: List[PassiveURL] = []
    try:
        resp = await client.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original,mimetype",
                "collapse": "urlkey",
                "limit": str(limit),
                "filter": "statuscode:200",
            },
        )
        if resp.status_code != 200:
            return urls
        data = resp.json()
        # First row is header
        for row in data[1:]:
            if len(row) >= 2:
                urls.append(PassiveURL(url=row[0], source="wayback", content_type=row[1] if len(row) > 1 else None))
    except Exception as exc:
        logger.warning("Wayback fetch failed for %s: %s", domain, exc)
    return urls


async def fetch_commoncrawl_urls(domain: str, client: httpx.AsyncClient, limit: int = 300) -> List[PassiveURL]:
    """Fetch URLs from the CommonCrawl index API."""
    urls: List[PassiveURL] = []
    try:
        # Get the latest index
        index_resp = await client.get("https://index.commoncrawl.org/collinfo.json")
        if index_resp.status_code != 200:
            return urls
        indexes = index_resp.json()
        if not indexes:
            return urls
        latest_index = indexes[0]["cdx-api"]

        resp = await client.get(
            latest_index,
            params={
                "url": f"*.{domain}",
                "output": "json",
                "limit": str(limit),
            },
        )
        if resp.status_code != 200:
            return urls
        for line in resp.text.strip().splitlines():
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
                if url:
                    urls.append(PassiveURL(url=url, source="commoncrawl", content_type=obj.get("mime")))
            except json.JSONDecodeError:
                continue
    except Exception as exc:
        logger.warning("CommonCrawl fetch failed for %s: %s", domain, exc)
    return urls


async def fetch_otx_urls(domain: str, client: httpx.AsyncClient, limit: int = 500) -> List[PassiveURL]:
    """Fetch known URLs from AlienVault OTX."""
    urls: List[PassiveURL] = []
    try:
        resp = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
            params={"limit": str(limit), "page": "1"},
        )
        if resp.status_code != 200:
            return urls
        data = resp.json()
        for entry in data.get("url_list", []):
            url = entry.get("url", "")
            if url:
                urls.append(PassiveURL(url=url, source="otx"))
        # Also extract passive DNS subdomains
        dns_resp = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            params={"limit": "200"},
        )
        if dns_resp.status_code == 200:
            dns_data = dns_resp.json()
            for entry in dns_data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if hostname and hostname.endswith(domain) and hostname != domain:
                    urls.append(PassiveURL(url=f"https://{hostname}", source="otx"))
    except Exception as exc:
        logger.warning("OTX fetch failed for %s: %s", domain, exc)
    return urls


def extract_js_endpoints(js_body: str, source_url: str = "") -> tuple[List[str], List[SecretFinding]]:
    """Parse JavaScript file content for API endpoints and secrets."""
    endpoints: Set[str] = set()
    secrets: List[SecretFinding] = []

    # Extract API routes
    for match in JS_API_ROUTE_RE.finditer(js_body):
        path = match.group(1) or match.group(2)
        if path and len(path) > 2 and not path.endswith((".css", ".png", ".jpg", ".svg", ".ico", ".woff")):
            endpoints.add(path)

    # Extract full URLs that look like API endpoints
    for match in URL_PATH_RE.finditer(js_body):
        url = match.group(0).rstrip("\"'`,;)}>]")
        parsed = urlparse(url)
        if parsed.path and any(seg in parsed.path.lower() for seg in ["/api", "/v1", "/v2", "/v3", "/graphql", "/auth"]):
            endpoints.add(url)

    # Scan for secrets
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(js_body):
            value = match.group(0)
            # Get surrounding context
            start = max(0, match.start() - 30)
            end = min(len(js_body), match.end() + 30)
            context = js_body[start:end].replace("\n", " ").strip()
            secrets.append(SecretFinding(
                secret_type=secret_type,
                value=value,
                source_url=source_url,
                context=context,
            ))

    return sorted(endpoints), secrets


async def fetch_and_analyze_js_files(
    domain: str,
    client: httpx.AsyncClient,
    discovered_urls: List[PassiveURL],
    max_files: int = 30,
) -> tuple[List[str], List[SecretFinding]]:
    """Fetch JS files found in passive URLs and extract endpoints/secrets."""
    all_endpoints: Set[str] = set()
    all_secrets: List[SecretFinding] = []

    js_urls: Set[str] = set()
    for pu in discovered_urls:
        if pu.url.endswith((".js", ".mjs")) or (pu.content_type and "javascript" in pu.content_type):
            js_urls.add(pu.url)
    # Also try common JS paths
    for path in ["/main.js", "/app.js", "/bundle.js", "/index.js", "/vendor.js", "/chunk.js"]:
        js_urls.add(f"https://{domain}{path}")

    sem = asyncio.Semaphore(5)

    async def _fetch_js(url: str) -> None:
        async with sem:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    ct = (resp.headers.get("content-type") or "").lower()
                    if "javascript" in ct or "ecmascript" in ct or url.endswith((".js", ".mjs")):
                        body = resp.text[:500_000]  # Limit to 500KB
                        endpoints, secrets = extract_js_endpoints(body, url)
                        all_endpoints.update(endpoints)
                        all_secrets.extend(secrets)
            except Exception:
                pass

    tasks = [_fetch_js(url) for url in list(js_urls)[:max_files]]
    await asyncio.gather(*tasks)

    return sorted(all_endpoints), all_secrets


# ---------- Orchestrator ----------

async def run_passive_recon(domain: str) -> PassiveReconResult:
    """Run all passive recon sources in parallel and merge results."""
    domain = domain.strip().lower()
    # Strip protocol/path if user passed a full URL
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc or domain
    domain = domain.split(":")[0]  # Strip port

    result = PassiveReconResult(domain=domain)

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=True,
        headers={"User-Agent": "AASE-PassiveRecon/1.0"},
    ) as client:
        # Run all passive sources in parallel
        wayback_task = fetch_wayback_urls(domain, client)
        commoncrawl_task = fetch_commoncrawl_urls(domain, client)
        otx_task = fetch_otx_urls(domain, client)

        wayback_urls, cc_urls, otx_urls = await asyncio.gather(
            wayback_task, commoncrawl_task, otx_task,
            return_exceptions=True,
        )

        # Process results (handle exceptions gracefully)
        for source_name, source_urls in [
            ("wayback", wayback_urls),
            ("commoncrawl", cc_urls),
            ("otx", otx_urls),
        ]:
            if isinstance(source_urls, Exception):
                result.errors.append(f"{source_name}: {str(source_urls)}")
                result.source_counts[source_name] = 0
            else:
                result.urls.extend(source_urls)
                result.source_counts[source_name] = len(source_urls)

        # Deduplicate URLs
        seen: Set[str] = set()
        unique_urls: List[PassiveURL] = []
        for pu in result.urls:
            if pu.url not in seen:
                seen.add(pu.url)
                unique_urls.append(pu)
        result.urls = unique_urls

        # Extract subdomains from discovered URLs
        subdomain_set: Set[str] = set()
        for pu in result.urls:
            try:
                parsed = urlparse(pu.url)
                host = (parsed.netloc or "").split(":")[0].lower()
                if host and host.endswith(domain) and host != domain:
                    subdomain_set.add(host)
            except Exception:
                continue
        result.subdomains = sorted(subdomain_set)

        # Filter for API-looking endpoints
        api_keywords = {"/api", "/v1/", "/v2/", "/v3/", "/graphql", "/auth", "/oauth",
                        "/token", "/login", "/register", "/admin", "/internal", "/webhook",
                        "/callback", "/ws", "/socket", ".json", "/rest"}
        for pu in result.urls:
            path = urlparse(pu.url).path.lower()
            if any(kw in path for kw in api_keywords):
                if pu.url not in result.api_endpoints:
                    result.api_endpoints.append(pu.url)

        # Analyze JS files for endpoints and secrets
        try:
            js_endpoints, js_secrets = await fetch_and_analyze_js_files(
                domain, client, result.urls,
            )
            result.api_endpoints.extend(ep for ep in js_endpoints if ep not in result.api_endpoints)
            result.js_secrets = js_secrets
            result.source_counts["js_analysis"] = len(js_endpoints) + len(js_secrets)
        except Exception as exc:
            result.errors.append(f"js_analysis: {str(exc)}")
            result.source_counts["js_analysis"] = 0

    return result
