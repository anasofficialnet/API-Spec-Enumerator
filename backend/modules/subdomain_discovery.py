"""
AASE Subdomain Discovery Module
---------------------------------
Discovers subdomains via:
  - crt.sh Certificate Transparency logs
  - DNS resolution verification
  - Cross-subdomain CORS misconfiguration testing
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("aase.subdomain_discovery")


@dataclass
class SubdomainInfo:
    subdomain: str
    source: str  # "crtsh", "otx", "passive_recon"
    is_live: bool = False
    ip_address: Optional[str] = None
    http_status: Optional[int] = None
    server_header: Optional[str] = None
    cors_misconfigured: bool = False
    cors_details: Optional[str] = None


@dataclass
class SubdomainResult:
    domain: str
    subdomains: List[SubdomainInfo] = field(default_factory=list)
    live_count: int = 0
    cors_issues: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "source": s.source,
                    "is_live": s.is_live,
                    "ip_address": s.ip_address,
                    "http_status": s.http_status,
                    "server_header": s.server_header,
                    "cors_misconfigured": s.cors_misconfigured,
                    "cors_details": s.cors_details,
                }
                for s in self.subdomains
            ],
            "total": len(self.subdomains),
            "live_count": self.live_count,
            "cors_issues": self.cors_issues,
            "errors": self.errors,
        }


# ---------- crt.sh ----------

async def fetch_crtsh_subdomains(domain: str, client: httpx.AsyncClient) -> List[str]:
    """Query crt.sh Certificate Transparency logs for subdomains."""
    subdomains: Set[str] = set()
    try:
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            # name_value can contain multiple domains separated by newlines
            for name in name_value.split("\n"):
                name = name.strip().lower()
                # Remove wildcard prefix
                if name.startswith("*."):
                    name = name[2:]
                if name and name.endswith(domain) and name != domain:
                    # Basic validation
                    if all(c.isalnum() or c in ".-_" for c in name):
                        subdomains.add(name)
    except Exception as exc:
        logger.warning("crt.sh fetch failed for %s: %s", domain, exc)
    return sorted(subdomains)


# ---------- DNS Resolution ----------

async def dns_resolve_subdomains(
    subdomains: List[str],
    concurrency: int = 20,
) -> Dict[str, Optional[str]]:
    """Resolve subdomains to IP addresses using stdlib socket (non-blocking via executor)."""
    results: Dict[str, Optional[str]] = {}
    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_event_loop()

    async def _resolve(subdomain: str) -> None:
        async with sem:
            try:
                ip = await loop.run_in_executor(
                    None, lambda: socket.gethostbyname(subdomain)
                )
                results[subdomain] = ip
            except (socket.gaierror, socket.herror, OSError):
                results[subdomain] = None

    await asyncio.gather(*[_resolve(s) for s in subdomains])
    return results


# ---------- HTTP Probing ----------

async def probe_subdomains(
    subdomains: List[str],
    client: httpx.AsyncClient,
    concurrency: int = 10,
) -> Dict[str, Dict[str, Any]]:
    """Probe subdomains with HTTP to check if they're serving content."""
    results: Dict[str, Dict[str, Any]] = {}
    sem = asyncio.Semaphore(concurrency)

    async def _probe(subdomain: str) -> None:
        async with sem:
            for scheme in ["https", "http"]:
                try:
                    resp = await client.get(
                        f"{scheme}://{subdomain}/",
                        follow_redirects=True,
                    )
                    results[subdomain] = {
                        "status": resp.status_code,
                        "server": resp.headers.get("server"),
                        "scheme": scheme,
                    }
                    return
                except Exception:
                    continue
            results[subdomain] = {"status": None, "server": None, "scheme": None}

    await asyncio.gather(*[_probe(s) for s in subdomains])
    return results


# ---------- Cross-Subdomain CORS Testing ----------

async def test_cross_subdomain_cors(
    domain: str,
    live_subdomains: List[str],
    client: httpx.AsyncClient,
    concurrency: int = 5,
) -> List[Dict[str, Any]]:
    """Test whether subdomains accept CORS requests from other subdomains."""
    issues: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(concurrency)

    async def _test(target: str, origin: str) -> None:
        async with sem:
            for scheme in ["https", "http"]:
                try:
                    resp = await client.get(
                        f"{scheme}://{target}/",
                        headers={"Origin": f"{scheme}://{origin}"},
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower()

                    if acao == "*":
                        issues.append({
                            "target": target,
                            "origin_tested": origin,
                            "issue": "Wildcard CORS (Access-Control-Allow-Origin: *)",
                            "severity": "MEDIUM",
                            "allows_credentials": acac == "true",
                        })
                        return
                    if origin in acao and origin != target:
                        issues.append({
                            "target": target,
                            "origin_tested": origin,
                            "issue": f"Cross-subdomain CORS allows {origin}",
                            "severity": "HIGH" if acac == "true" else "MEDIUM",
                            "allows_credentials": acac == "true",
                        })
                        return
                except Exception:
                    continue

    # Test each live subdomain against a few other subdomains as origins
    tasks = []
    for i, target in enumerate(live_subdomains[:20]):
        # Test with main domain
        tasks.append(_test(target, domain))
        # Test with other subdomains
        for origin in live_subdomains[:5]:
            if origin != target:
                tasks.append(_test(target, origin))
        # Test with a fake subdomain to check for reflection
        tasks.append(_test(target, f"evil.{domain}"))
        tasks.append(_test(target, "attacker.com"))

    await asyncio.gather(*tasks)
    return issues


# ---------- Orchestrator ----------

async def run_subdomain_discovery(domain: str) -> SubdomainResult:
    """Run full subdomain discovery pipeline."""
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc or domain
    domain = domain.split(":")[0]

    result = SubdomainResult(domain=domain)

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=True,
        headers={"User-Agent": "AASE-SubdomainDiscovery/1.0"},
    ) as client:
        # Step 1: Discover subdomains from crt.sh
        try:
            crtsh_subs = await fetch_crtsh_subdomains(domain, client)
        except Exception as exc:
            result.errors.append(f"crt.sh: {str(exc)}")
            crtsh_subs = []

        # Step 2: DNS resolve all discovered subdomains
        if crtsh_subs:
            dns_results = await dns_resolve_subdomains(crtsh_subs)
        else:
            dns_results = {}

        # Step 3: HTTP probe live subdomains
        live_subs = [s for s, ip in dns_results.items() if ip is not None]
        if live_subs:
            probe_results = await probe_subdomains(live_subs, client)
        else:
            probe_results = {}

        # Build SubdomainInfo objects
        for subdomain in crtsh_subs:
            ip = dns_results.get(subdomain)
            probe = probe_results.get(subdomain, {})
            info = SubdomainInfo(
                subdomain=subdomain,
                source="crtsh",
                is_live=ip is not None and probe.get("status") is not None,
                ip_address=ip,
                http_status=probe.get("status"),
                server_header=probe.get("server"),
            )
            result.subdomains.append(info)

        result.live_count = sum(1 for s in result.subdomains if s.is_live)

        # Step 4: Cross-subdomain CORS testing on live subdomains
        live_subdomain_names = [s.subdomain for s in result.subdomains if s.is_live]
        if live_subdomain_names:
            try:
                cors_issues = await test_cross_subdomain_cors(
                    domain, live_subdomain_names, client,
                )
                result.cors_issues = cors_issues
                # Mark affected subdomains
                cors_targets = {issue["target"] for issue in cors_issues}
                for info in result.subdomains:
                    if info.subdomain in cors_targets:
                        info.cors_misconfigured = True
                        matching = [i for i in cors_issues if i["target"] == info.subdomain]
                        if matching:
                            info.cors_details = matching[0]["issue"]
            except Exception as exc:
                result.errors.append(f"CORS testing: {str(exc)}")

    return result
