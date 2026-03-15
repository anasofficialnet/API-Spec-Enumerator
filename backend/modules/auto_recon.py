from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

try:
    from main import RequestRecord
except ImportError:
    from backend.main import RequestRecord


DOC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs.yaml",
    "/v3/api-docs/swagger-config",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/swagger-ui/index.html",
    "/docs",
    "/redoc",
    "/scalar",
    "/actuator/swagger-ui",
    "/actuator/scalar",
    "/api/schema",
    "/schema",
]
API_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/v4",
    "/v1",
    "/v2",
    "/v3",
    "/v4",
    "/graphql",
    "/graphql/",
    "/graphiql",
    "/api/graphiql",
    "/playground",
    "/api/playground",
    "/api/graphql",
    "/v1/graphql",
    "/api/internal",
    "/api/public",
    "/api/users",
    "/api/auth",
    "/auth/login",
    "/login",
    "/api/private",
    "/api/health",
    "/health",
    "/status",
]
JS_ASSET_RE = re.compile(r"""["'`](?P<asset>/(?:_next|static|assets?|dist|build|chunks?|js|scripts?)/[^"'`\s]+?\.(?:js|mjs|cjs|json|map))["'`]""", re.IGNORECASE)
HTML_LINK_RE = re.compile(r"""(?:href|src|action)=["'](?P<value>[^"'#]+)["']""", re.IGNORECASE)
JS_ROUTE_RE = re.compile(
    r"""(?:(?:fetch|axios\.(?:get|post|put|patch|delete)|axios|request|client\.(?:get|post|put|patch|delete)|new\s+URL)\s*\(\s*(?P<quote>["'`])(?P<fn>[^"'`]+)(?P=quote))|(?P<plain>["'`]/(?:api|graphql|v[1-9]|swagger|openapi)[^"'`\s)]*["'`])""",
    re.IGNORECASE,
)
SOURCE_MAP_REF_RE = re.compile(r"(?://[#@]\s*sourceMappingURL=|/\*[#@]\s*sourceMappingURL=)(?P<value>[^\s*]+)", re.IGNORECASE)
PATH_RE = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/\-{}]+")
PATH_PARAM_RE = re.compile(r"\{[^}]+\}")
JS_TEMPLATE_SEGMENT_RE = re.compile(r"\$\{[^}]+\}")
COLON_PARAM_SEGMENT_RE = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
SOURCE_FILE_ROUTE_RE = re.compile(r"(?:^|/)(?:src/)?(?:app|pages)/(api/[^?#]+?)(?:/(?:route|page)|\.(?:[jt]sx?))$", re.IGNORECASE)
SOURCE_STATUS_DEFAULTS = {
    "seed_probe": "guessed",
    "crawl": "derived",
    "response_link": "derived",
    "spec": "derived",
}


@dataclass
class ReconNode:
    candidate: str
    depth: int
    source: str
    discovery_status: Optional[str] = None


def _sample_json_body(fields: List[str]) -> Optional[bytes]:
    if not fields:
        return None
    body: Dict[str, Any] = {}
    for field_name in fields[:12]:
        cursor = body
        parts = [part for part in field_name.split(".") if part]
        if not parts:
            continue
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = "aase-recon"
    return json.dumps(body).encode("utf-8")


class AutoReconEngine:
    def __init__(
        self,
        target_url: str,
        max_depth: int = 4,
        max_requests: int = 160,
        concurrency: int = 8,
        timeout: float = 5.0,
    ) -> None:
        parsed = urlparse(target_url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        root_path = parsed.path if parsed.netloc else "/"

        self.target_url = f"{scheme}://{netloc}{root_path or '/'}"
        self.base_url = f"{scheme}://{netloc}"
        self.base_path = root_path if parsed.netloc else "/"
        self.host = netloc
        self.max_depth = max(1, max_depth)
        self.max_requests = max(20, max_requests)
        self.concurrency = max(1, concurrency)
        self.timeout = timeout

        self.records: List[RequestRecord] = []
        self._seen_urls: set[str] = set()
        self._queued_urls: set[str] = set()
        self._synthetic_keys: set[tuple[str, str]] = set()
        self.seed_statuses: Dict[str, str] = {}

    def _seed_paths(self) -> List[str]:
        seeds = list(dict.fromkeys([self.base_path or "/", *API_PATHS, *DOC_PATHS]))
        return seeds

    def _default_status_for_source(self, source: str) -> Optional[str]:
        return SOURCE_STATUS_DEFAULTS.get(source)

    def _sanitize_candidate(self, candidate: str) -> str:
        cleaned = candidate.strip().strip("\"'`")
        cleaned = JS_TEMPLATE_SEGMENT_RE.sub("1", cleaned)
        cleaned = PATH_PARAM_RE.sub("1", cleaned)
        cleaned = COLON_PARAM_SEGMENT_RE.sub("1", cleaned)
        cleaned = cleaned.rstrip("),;]}").strip("\"'`")
        return cleaned

    def _resolve_candidate(self, current_url: str, candidate: str) -> Optional[str]:
        if not candidate:
            return None
        absolute = urljoin(current_url, self._sanitize_candidate(candidate))
        parsed = urlparse(absolute)
        if not parsed.scheme or not parsed.netloc:
            return None
        if parsed.netloc != self.host:
            return None
        normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
        return normalized

    async def _enqueue(
        self,
        queue: asyncio.Queue[ReconNode],
        current_url: str,
        candidate: str,
        depth: int,
        source: str,
        discovery_status: Optional[str] = None,
    ) -> None:
        if depth > self.max_depth:
            return
        url = self._resolve_candidate(current_url, candidate)
        if not url or url in self._queued_urls or len(self._queued_urls) >= self.max_requests * 4:
            return
        self._queued_urls.add(url)
        await queue.put(
            ReconNode(
                candidate=url,
                depth=depth,
                source=source,
                discovery_status=discovery_status or self._default_status_for_source(source),
            )
        )

    def _record(self, url: str, response: httpx.Response, source: str, discovery_status: Optional[str]) -> None:
        self.records.append(
            RequestRecord(
                method="GET",
                url=url,
                headers={
                    "Accept": "application/json, text/html, */*",
                    "User-Agent": "AASE-AutoRecon/2.0",
                },
                body=None,
                status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.content,
                source=source,
                discovery_status=discovery_status,
            )
        )

    def _record_spec_endpoint(self, method: str, path: str, body_fields: List[str]) -> None:
        materialized_path = PATH_PARAM_RE.sub("1", path)
        url = urljoin(self.base_url, materialized_path)
        key = (method.upper(), url)
        if key in self._synthetic_keys:
            return
        self._synthetic_keys.add(key)
        headers = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "AASE-AutoRecon/2.0",
        }
        body = None
        if method.upper() in {"POST", "PUT", "PATCH"}:
            body = _sample_json_body(body_fields)
            if body is not None:
                headers["Content-Type"] = "application/json"
        self.records.append(
            RequestRecord(
                method=method.upper(),
                url=url,
                headers=headers,
                body=body,
                status=200,
                source="spec",
                discovery_status="derived",
            )
        )

    def _extract_json_candidates(self, payload: Any, current_url: str, found: set[str], depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(payload, str):
            url = self._resolve_candidate(current_url, payload)
            if url:
                found.add(url)
            for match in PATH_RE.findall(payload):
                url = self._resolve_candidate(current_url, match)
                if url:
                    found.add(url)
            return
        if isinstance(payload, dict):
            if isinstance(payload.get("urls"), list):
                for item in payload["urls"][:20]:
                    if isinstance(item, dict) and isinstance(item.get("url"), str):
                        url = self._resolve_candidate(current_url, item["url"])
                        if url:
                            found.add(url)
            for key, value in payload.items():
                if isinstance(value, str):
                    url = self._resolve_candidate(current_url, value)
                    if url:
                        found.add(url)
                    for match in PATH_RE.findall(value):
                        url = self._resolve_candidate(current_url, match)
                        if url:
                            found.add(url)
                elif isinstance(value, (dict, list)):
                    self._extract_json_candidates(value, current_url, found, depth + 1)
        elif isinstance(payload, list):
            for item in payload[:25]:
                self._extract_json_candidates(item, current_url, found, depth + 1)

    def _extract_js_candidates(self, text: str, current_url: str) -> List[str]:
        found: set[str] = set()
        for match in JS_ROUTE_RE.finditer(text):
            candidate = match.group("fn") or match.group("plain")
            if candidate:
                url = self._resolve_candidate(current_url, candidate)
                if url:
                    found.add(url)
        return sorted(found)

    def _extract_js_asset_candidates(self, text: str, current_url: str) -> List[str]:
        found: set[str] = set()
        for match in JS_ASSET_RE.finditer(text):
            url = self._resolve_candidate(current_url, match.group("asset"))
            if url:
                found.add(url)
        return sorted(found)

    def _extract_source_map_reference(self, text: str, current_url: str) -> Optional[str]:
        match = SOURCE_MAP_REF_RE.search(text)
        if not match:
            return None
        return self._resolve_candidate(current_url, match.group("value"))

    def _extract_source_file_candidates(self, source_path: str, current_url: str) -> List[str]:
        normalized = source_path.replace("\\", "/")
        match = SOURCE_FILE_ROUTE_RE.search(normalized)
        if not match:
            return []
        route_path = match.group(1).strip("/")
        if route_path.endswith("/route"):
            route_path = route_path[:-len("/route")]
        if route_path.endswith("/page"):
            route_path = route_path[:-len("/page")]
        url = self._resolve_candidate(current_url, "/" + route_path)
        return [url] if url else []

    def _extract_source_map_candidates(self, payload: Dict[str, Any], current_url: str) -> List[str]:
        found: set[str] = set()

        for source_path in payload.get("sources", [])[:200]:
            if isinstance(source_path, str):
                for candidate in self._extract_source_file_candidates(source_path, current_url):
                    found.add(candidate)

        for source_content in payload.get("sourcesContent", [])[:80]:
            if not isinstance(source_content, str):
                continue
            for candidate in self._extract_js_candidates(source_content[:150000], current_url):
                found.add(candidate)
            for candidate in self._extract_js_asset_candidates(source_content[:150000], current_url):
                found.add(candidate)
            for match in PATH_RE.findall(source_content[:150000]):
                resolved = self._resolve_candidate(current_url, match)
                if resolved:
                    found.add(resolved)

        return sorted(found)

    def _extract_html_candidates(self, text: str, current_url: str) -> List[str]:
        found: set[str] = set()
        for match in HTML_LINK_RE.finditer(text):
            url = self._resolve_candidate(current_url, match.group("value"))
            if url:
                found.add(url)
        for candidate in self._extract_js_candidates(text, current_url):
            found.add(candidate)
        return sorted(found)

    def _extract_robots_candidates(self, text: str, current_url: str) -> List[str]:
        found = set()
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key in {"allow", "disallow", "sitemap"}:
                url = self._resolve_candidate(current_url, value)
                if url:
                    found.add(url)
        return sorted(found)

    async def _extract_spec_candidates(
        self,
        queue: asyncio.Queue[ReconNode],
        current_url: str,
        body: bytes,
        content_type: str,
        depth: int,
    ) -> None:
        try:
            from backend.modules.shadow_api import parse_openapi_spec
        except ImportError:
            from modules.shadow_api import parse_openapi_spec

        fmt = "yaml" if "yaml" in content_type or current_url.endswith((".yaml", ".yml")) else "json"
        try:
            spec_endpoints = parse_openapi_spec(body, fmt)
        except Exception:
            return

        for endpoint in spec_endpoints:
            self._record_spec_endpoint(endpoint.method, endpoint.path, endpoint.request_body_fields)
            if endpoint.method == "GET":
                materialized_path = PATH_PARAM_RE.sub("1", endpoint.path)
                await self._enqueue(queue, current_url, materialized_path, depth + 1, "spec", "derived")

    async def _extract_candidates(
        self,
        queue: asyncio.Queue[ReconNode],
        url: str,
        response: httpx.Response,
        depth: int,
    ) -> None:
        response_link_candidates: set[str] = set()
        crawl_candidates: set[str] = set()
        location = response.headers.get("Location")
        if location:
            resolved = self._resolve_candidate(url, location)
            if resolved:
                response_link_candidates.add(resolved)

        content_type = (response.headers.get("Content-Type") or "").lower()
        body = response.content or b""
        body_limit = 150000 if url.endswith(".map") or "javascript" in content_type or "ecmascript" in content_type else 50000
        body_text = body.decode("utf-8", errors="ignore")[:body_limit]

        if "json" in content_type or url.endswith(".json"):
            try:
                payload = json.loads(body_text)
            except Exception:
                payload = None
            if payload is not None:
                is_source_map = url.endswith(".map") or (
                    isinstance(payload, dict) and "sourcesContent" in payload and "sources" in payload
                )
                target_candidates = crawl_candidates if is_source_map else response_link_candidates
                self._extract_json_candidates(payload, url, target_candidates)
                if is_source_map and isinstance(payload, dict):
                    for candidate in self._extract_source_map_candidates(payload, url):
                        crawl_candidates.add(candidate)
                if isinstance(payload, dict) and "paths" in payload:
                    await self._extract_spec_candidates(queue, url, body, content_type, depth)
        elif "html" in content_type or url.endswith((".html", ".htm")):
            for candidate in self._extract_html_candidates(body_text, url):
                crawl_candidates.add(candidate)
        elif "javascript" in content_type or "ecmascript" in content_type or url.endswith((".js", ".mjs", ".cjs")):
            for candidate in self._extract_js_candidates(body_text, url):
                crawl_candidates.add(candidate)
            for candidate in self._extract_js_asset_candidates(body_text, url):
                crawl_candidates.add(candidate)
            source_map_url = self._extract_source_map_reference(body_text, url)
            if source_map_url:
                crawl_candidates.add(source_map_url)
        elif "text/plain" in content_type and url.endswith("robots.txt"):
            for candidate in self._extract_robots_candidates(body_text, url):
                crawl_candidates.add(candidate)
        elif "xml" in content_type or url.endswith(".xml"):
            for match in re.findall(r"<loc>([^<]+)</loc>", body_text, flags=re.IGNORECASE):
                resolved = self._resolve_candidate(url, match)
                if resolved:
                    crawl_candidates.add(resolved)

        for candidate in sorted(crawl_candidates):
            await self._enqueue(queue, url, candidate, depth + 1, "crawl", "derived")
        for candidate in sorted(response_link_candidates):
            await self._enqueue(queue, url, candidate, depth + 1, "response_link", "derived")

    async def _fetch(self, client: httpx.AsyncClient, queue: asyncio.Queue[ReconNode], node: ReconNode) -> None:
        if len(self._seen_urls) >= self.max_requests:
            return
        url = node.candidate
        if url in self._seen_urls:
            return
        self._seen_urls.add(url)

        try:
            response = await client.get(url)
        except Exception:
            if node.source == "seed_probe":
                self.seed_statuses[url] = "failed"
            return

        if response.status_code == 404:
            if node.source == "seed_probe":
                self.seed_statuses[url] = "failed"
            return

        discovery_status = node.discovery_status or self._default_status_for_source(node.source)
        if node.source == "seed_probe":
            if response.status_code in {200, 401, 403}:
                discovery_status = "confirmed"
            else:
                discovery_status = discovery_status or "guessed"
            self.seed_statuses[url] = discovery_status

        self._record(url, response, node.source, discovery_status)

        if node.depth >= self.max_depth:
            return
        await self._extract_candidates(queue, url, response, node.depth)

    async def _worker(self, client: httpx.AsyncClient, queue: asyncio.Queue[ReconNode]) -> None:
        while True:
            node = await queue.get()
            try:
                if node.candidate == "__STOP__":
                    return
                await self._fetch(client, queue, node)
            finally:
                queue.task_done()

    async def execute_recon(self) -> List[RequestRecord]:
        queue: asyncio.Queue[ReconNode] = asyncio.Queue()
        for seed in self._seed_paths():
            await self._enqueue(queue, self.base_url, seed, 0, "seed_probe", "guessed")

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "AASE-AutoRecon/2.0"},
        ) as client:
            workers = [asyncio.create_task(self._worker(client, queue)) for _ in range(self.concurrency)]
            await queue.join()
            for _ in workers:
                await queue.put(ReconNode(candidate="__STOP__", depth=0, source="control"))
            await asyncio.gather(*workers, return_exceptions=True)

        return self.records
