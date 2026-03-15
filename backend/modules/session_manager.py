from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


TOKEN_KEYS = (
    "token",
    "access_token",
    "accessToken",
    "jwt",
    "sessionToken",
    "id_token",
)
CSRF_COOKIE_NAMES = ("csrftoken", "csrf", "xsrf-token", "x-csrf-token")
CSRF_HEADER_NAMES = (
    "X-CSRF-Token",
    "X-CSRFToken",
    "X-XSRF-TOKEN",
)
CSRF_FIELD_RE = re.compile(
    r"""(?:name|id)=["'](?P<name>csrf(?:_token)?|authenticity_token|_csrf)["'][^>]*value=["'](?P<value>[^"']+)["']""",
    re.IGNORECASE,
)
CSRF_META_RE = re.compile(
    r"""<meta[^>]+name=["'](?P<name>csrf-token|xsrf-token)["'][^>]+content=["'](?P<value>[^"']+)["']""",
    re.IGNORECASE,
)


def _extract_tokens_from_json(data: Any, found: Dict[str, str]) -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str) and key in TOKEN_KEYS:
                found[key] = value
            elif isinstance(value, (dict, list)):
                _extract_tokens_from_json(value, found)
    elif isinstance(data, list):
        for item in data[:10]:
            _extract_tokens_from_json(item, found)


def _merge_cookie_header(headers: Dict[str, str], cookies: Dict[str, str]) -> None:
    if not cookies:
        return
    cookie_str = "; ".join(f"{key}={value}" for key, value in cookies.items())
    existing = headers.get("Cookie")
    headers["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str


@dataclass
class SessionAuthState:
    bearer: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    csrf: Dict[str, str] = field(default_factory=dict)
    last_login_at: float = 0.0
    login_attempts: int = 0


class AuthSessionManager:
    def __init__(
        self,
        base_auth: Optional[Dict[str, Any]] = None,
        login_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.state = SessionAuthState()
        self.login_config = login_config or None
        self._lock = asyncio.Lock()
        if base_auth:
            self.seed(base_auth)

    def seed(self, auth: Dict[str, Any]) -> None:
        bearer = auth.get("bearer")
        if isinstance(bearer, str) and bearer:
            self.state.bearer = bearer
        headers = auth.get("headers") or {}
        if isinstance(headers, dict):
            for key, value in headers.items():
                if isinstance(key, str) and isinstance(value, str):
                    self.state.headers[key] = value
        cookies = auth.get("cookies") or {}
        if isinstance(cookies, dict):
            for key, value in cookies.items():
                if isinstance(key, str) and isinstance(value, str):
                    self.state.cookies[key] = value
                    if key.lower() in CSRF_COOKIE_NAMES:
                        self.state.csrf[key] = value

    def has_auth(self) -> bool:
        return bool(self.state.bearer or self.state.headers or self.state.cookies)

    def apply(self, original_headers: Dict[str, str]) -> Dict[str, str]:
        headers = dict(original_headers)
        if self.state.bearer:
            headers["Authorization"] = f"Bearer {self.state.bearer}"
        for key, value in self.state.headers.items():
            headers[key] = value
        _merge_cookie_header(headers, self.state.cookies)

        csrf_value = self._preferred_csrf_value()
        if csrf_value:
            for header_name in CSRF_HEADER_NAMES:
                headers.setdefault(header_name, csrf_value)
        return headers

    def capture_response(self, response: Any) -> None:
        try:
            for key, value in response.cookies.items():
                self.state.cookies[key] = value
                if key.lower() in CSRF_COOKIE_NAMES:
                    self.state.csrf[key] = value
        except Exception:
            pass

        auth_header = response.headers.get("Authorization")
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                self.state.bearer = auth_header[7:].strip()
            else:
                self.state.headers["Authorization"] = auth_header

        content_type = (response.headers.get("Content-Type") or "").lower()
        if "json" in content_type:
            try:
                payload = response.json()
            except Exception:
                payload = None
            if payload is not None:
                found_tokens: Dict[str, str] = {}
                _extract_tokens_from_json(payload, found_tokens)
                for key in TOKEN_KEYS:
                    if key in found_tokens:
                        self.state.bearer = found_tokens[key]
                        break
                self._capture_csrf_from_json(payload)

        try:
            body_text = response.text[:20000]
        except Exception:
            body_text = ""
        if body_text:
            self._capture_csrf_from_text(body_text)

    async def bootstrap(self, client: Any) -> bool:
        if not self.login_config:
            return self.has_auth()
        async with self._lock:
            return await self._perform_login(client)

    async def refresh(self, client: Any) -> bool:
        if not self.login_config:
            return False
        async with self._lock:
            return await self._perform_login(client)

    async def maybe_refresh(self, client: Any, response: Any) -> bool:
        if not self.login_config or response.status_code not in (401, 403):
            return False
        return await self.refresh(client)

    async def _perform_login(self, client: Any) -> bool:
        login_url = str(self.login_config.get("login_url") or "").strip()
        username = str(self.login_config.get("username") or "").strip()
        password = str(self.login_config.get("password") or "").strip()
        if not login_url or not username or not password:
            return False

        self.state.login_attempts += 1
        await self._prime_login_page(client, login_url)

        for kwargs in self._candidate_payloads(username, password):
            request_headers = self.apply(kwargs.pop("headers", {}))
            try:
                response = await client.post(login_url, headers=request_headers, **kwargs)
            except Exception:
                continue

            self.capture_response(response)
            if response.status_code < 400 and self.has_auth():
                self.state.last_login_at = time.time()
                return True
        return self.has_auth()

    async def _prime_login_page(self, client: Any, login_url: str) -> None:
        try:
            response = await client.get(login_url, headers=self.apply({}))
        except Exception:
            return
        self.capture_response(response)

    def _candidate_payloads(self, username: str, password: str) -> list[Dict[str, Any]]:
        csrf_fields = self._csrf_form_fields()
        csrf_value = self._preferred_csrf_value()
        headers = {}
        if csrf_value:
            for name in CSRF_HEADER_NAMES:
                headers[name] = csrf_value

        base_forms = [
            {"username": username, "password": password},
            {"email": username, "password": password},
            {"user": username, "password": password},
            {"identifier": username, "password": password},
            {
                "grant_type": "password",
                "username": username,
                "password": password,
            },
        ]
        for form in base_forms:
            form_payload = dict(form)
            form_payload.update(csrf_fields)
            yield {"json": form_payload, "headers": dict(headers)}
            yield {"data": form_payload, "headers": dict(headers)}

    def _csrf_form_fields(self) -> Dict[str, str]:
        value = self._preferred_csrf_value()
        if not value:
            return {}
        fields = {"csrf_token": value}
        for name in self.state.csrf.keys():
            fields.setdefault(name, value)
        return fields

    def _preferred_csrf_value(self) -> Optional[str]:
        if not self.state.csrf:
            return None
        for name in ("csrf_token", "csrf", "xsrf-token", "csrftoken"):
            if name in self.state.csrf:
                return self.state.csrf[name]
        return next(iter(self.state.csrf.values()))

    def _capture_csrf_from_json(self, payload: Any) -> None:
        if isinstance(payload, dict):
            for key, value in payload.items():
                if not isinstance(value, str):
                    continue
                if "csrf" in key.lower() or "xsrf" in key.lower():
                    self.state.csrf[key] = value

    def _capture_csrf_from_text(self, text: str) -> None:
        for pattern in (CSRF_FIELD_RE, CSRF_META_RE):
            for match in pattern.finditer(text):
                self.state.csrf[match.group("name")] = match.group("value")

