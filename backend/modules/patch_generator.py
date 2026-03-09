"""
AASE Module 6: Auto-Remediation Patch Generator
================================================
Generates code-level fixes and WAF rules for discovered vulnerabilities.
"""
from __future__ import annotations
import textwrap
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class PatchSuggestion:
    finding_id: str
    finding_type: str
    severity: str
    language: str
    title: str
    description: str
    code: str
    endpoint: str = ""
    method: str = ""


def _p(finding, ftype, lang, title, desc, code, ep=None):
    return PatchSuggestion(
        finding_id=finding.get("id","?"), finding_type=ftype,
        severity=finding.get("severity","MEDIUM"), language=lang,
        title=title, description=desc, code=textwrap.dedent(code),
        endpoint=ep or finding.get("endpoint","?"),
        method=finding.get("method",""),
    )


def _patch_for_sqli(f):
    ep = f.get("endpoint","?")
    return [
        _p(f,"SQLi","python","Parameterized Query",
           "Use parameterized queries instead of string concatenation.",
           f'''\
           from sqlalchemy import text
           @app.get("{ep}")
           async def get_resource(rid: str, db=Depends(get_db)):
               stmt = text("SELECT * FROM resources WHERE id = :rid")
               return db.execute(stmt, {{"rid": rid}}).fetchone()
           ''', ep),
        _p(f,"SQLi","modsecurity","WAF Rule (ModSecurity)",
           "Block SQL injection patterns at WAF level.",
           '''\
           SecRule ARGS "@rx (?i)(?:union\\s+select|or\\s+1=1|'\\s*--)" \\
               "id:100001,phase:2,deny,msg:'SQLi blocked',severity:'CRITICAL'"
           ''', ep),
    ]


def _patch_for_xss(f):
    ep = f.get("endpoint","?")
    return [_p(f,"XSS","python","CSP Headers + Output Encoding",
        "Set Content-Security-Policy and encode user input on output.",
        f'''\
        from markupsafe import escape
        @app.middleware("http")
        async def security_headers(request, call_next):
            response = await call_next(request)
            response.headers["Content-Security-Policy"] = "default-src 'self'"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response
        @app.get("{ep}")
        async def render(user_input: str):
            return {{"content": str(escape(user_input))}}
        ''', ep)]


def _patch_for_cors(f):
    return [_p(f,"CORS","python","Restrictive CORS",
        "Replace wildcard origins with explicit allowlist.",
        '''\
        ALLOWED_ORIGINS = ["https://your-frontend.com"]
        app.add_middleware(CORSMiddleware,
            allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
            allow_methods=["GET","POST","PUT","DELETE"],
            allow_headers=["Authorization","Content-Type"])
        ''')]


def _patch_for_auth(f):
    ep = f.get("endpoint","?")
    return [_p(f,"Auth Bypass","python","Auth Middleware Guard",
        "Enforce authentication on protected routes.",
        f'''\
        async def require_auth(authorization: str = Header(...)):
            if not authorization.startswith("Bearer "):
                raise HTTPException(401, "Missing token")
            user = await verify_token(authorization[7:])
            if not user: raise HTTPException(401, "Invalid token")
            return user
        @app.get("{ep}", dependencies=[Depends(require_auth)])
        async def protected(user=Depends(require_auth)):
            return {{"user": user.id}}
        ''', ep)]


def _patch_for_bola(f):
    ep = f.get("endpoint","?")
    return [_p(f,"BOLA/IDOR","python","Object-Level Authorization",
        "Verify resource ownership before granting access.",
        f'''\
        async def verify_ownership(rid: str, user=Depends(require_auth), db=Depends(get_db)):
            resource = await db.get(rid)
            if not resource: raise HTTPException(404)
            if resource.owner_id != user.id: raise HTTPException(403, "Access denied")
            return resource
        @app.get("{ep}")
        async def get_resource(resource=Depends(verify_ownership)):
            return resource
        ''', ep)]


def _patch_for_race(f):
    ep = f.get("endpoint","?")
    return [_p(f,"Race Condition","python","DB Locking + Idempotency Key",
        "Use SELECT FOR UPDATE and idempotency keys.",
        f'''\
        @app.post("{ep}")
        async def process(body: Model, idem_key: str = Header(..., alias="Idempotency-Key"),
                          db=Depends(get_db)):
            existing = await db.execute(select(Tx).where(Tx.idem_key == idem_key))
            if existing.scalar(): return {{"status": "already_processed"}}
            async with db.begin():
                acct = (await db.execute(select(Account).where(Account.id == body.acct_id)
                    .with_for_update())).scalar_one()
                if acct.balance < body.amount: raise HTTPException(400, "Insufficient")
                acct.balance -= body.amount
            return {{"status": "success"}}
        ''', ep)]


def _patch_for_stateful(f):
    return [_p(f,"Business Logic","python","State Machine Validation",
        "Enforce workflow step ordering server-side.",
        '''\
        from enum import Enum
        class State(str, Enum):
            CREATED="created"; CONFIRMED="confirmed"; PAID="paid"
        TRANSITIONS = {State.CREATED:[State.CONFIRMED], State.CONFIRMED:[State.PAID]}
        async def transition(order_id, new_state, db=Depends(get_db)):
            order = await db.get(order_id)
            if new_state not in TRANSITIONS.get(order.state, []):
                raise HTTPException(409, f"Cannot go from {order.state} to {new_state}")
            order.state = new_state; await db.save(order)
        ''')]


def _patch_for_mutation(f):
    return [_p(f,"Input Validation","python","Strict Pydantic Schema",
        "Reject unexpected fields and enforce type constraints.",
        '''\
        from pydantic import BaseModel, Field
        class StrictInput(BaseModel):
            class Config:
                extra = "forbid"
            name: str = Field(..., max_length=200)
            amount: float = Field(..., ge=0, le=1000000)
        ''')]


def _patch_for_graphql(f):
    return [_p(f,"GraphQL","python","Query Depth Limiting",
        "Prevent DoS via deeply nested GraphQL queries.",
        '''\
        MAX_DEPTH = 10
        class DepthLimitRule(ASTValidationRule):
            def __init__(self, ctx):
                super().__init__(ctx)
                self.depth = 0
            def enter_field(self, *a):
                self.depth += 1
                if self.depth > MAX_DEPTH:
                    self.report_error("Too deep")
            def leave_field(self, *a):
                self.depth -= 1
        ''')]


_GENERATORS = {
    "sqli": _patch_for_sqli, "xss": _patch_for_xss, "cors": _patch_for_cors,
    "permissive cors": _patch_for_cors,
    "auth_bypass": _patch_for_auth, "auth bypass": _patch_for_auth,
    "possible auth bypass": _patch_for_auth,
    "bola": _patch_for_bola, "bola/idor": _patch_for_bola, "idor": _patch_for_bola,
    "race": _patch_for_race, "race condition": _patch_for_race,
    "race condition (toctou)": _patch_for_race,
    "stateful": _patch_for_stateful, "business logic": _patch_for_stateful,
    "business logic bypass (skip-step)": _patch_for_stateful,
    "business logic bypass (reverse order)": _patch_for_stateful,
    "replay/idempotency issue": _patch_for_race,
    "mutation": _patch_for_mutation, "json mutation": _patch_for_mutation,
    "mass assignment": _patch_for_mutation, "prototype pollution": _patch_for_mutation,
    "graphql": _patch_for_graphql, "verbose error": _patch_for_mutation,
}


def generate_patches(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    all_patches = []
    for finding in findings:
        ft = finding.get("type", "").lower()
        gen = _GENERATORS.get(ft)
        if not gen:
            for key, g in _GENERATORS.items():
                if key in ft:
                    gen = g
                    break
        if gen:
            for patch in gen(finding):
                all_patches.append({
                    "finding_id": patch.finding_id, "finding_type": patch.finding_type,
                    "severity": patch.severity, "language": patch.language,
                    "title": patch.title, "description": patch.description,
                    "code": patch.code, "endpoint": patch.endpoint, "method": patch.method,
                })
    return all_patches
