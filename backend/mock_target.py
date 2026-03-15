from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Any, Dict, Optional

import httpx
from fastapi import Body, Cookie, FastAPI, Form, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse


app = FastAPI(title="AASE Safe Mock Target", version="0.2.0")

FLAKY_CALLS = 0
CALLBACK_URL_RE = re.compile(r"https?://[^\s\"']+/api/oast/[A-Za-z0-9]+")


def _check_auth(authorization: Optional[str], session: Optional[str]) -> None:
    if authorization == "Bearer mock-jwt" or session == "mock-session":
        return
    raise HTTPException(status_code=401, detail="Authentication required")


def _extract_callback_url(payload: Any) -> Optional[str]:
    if isinstance(payload, str):
        match = CALLBACK_URL_RE.search(payload)
        return match.group(0) if match else None
    if isinstance(payload, dict):
        for value in payload.values():
            callback = _extract_callback_url(value)
            if callback:
                return callback
    if isinstance(payload, list):
        for item in payload:
            callback = _extract_callback_url(item)
            if callback:
                return callback
    return None


async def _trigger_callback(callback_url: str) -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.get(callback_url, headers={"User-Agent": "AASE-MockTarget/1.0"})


@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": "aase-mock-target",
        "status": "ok",
        "links": {
            "discovery": "/api/discovery",
            "docs": "/openapi.json",
            "login": "/auth/login",
            "graphql": "/graphql",
        },
    }


@app.get("/api/discovery")
async def discovery() -> Dict[str, Any]:
    return {
        "resources": [
            "/api/users",
            "/api/users/1",
            "/api/orders/ord-1001",
            "/api/cors",
            "/api/private",
            "/api/flaky",
            "/api/slow",
        ],
        "links": {
            "self": "/api/discovery",
            "next": "/api/users/2",
            "workflow": ["/api/cart", "/api/checkout"],
        },
    }


@app.get("/api/users")
async def list_users(aase_probe: Optional[str] = None) -> Dict[str, Any]:
    payload = {
        "items": [
            {"id": 1, "name": "Alice", "href": "/api/users/1"},
            {"id": 2, "name": "Bob", "href": "/api/users/2"},
        ],
        "orders": ["/api/orders/ord-1001"],
    }
    if aase_probe:
        payload["debug_hint"] = "probe-observed"
    return payload


@app.get("/api/users/{user_id}")
async def get_user(user_id: int) -> Dict[str, Any]:
    return {
        "id": user_id,
        "name": "Alice" if user_id == 1 else "Bob",
        "profile": "/api/private",
        "latest_order": "/api/orders/ord-1001",
    }


@app.get("/api/orders/{order_id}")
async def get_order(order_id: str) -> Dict[str, Any]:
    return {
        "order_id": order_id,
        "status": "created",
        "links": {"checkout": "/api/checkout", "transfer": "/api/transfer"},
    }


@app.get("/api/cart")
async def cart() -> Dict[str, Any]:
    return {"cart_id": "cart-1", "next": "/api/checkout"}


@app.post("/api/checkout")
async def checkout(payload: Dict[str, Any] = Body(default_factory=dict)) -> Dict[str, Any]:
    return {"checkout_id": "chk-1", "accepted": True, "payload": payload}


@app.get("/api/cors")
async def cors_probe(origin: Optional[str] = Header(default=None)) -> JSONResponse:
    response = JSONResponse({"ok": True})
    if origin:
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(response: Response) -> str:
    response.set_cookie("csrftoken", "mock-csrf")
    return """
    <html>
      <head><meta name="csrf-token" content="mock-csrf" /></head>
      <body>
        <form method="post" action="/auth/login">
          <input type="hidden" name="csrf_token" value="mock-csrf" />
          <input type="text" name="username" />
          <input type="password" name="password" />
        </form>
      </body>
    </html>
    """


@app.post("/auth/login")
async def login(
    request: Request,
    response: Response,
    username: Optional[str] = Form(default=None),
    email: Optional[str] = Form(default=None),
    password: Optional[str] = Form(default=None),
    csrf_token: Optional[str] = Form(default=None),
    x_csrf_token: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
    x_csrf_alt: Optional[str] = Header(default=None, alias="X-CSRFToken"),
    csrf_cookie: Optional[str] = Cookie(default=None, alias="csrftoken"),
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    if request.headers.get("content-type", "").lower().startswith("application/json"):
        try:
            payload = await request.json()
        except Exception:
            payload = {}
    user_value = username or email or payload.get("username") or payload.get("email")
    pass_value = password or payload.get("password")
    csrf_value = csrf_token or x_csrf_token or x_csrf_alt or payload.get("csrf_token") or payload.get("csrf")

    if csrf_cookie and csrf_value != csrf_cookie:
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
    if user_value == "demo" and pass_value == "demo":
        response.set_cookie("session", "mock-session", httponly=True)
        response.set_cookie("csrftoken", "rotated-csrf")
        return {"token": "mock-jwt", "csrf": "rotated-csrf", "user": {"name": "demo"}}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/private")
async def private_data(
    authorization: Optional[str] = Header(default=None),
    session: Optional[str] = Cookie(default=None),
) -> Dict[str, Any]:
    _check_auth(authorization, session)
    return {"secret": "local-only", "scope": "demo", "related": "/api/orders/ord-1001"}


@app.post("/api/items")
async def create_item(payload: Dict[str, Any]) -> Dict[str, Any]:
    callback_url = _extract_callback_url(payload)
    if callback_url:
        await _trigger_callback(callback_url)
    created = dict(payload)
    created["id"] = str(uuid.uuid4())
    return created


@app.get("/api/flaky")
async def flaky() -> JSONResponse:
    global FLAKY_CALLS
    FLAKY_CALLS += 1
    if FLAKY_CALLS <= 2:
        return JSONResponse({"ok": False, "attempt": FLAKY_CALLS}, status_code=503)
    return JSONResponse({"ok": True, "attempt": FLAKY_CALLS})


@app.get("/api/slow")
async def slow() -> Dict[str, Any]:
    await asyncio.sleep(1.0)
    return {"slow": True}


@app.post("/api/transfer")
async def transfer(payload: Dict[str, Any]) -> Dict[str, Any]:
    amount = payload.get("amount", 0)
    return {
        "transfer_id": str(uuid.uuid4()),
        "accepted": True,
        "amount": amount,
    }


@app.post("/graphql")
async def graphql(payload: Any = Body(...)) -> Any:
    if isinstance(payload, dict):
        query = str(payload.get("query", ""))
        if "__schema" in query:
            return {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        if "nonExistentField12345" in query:
            return {"errors": [{"message": "Cannot query field 'nonExistentField12345'. Did you mean 'health'?"}]}
        return {"data": {"health": "ok", "__typename": "Query"}}
    if isinstance(payload, list):
        return [{"data": {"__typename": "Query"}} for _ in payload]
    raise HTTPException(status_code=400, detail="Invalid GraphQL payload")


@app.get("/openapi.json")
async def openapi_doc() -> Dict[str, Any]:
    return {
        "openapi": "3.0.0",
        "info": {"title": "AASE Mock Target", "version": "2.0.0"},
        "paths": {
            "/api/discovery": {"get": {"summary": "Discovery root"}},
            "/api/users": {"get": {"summary": "List users"}},
            "/api/users/{user_id}": {"get": {"summary": "Get user"}},
            "/api/orders/{order_id}": {"get": {"summary": "Get order"}},
            "/api/private": {"get": {"summary": "Private data"}},
            "/api/cors": {"get": {"summary": "CORS test"}},
            "/api/flaky": {"get": {"summary": "Retry test"}},
            "/api/slow": {"get": {"summary": "Slow endpoint"}},
            "/api/items": {
                "post": {
                    "summary": "Create item",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "amount": {"type": "number"},
                                        "callback": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                }
            },
            "/api/transfer": {
                "post": {
                    "summary": "Transfer funds",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "amount": {"type": "number"},
                                    },
                                }
                            }
                        }
                    },
                }
            },
            "/graphql": {"post": {"summary": "GraphQL endpoint"}},
        },
    }


@app.get("/swagger.json")
async def swagger_doc() -> Dict[str, Any]:
    return await openapi_doc()

