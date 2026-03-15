import httpx
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("aase.auto_login")

async def execute_auto_login(login_url: str, username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Executes a pre-scan login sequence to harvest session tokens.
    Attempts common JSON and form-encoded payloads.
    Returns a dictionary with 'bearer', 'cookies', or 'headers' containing the harvested auth state.
    """
    logger.info(f"Attempting auto-login to {login_url} as {username}")

    payloads_to_try = [
        # Standard JSON
        {"json": {"username": username, "password": password}},
        {"json": {"email": username, "password": password}},
        # Form Data
        {"data": {"username": username, "password": password}},
        {"data": {"email": username, "password": password}},
    ]

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        for payload_kwargs in payloads_to_try:
            try:
                resp = await client.post(login_url, **payload_kwargs)
                if resp.status_code < 400:
                    auth_state = {}
                    
                    # 1. Harvest Cookies
                    if resp.cookies:
                        auth_state["cookies"] = dict(resp.cookies)
                    
                    # 2. Harvest Bearer/JWT from JSON response
                    try:
                        body_json = resp.json()
                        if isinstance(body_json, dict):
                            # Look for common token keys
                            for key in ["token", "access_token", "jwt", "sessionToken"]:
                                if key in body_json and isinstance(body_json[key], str):
                                    auth_state["bearer"] = body_json[key]
                                    break
                    except Exception:
                        pass # Not JSON
                    
                    # 3. Harvest Authorization Header if returned (rare but happens)
                    if "Authorization" in resp.headers:
                        auth_str = resp.headers["Authorization"]
                        if auth_str.lower().startswith("bearer "):
                            auth_state["bearer"] = auth_str[7:].strip()
                        else:
                            auth_state["headers"] = {"Authorization": auth_str}

                    if auth_state:
                         logger.info(f"Successfully harvested auth state: {list(auth_state.keys())}")
                         return auth_state
            except Exception as e:
                logger.debug(f"Auto-login attempt failed for {payload_kwargs}: {e}")

    logger.warning("Auto-login exhausted all attempts without harvesting a token.")
    return None
