import random
import time
import httpx
from typing import Dict

# Common modern web browsers
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

class ShadowRunnerWAF:
    def __init__(self):
        self.is_evasion_active = False
        self.forbidden_count = 0
        self.threshold = 3 
        
    def analyze_response(self, status_code: int):
        """Monitors for WAF blocks (403/406/429) to trigger Stealth Mode dynamically."""
        if status_code in [403, 406, 429]:
            self.forbidden_count += 1
            if self.forbidden_count >= self.threshold and not self.is_evasion_active:
                self.is_evasion_active = True
                
    def get_evasion_headers(self, original_headers: dict) -> dict:
        """Rotates User-Agents and injects evasion headers to mask bot signatures."""
        headers = dict(original_headers)
        if self.is_evasion_active:
            # Spoof common browser UAs
            headers["User-Agent"] = random.choice(USER_AGENTS)
            headers["Accept-Language"] = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9"])
            # Spoof real traffic
            headers.pop("httpx", None) 
            headers.pop("python-requests", None)
            # True-Client IP spoofing
            fake_ip = f"{random.randint(11,250)}.{random.randint(1,250)}.{random.randint(1,250)}.{random.randint(1,250)}"
            headers["X-Forwarded-For"] = fake_ip
            headers["X-Real-IP"] = fake_ip
        return headers

    async def apply_jitter(self, base_rate_limit: float):
        """Adds randomized delay jitter to defeat strict heuristic rate limiters (e.g. AWS WAF rate-based rules)"""
        import asyncio
        if self.is_evasion_active:
            # 50% to 150% variance of normal sleep duration 
            delay = (1.0 / max(0.1, base_rate_limit)) * random.uniform(0.5, 1.5)
            await asyncio.sleep(delay)
