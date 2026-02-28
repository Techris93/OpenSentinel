"""
Security Middleware
Rate limiting (global + per-endpoint), security headers, request audit logging,
and anti-automation protection.

OWASP API Security Coverage:
  API4 — Unrestricted Resource Consumption: Global + endpoint-specific rate limits
  API6 — Unrestricted Business Flows: Anti-automation on sensitive endpoints
  API8 — Security Misconfiguration: Security headers, CORS, HSTS
"""
import os
import time
from typing import Dict, Any, Optional
from collections import defaultdict


def get_security_config() -> Dict[str, Any]:
    """Load security configuration from environment."""
    return {
        "api_key": os.getenv("OPENSENTINEL_API_KEY", "dev-key-opensentinel-2024"),
        "rate_limit": int(os.getenv("RATE_LIMIT", "60")),
        "rate_window": int(os.getenv("RATE_WINDOW", "60")),
        "cors_origins": os.getenv("CORS_ORIGINS", "*").split(","),
        "enable_security_headers": os.getenv("ENABLE_SECURITY_HEADERS", "true").lower() == "true",
    }


# API6 — Per-endpoint rate limits for sensitive business flows
ENDPOINT_RATE_LIMITS: Dict[str, Dict[str, int]] = {
    "/api/v1/chat":              {"limit": 20, "window": 60},

    "/api/v1/sentinel/start":    {"limit": 3,  "window": 60},
    "/api/v1/sentinel/stop":     {"limit": 3,  "window": 60},
    "/api/v1/copilot/analyze-script": {"limit": 10, "window": 60},
    "/api/v1/copilot/enrich":    {"limit": 10, "window": 60},
    "/api/v1/connect":           {"limit": 5,  "window": 60},
    "/api/v1/hunts/{hunt_id}/execute": {"limit": 10, "window": 60},
    # Legacy unversioned paths (backwards compat)
    "/api/chat":                 {"limit": 20, "window": 60},

    "/api/sentinel/start":       {"limit": 3,  "window": 60},
    "/api/connect":              {"limit": 5,  "window": 60},
}


class SecurityMiddleware:
    """HTTP security middleware for rate limiting, headers, and anti-automation."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or get_security_config()
        # Global rate limits: { client_ip: [timestamps] }
        self._global_limits: Dict[str, list] = defaultdict(list)
        # Per-endpoint rate limits: { "ip:path": [timestamps] }
        self._endpoint_limits: Dict[str, list] = defaultdict(list)
        # Failed auth tracking for brute-force detection
        self._failed_auths: Dict[str, list] = defaultdict(list)

    def check_rate_limit(self, client_ip: str) -> bool:
        """Check global rate limit for a client."""
        now = time.time()
        window = self.config.get("rate_window", 60)
        limit = self.config.get("rate_limit", 60)

        # Clean old entries
        self._global_limits[client_ip] = [
            t for t in self._global_limits[client_ip]
            if now - t < window
        ]

        if len(self._global_limits[client_ip]) >= limit:
            return False

        self._global_limits[client_ip].append(now)
        return True

    def check_endpoint_rate_limit(self, client_ip: str, path: str) -> bool:
        """API6 — Check per-endpoint rate limit for sensitive business flows."""
        # Normalize path (strip path params for matching)
        normalized = self._normalize_path(path)
        config = ENDPOINT_RATE_LIMITS.get(normalized)

        if not config:
            return True  # No specific limit for this endpoint

        now = time.time()
        key = f"{client_ip}:{normalized}"
        window = config["window"]
        limit = config["limit"]

        self._endpoint_limits[key] = [
            t for t in self._endpoint_limits[key]
            if now - t < window
        ]

        if len(self._endpoint_limits[key]) >= limit:
            return False

        self._endpoint_limits[key].append(now)
        return True

    def record_failed_auth(self, client_ip: str) -> bool:
        """Track failed auth attempts. Returns False if locked out."""
        now = time.time()
        lockout_window = 300  # 5 minutes
        max_failures = 10

        self._failed_auths[client_ip] = [
            t for t in self._failed_auths[client_ip]
            if now - t < lockout_window
        ]

        self._failed_auths[client_ip].append(now)

        if len(self._failed_auths[client_ip]) >= max_failures:
            return False  # Locked out

        return True

    def is_locked_out(self, client_ip: str) -> bool:
        """Check if a client is locked out due to too many failed auths."""
        now = time.time()
        lockout_window = 300
        max_failures = 10

        recent = [t for t in self._failed_auths.get(client_ip, [])
                  if now - t < lockout_window]
        return len(recent) >= max_failures

    def _normalize_path(self, path: str) -> str:
        """Normalize API path for rate limit matching (strip UUIDs/IDs)."""
        import re
        # Replace UUID-like and hex segments with {id}
        normalized = re.sub(
            r'/[a-fA-F0-9]{8,}(-[a-fA-F0-9]{4,}){0,4}',
            '/{id}', path
        )
        # Replace HUNT-XXX, INC-XXX, etc. with {id}
        normalized = re.sub(r'/[A-Z]+-[A-Z0-9]+', '/{id}', normalized)
        # Special case: /hunts/HUNT-001/execute -> /hunts/{hunt_id}/execute
        normalized = re.sub(r'/hunts/[^/]+/execute', '/hunts/{hunt_id}/execute', normalized)
        return normalized

    def add_security_headers(self, response) -> None:
        """API8 — Add comprehensive security headers to HTTP response."""
        if not self.config.get("enable_security_headers", True):
            return

        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src https://fonts.gstatic.com; "
                "img-src 'self' data:; "
                "connect-src 'self'"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        }

        for key, value in headers.items():
            response.headers[key] = value

    def get_rate_limit_info(self, client_ip: str, path: str) -> Dict[str, Any]:
        """Return rate limit headers info for the response."""
        normalized = self._normalize_path(path)
        config = ENDPOINT_RATE_LIMITS.get(normalized)

        if not config:
            # Use global limits
            window = self.config.get("rate_window", 60)
            limit = self.config.get("rate_limit", 60)
            now = time.time()
            recent = [t for t in self._global_limits.get(client_ip, [])
                      if now - t < window]
            remaining = max(0, limit - len(recent))
        else:
            window = config["window"]
            limit = config["limit"]
            key = f"{client_ip}:{normalized}"
            now = time.time()
            recent = [t for t in self._endpoint_limits.get(key, [])
                      if now - t < window]
            remaining = max(0, limit - len(recent))

        return {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(window)),
        }

    def log_request(self, method: str, path: str, client_ip: str,
                   status_code: int, api_key: str = "") -> None:
        """Audit log with key fingerprint (never log full keys)."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        key_hint = api_key[:8] + "..." if api_key else "none"
        print(f"[AUDIT] {timestamp} | {method} {path} | {client_ip} | "
              f"key={key_hint} | {status_code}")
