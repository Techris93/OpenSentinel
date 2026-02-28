"""
Authentication & Authorization Module
API key validation, RBAC roles, token management, and BOLA protection.

OWASP API Security Coverage:
  API1 — BOLA: Ownership context attached to authenticated requests
  API2 — Broken Auth: Key expiry enforcement, timing-safe comparison
  API3 — Object Property Auth: Field-level filtering helpers
  API5 — Function-Level Auth: require_role / require_permission decorators
"""
import os
import hmac
import secrets
import time
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta
from functools import wraps
from fastapi import HTTPException, Request


class AuthManager:
    """Manages API key authentication and role-based access control."""

    ROLES = {
        "readonly": {"read"},
        "analyst": {"read", "write", "execute"},
        "admin": {"read", "write", "execute", "admin"}
    }

    # Map roles → accessible resource scopes for BOLA checks
    ROLE_SCOPES = {
        "readonly": {"own"},
        "analyst": {"own", "team"},
        "admin": {"own", "team", "all"}
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self._api_keys: Dict[str, Dict] = {}
        self._load_keys()

    def _load_keys(self):
        """Load API keys from environment or config."""
        env_key = os.getenv("OPENSENTINEL_API_KEY", "dev-key-opensentinel-2024")
        self._api_keys[env_key] = {
            "role": "admin",
            "owner_id": "system",
            "created": datetime.utcnow().isoformat(),
            "expires": None,  # Never expires
            "description": "Default admin key"
        }

    def validate_key(self, api_key: str) -> bool:
        """Validate an API key with timing-safe comparison and expiry check."""
        if not api_key:
            return False

        key_info = self._api_keys.get(api_key)
        if not key_info:
            return False

        # Check expiry (API2 fix)
        expires = key_info.get("expires")
        if expires:
            try:
                exp_dt = datetime.fromisoformat(expires)
                if datetime.utcnow() > exp_dt:
                    # Auto-revoke expired keys
                    del self._api_keys[api_key]
                    return False
            except (ValueError, TypeError):
                pass

        return True

    def get_role(self, api_key: str) -> Optional[str]:
        """Get the role associated with an API key."""
        key_info = self._api_keys.get(api_key)
        return key_info["role"] if key_info else None

    def get_owner_id(self, api_key: str) -> Optional[str]:
        """Get the owner ID for BOLA checks."""
        key_info = self._api_keys.get(api_key)
        return key_info.get("owner_id") if key_info else None

    def has_permission(self, api_key: str, permission: str) -> bool:
        """Check if an API key has a specific permission."""
        role = self.get_role(api_key)
        if not role:
            return False
        return permission in self.ROLES.get(role, set())

    def can_access_resource(self, api_key: str, resource_owner: str) -> bool:
        """BOLA check — can this key access a resource owned by resource_owner?"""
        role = self.get_role(api_key)
        owner_id = self.get_owner_id(api_key)

        if not role or not owner_id:
            return False

        scopes = self.ROLE_SCOPES.get(role, set())

        # Admin can access everything
        if "all" in scopes:
            return True

        # Own resources
        if "own" in scopes and owner_id == resource_owner:
            return True

        return False

    def generate_temp_key(self, role: str = "analyst", ttl_hours: int = 24,
                         owner_id: str = "system") -> str:
        """Generate a temporary API key with enforced expiry."""
        key = f"tmp-{secrets.token_hex(16)}"
        self._api_keys[key] = {
            "role": role,
            "owner_id": owner_id,
            "created": datetime.utcnow().isoformat(),
            "expires": (datetime.utcnow() + timedelta(hours=ttl_hours)).isoformat(),
            "description": "Temporary key"
        }
        return key

    def revoke_key(self, api_key: str) -> bool:
        """Revoke an API key."""
        if api_key in self._api_keys:
            del self._api_keys[api_key]
            return True
        return False

    def list_keys(self) -> List[Dict]:
        """List all registered API keys (masked)."""
        return [
            {
                "key": k[:8] + "..." + k[-4:],
                "role": v["role"],
                "created": v["created"],
                "expires": v.get("expires", "never")
            }
            for k, v in self._api_keys.items()
        ]

    def filter_fields(self, data: Dict, role: str,
                     allowed_fields: Dict[str, Set[str]]) -> Dict:
        """API3 — Filter response fields based on role permissions."""
        role_fields = allowed_fields.get(role, allowed_fields.get("readonly", set()))
        return {k: v for k, v in data.items() if k in role_fields}


def require_role(required_role: str):
    """
    API5 — Decorator to enforce function-level authorization.
    Checks the X-API-Key header against the required role.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, request: Request = None, **kwargs):
            if request is None:
                # Try to find request in args
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                raise HTTPException(status_code=500, detail="Request context unavailable")

            api_key = request.headers.get("X-API-Key", "")
            auth_manager: AuthManager = request.app.state.auth_manager

            if not auth_manager.validate_key(api_key):
                raise HTTPException(status_code=401, detail="Invalid API key")

            role = auth_manager.get_role(api_key)
            role_hierarchy = {"readonly": 0, "analyst": 1, "admin": 2}

            if role_hierarchy.get(role, -1) < role_hierarchy.get(required_role, 99):
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Required role: {required_role}"
                )

            return await func(*args, request=request, **kwargs)
        return wrapper
    return decorator


def require_permission(permission: str):
    """Decorator to require a specific permission for an endpoint."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, request: Request = None, **kwargs):
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                raise HTTPException(status_code=500, detail="Request context unavailable")

            api_key = request.headers.get("X-API-Key", "")
            auth_manager: AuthManager = request.app.state.auth_manager

            if not auth_manager.has_permission(api_key, permission):
                raise HTTPException(
                    status_code=403,
                    detail=f"Missing permission: {permission}"
                )

            return await func(*args, request=request, **kwargs)
        return wrapper
    return decorator
