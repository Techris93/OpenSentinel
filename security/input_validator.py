"""
Input Validation Module
Sanitizes user input to prevent prompt injection, SSRF, and other attacks.
"""
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class InputValidator:
    """Validates and sanitizes user inputs for security."""

    # Prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|above|all)\s+(instructions|prompts)",
        r"you\s+are\s+now\s+(?:a\s+)?(?:different|new)",
        r"system\s*:\s*",
        r"<\s*(?:script|system|admin)",
        r"(?:forget|disregard|override)\s+(?:your|all|previous)",
        r"\{\{.*\}\}",
        r"jailbreak",
        r"DAN\s+mode",
    ]

    # SSRF prevention — private IP ranges
    PRIVATE_RANGES = [
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"^192\.168\.",
        r"^127\.",
        r"^0\.",
        r"^169\.254\.",
        r"^::1$",
        r"^fc00:",
        r"^fe80:",
    ]

    # Dangerous SPL commands
    DANGEROUS_SPL = [
        "| delete", "| outputlookup", "| sendemail",
        "| script", "| run", "| collect",
        "| mcollect", "| outputcsv",
    ]

    def __init__(self):
        self._injection_re = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]
        self._private_re = [re.compile(p) for p in self.PRIVATE_RANGES]

    def validate_chat_input(self, text: str) -> Dict[str, Any]:
        """Validate chat input for prompt injection and malicious content."""
        if not text or not text.strip():
            return {"safe": False, "reason": "Empty input"}

        if len(text) > 10000:
            return {"safe": False, "reason": "Input too long (max 10000 chars)"}

        # Check for prompt injection
        for pattern in self._injection_re:
            if pattern.search(text):
                return {"safe": False, "reason": "Potential prompt injection detected"}

        # Check for dangerous SPL commands
        text_lower = text.lower()
        for cmd in self.DANGEROUS_SPL:
            if cmd in text_lower:
                return {"safe": False, "reason": f"Dangerous SPL command detected: {cmd}"}

        return {"safe": True, "reason": None}

    def validate_recon_target(self, target: str) -> Dict[str, Any]:
        """Validate a reconnaissance target to prevent SSRF."""
        if not target or not target.strip():
            return {"safe": False, "reason": "Empty target"}

        # Check for private IP ranges
        for pattern in self._private_re:
            if pattern.match(target):
                return {"safe": False, "reason": "Private/internal IP address not allowed"}

        # Parse as URL and check
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            hostname = parsed.hostname or target
            for pattern in self._private_re:
                if pattern.match(hostname):
                    return {"safe": False, "reason": "Private hostname not allowed"}
        except Exception:
            pass

        return {"safe": True, "reason": None}

    def sanitize_spl(self, query: str) -> str:
        """Remove dangerous SPL commands from a query."""
        sanitized = query
        for cmd in self.DANGEROUS_SPL:
            sanitized = sanitized.replace(cmd, "")
        return sanitized

    def validate_api_key_format(self, key: str) -> bool:
        """Validate API key format."""
        if not key or len(key) < 8:
            return False
        return bool(re.match(r'^[a-zA-Z0-9_\-]+$', key))
