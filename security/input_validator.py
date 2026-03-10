"""
Input Validation Module
Sanitizes user input to prevent prompt injection, SQL injection, XSS,
SSRF, command injection, path traversal, and other attacks.

OWASP Coverage:
  API7  — Server-Side Request Forgery (SSRF prevention)
  API8  — Security Misconfiguration (XSS, injection defenses)
  API10 — Unsafe Consumption (external input sanitization)
"""
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class InputValidator:
    """Validates and sanitizes user inputs for security."""

    # ── Prompt Injection Patterns ────────────────────────────────────────────
    INJECTION_PATTERNS = [
        # Instruction override attempts
        r"ignore\s+(previous|above|all|prior|earlier)\s+(instructions|prompts|rules|context)",
        r"(?:forget|disregard|override|bypass|skip)\s+(?:your|all|previous|prior|safety|content)",
        r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|evil|unrestricted)",
        r"pretend\s+(?:you\s+are|to\s+be|that)",
        r"act\s+as\s+(?:if|though|a\s+(?:different|new))",
        r"roleplay\s+as",

        # System prompt extraction
        r"system\s*:\s*",
        r"(?:show|reveal|print|output|display)\s+(?:your|the)\s+(?:system|initial|original)\s+(?:prompt|instructions|message)",
        r"what\s+(?:are|were)\s+your\s+(?:original|initial|system)\s+(?:instructions|prompt)",

        # Template / code injection
        r"<\s*(?:script|system|admin|iframe|object|embed|form|meta|link|base)",
        r"\{\{.*\}\}",
        r"\$\{.*\}",
        r"`.*`\s*\+\s*`",

        # Known jailbreak techniques
        r"jailbreak",
        r"DAN\s+mode",
        r"developer\s+mode\s+enabled",
        r"DUDE\s+mode",
        r"stay\s+in\s+character",
        r"do\s+anything\s+now",
    ]

    # ── SQL Injection Patterns ───────────────────────────────────────────────
    SQL_INJECTION_PATTERNS = [
        # Classic SQL injection
        r"(?:^|\s|;)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\s",
        r"(?:UNION\s+(?:ALL\s+)?SELECT)",
        r"(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",    # OR 1=1
        r"(?:OR|AND)\s+['\"]?[a-z]+['\"]?\s*=\s*['\"]?[a-z]+['\"]?",  # OR 'a'='a'
        r"--\s*$",                                                   # SQL comment
        r"/\*.*?\*/",                                                # Block comment
        r";\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)",           # Stacked queries
        r"(?:SLEEP|BENCHMARK|WAITFOR)\s*\(",                        # Time-based SQLi
        r"(?:LOAD_FILE|INTO\s+(?:OUTFILE|DUMPFILE))\s*\(",         # File access
        r"(?:information_schema|sqlite_master|sys\.)",              # Schema probing
        r"CHAR\s*\(\d+\)",                                          # Encoded chars
        r"0x[0-9a-fA-F]+",                                          # Hex-encoded payload
    ]

    # ── XSS / HTML Injection ─────────────────────────────────────────────────
    XSS_PATTERNS = [
        r"<\s*script[^>]*>",
        r"javascript\s*:",
        r"on(?:load|error|click|mouseover|focus|blur|submit|change|input|keyup|keydown)\s*=",
        r"<\s*(?:img|svg|body|input|button|textarea|select)[^>]*\bon\w+\s*=",
        r"<\s*iframe",
        r"<\s*object",
        r"<\s*embed",
        r"<\s*form[^>]*action\s*=",
        r"expression\s*\(",
        r"url\s*\(\s*['\"]?javascript",
        r"data\s*:\s*text/html",
    ]

    # ── Command Injection ────────────────────────────────────────────────────
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`]\s*(?:cat|ls|rm|mv|cp|chmod|chown|wget|curl|nc|ncat|bash|sh|zsh|python|perl|ruby|php|node)\b",
        r"\$\(.*\)",                   # $(...) subshell
        r"`[^`]{2,}`",                 # backtick execution
        r"\|\s*(?:sh|bash|zsh|python)", # pipe to shell
        r">\s*/(?:etc|tmp|dev|proc)/",  # redirect to system paths
        r"(?:&&|\|\|)\s*\w+",          # chained commands
    ]

    # ── Path Traversal ───────────────────────────────────────────────────────
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",                       # ../
        r"\.\.\%2[fF]",               # URL-encoded ../
        r"\.\.\%5[cC]",               # URL-encoded ..\
        r"\.\.\\",                      # ..\
        r"%00",                         # null byte
        r"/etc/(?:passwd|shadow|hosts)",
        r"/proc/self/",
        r"(?:C|D):\\\\(?:Windows|Users)",
    ]

    # ── SSRF — Private IP Ranges ─────────────────────────────────────────────
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
        r"^localhost$",
        r"^0\.0\.0\.0$",
    ]

    # ── Dangerous SPL Commands ───────────────────────────────────────────────
    DANGEROUS_SPL = [
        "| delete", "| outputlookup", "| sendemail",
        "| script", "| run", "| collect",
        "| mcollect", "| outputcsv", "| runshellscript",
        "| sendalert", "| outputtelemetry",
    ]

    # ═════════════════════════════════════════════════════════════════════════

    def __init__(self):
        self._injection_re = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]
        self._sqli_re = [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS]
        self._xss_re = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self._cmd_re = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]
        self._path_re = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
        self._private_re = [re.compile(p) for p in self.PRIVATE_RANGES]

    # ── Primary Validators ───────────────────────────────────────────────────

    def validate_chat_input(self, text: str) -> Dict[str, Any]:
        """Validate chat input for prompt injection and malicious content."""
        if not text or not text.strip():
            return {"safe": False, "reason": "Empty input"}

        if len(text) > 10000:
            return {"safe": False, "reason": "Input too long (max 10,000 chars)"}

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

    def validate_text_field(self, text: str, field_name: str = "input",
                            max_length: int = 5000) -> Dict[str, Any]:
        """
        General-purpose text field validator.
        Checks for SQL injection, XSS, command injection, and path traversal.
        Use for incident titles, descriptions, notes, etc.
        """
        if not text or not text.strip():
            return {"safe": False, "reason": f"Empty {field_name}"}

        if len(text) > max_length:
            return {"safe": False, "reason": f"{field_name} too long (max {max_length} chars)"}

        # SQL injection
        for pattern in self._sqli_re:
            if pattern.search(text):
                return {"safe": False, "reason": f"SQL injection pattern detected in {field_name}"}

        # XSS / HTML injection
        for pattern in self._xss_re:
            if pattern.search(text):
                return {"safe": False, "reason": f"XSS/HTML injection detected in {field_name}"}

        # Command injection
        for pattern in self._cmd_re:
            if pattern.search(text):
                return {"safe": False, "reason": f"Command injection detected in {field_name}"}

        # Path traversal
        for pattern in self._path_re:
            if pattern.search(text):
                return {"safe": False, "reason": f"Path traversal detected in {field_name}"}

        return {"safe": True, "reason": None}

    def validate_identifier(self, value: str, field_name: str = "id") -> Dict[str, Any]:
        """
        Validate an identifier (incident ID, hunt ID, alert ID, etc.).
        Must be alphanumeric with hyphens/underscores only.
        """
        if not value or not value.strip():
            return {"safe": False, "reason": f"Empty {field_name}"}

        if len(value) > 128:
            return {"safe": False, "reason": f"{field_name} too long (max 128 chars)"}

        if not re.match(r'^[a-zA-Z0-9_\-]+$', value):
            return {"safe": False, "reason": f"Invalid {field_name} format (alphanumeric, hyphens, underscores only)"}

        return {"safe": True, "reason": None}

    def validate_ioc(self, ioc: str) -> Dict[str, Any]:
        """
        Validate an IOC (Indicator of Compromise) value.
        Allows IPs, domains, hashes, URLs — blocks injection attempts.
        """
        if not ioc or not ioc.strip():
            return {"safe": False, "reason": "Empty IOC"}

        if len(ioc) > 2048:
            return {"safe": False, "reason": "IOC too long (max 2048 chars)"}

        # Check for SQL injection in IOC values
        for pattern in self._sqli_re:
            if pattern.search(ioc):
                return {"safe": False, "reason": "SQL injection in IOC value"}

        # Check for command injection
        for pattern in self._cmd_re:
            if pattern.search(ioc):
                return {"safe": False, "reason": "Command injection in IOC value"}

        return {"safe": True, "reason": None}

    def validate_ioc_list(self, iocs: List[str]) -> Dict[str, Any]:
        """Validate a list of IOCs."""
        if not iocs:
            return {"safe": False, "reason": "Empty IOC list"}

        if len(iocs) > 100:
            return {"safe": False, "reason": "Too many IOCs (max 100)"}

        for i, ioc in enumerate(iocs):
            result = self.validate_ioc(ioc)
            if not result["safe"]:
                return {"safe": False, "reason": f"IOC[{i}]: {result['reason']}"}

        return {"safe": True, "reason": None}

    def validate_recon_target(self, target: str) -> Dict[str, Any]:
        """Validate a reconnaissance target to prevent SSRF."""
        if not target or not target.strip():
            return {"safe": False, "reason": "Empty target"}

        if len(target) > 1024:
            return {"safe": False, "reason": "Target too long"}

        # Command injection check
        for pattern in self._cmd_re:
            if pattern.search(target):
                return {"safe": False, "reason": "Command injection in target"}

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

    # ── Sanitizers ───────────────────────────────────────────────────────────

    def sanitize_spl(self, query: str) -> str:
        """Remove dangerous SPL commands from a query."""
        sanitized = query
        for cmd in self.DANGEROUS_SPL:
            sanitized = sanitized.replace(cmd, "")
        return sanitized

    def sanitize_html(self, text: str) -> str:
        """Strip HTML/script tags from text to prevent XSS."""
        # Remove script tags and content
        text = re.sub(r'<\s*script[^>]*>.*?</\s*script\s*>', '', text, flags=re.IGNORECASE | re.DOTALL)
        # Remove all HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        # Escape remaining special characters
        text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        return text

    def validate_api_key_format(self, key: str) -> bool:
        """Validate API key format.
        Requires 32+ characters for sufficient entropy (128-bit minimum).
        """
        if not key or len(key) < 32:
            return False
        return bool(re.match(r'^[a-zA-Z0-9_\-]+$', key))
