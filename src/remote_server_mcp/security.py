"""
Security Validator for Remote Server MCP

This module enforces strict security policies:
- No command execution escapes
- Path traversal prevention (including Unicode/encoding bypasses)
- Service name validation (Docker-safe, no option injection)
- Command injection prevention
- Sensitive file access protection
- Symlink attack mitigation
- Database query validation (read-only enforcement)

Design: Whitelist specific safe operations, don't try to blacklist dangerous ones.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Strict service name pattern: must start with alphanumeric, then alphanumeric,
# hyphens, underscores. Prevents Docker option injection (names like "-help").
SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")

# Patterns that indicate path traversal attempts
PATH_TRAVERSAL_PATTERNS = [
    "..",  # Parent directory reference
    "~",  # Home directory
    "$",  # Variable expansion
    "`",  # Command substitution
    ";",  # Command separator
    "|",  # Pipe
    "&",  # Background/AND
    ">",  # Redirect
    "<",  # Redirect input
    "(",  # Subshell
    ")",  # Subshell
    "{",  # Brace expansion
    "}",  # Brace expansion
    "[",  # Glob
    "]",  # Glob
    "*",  # Glob
    "?",  # Glob
    "'",  # Quote escape
    '"',  # Quote escape
    "\\",  # Escape character
    "\n",  # Newline injection
    "\r",  # Carriage return
    "\t",  # Tab injection
    " ",  # Space (shell word splitting)
    "!",  # Bash history expansion
    ":",  # Shell special in some contexts
    "@",  # SSH-style syntax
    "#",  # Comment character
    "%",  # URL encoding indicator
]

# URL-encoded path traversal patterns
URL_ENCODED_TRAVERSAL = [
    "%2e",  # URL-encoded dot
    "%2f",  # URL-encoded slash
    "%5c",  # URL-encoded backslash
    "%25",  # URL-encoded percent (double encoding)
    "%00",  # Null byte
]

# Unicode lookalike characters that could bypass ".." detection
UNICODE_DOT_VARIANTS = [
    "\uff0e",  # Fullwidth full stop
    "\u3002",  # Ideographic full stop
    "\u2024",  # One dot leader
    "\u2025",  # Two dot leader
    "\u2027",  # Hyphenation point
    "\u00b7",  # Middle dot
    "\u200b",  # Zero-width space (used between dots)
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
]

# Patterns that indicate write/mutate operations in SQL/InfluxQL
WRITE_QUERY_PATTERNS = [
    "drop ",
    "delete ",
    "insert ",
    "update ",
    "alter ",
    "create ",
    "truncate ",
    "grant ",
    "revoke ",
    "set password",
    "kill ",
]

# Dangerous characters that could be used for injection in query strings
DANGEROUS_QUERY_CHARS = [
    ";",  # Statement terminator (SQL injection)
    "--",  # SQL comment
    "/*",  # Block comment start
    "*/",  # Block comment end
    "`",  # Command substitution
    "$",  # Variable expansion
    "|",  # Pipe
    "&",  # Background
    "{",  # Brace expansion
    "}",  # Brace expansion
    "\\",  # Escape
    "\n",  # Newline
    "\r",  # Carriage return
    "\x00",  # Null byte
]

# Sensitive file patterns that should NEVER be accessible
SENSITIVE_FILE_PATTERNS = [
    ".env",
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".pem",
    ".key",
    "secret",
    "password",
    "credential",
    "token",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/ssl",
    "/root/",
    "/home/",
    ".git/",  # Git directory (may contain credentials in remote URLs)
    ".git/config",  # Contains remote URLs with possible credentials
    ".git/HEAD",  # Reveals branch info
    "/proc/",  # Process info, environment variables
    "/sys/",  # System information
    "/dev/",  # Device files
    "htpasswd",
    "wp-config",
    "database.yml",
    "secrets.yml",
]


class SecurityValidator:
    """Validates all inputs for security before execution."""

    def __init__(self, config: dict):
        """
        Initialize security validator.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.security_config = config.get("security", {})

        # Base service directory
        self.services_base_path = self.security_config.get("services_path", "/srv")

        # Allowed operations (no generic command execution)
        self.allow_generic_command_execution = False  # NEVER enable this

    def validate_service_name(self, service_name: str) -> bool:
        """
        Validate service name against strict pattern.

        Service names must start with an alphanumeric character to prevent
        Docker option injection (e.g., "-help" would be interpreted as a flag).

        Args:
            service_name: Service name to validate

        Returns:
            True if valid, False otherwise
        """
        if not service_name or not isinstance(service_name, str):
            logger.warning(f"Invalid service name: {service_name}")
            return False

        # Check length (prevent DoS)
        if len(service_name) > 100:
            logger.warning(f"Service name too long: {len(service_name)} chars")
            return False

        # Check pattern - must start with alphanumeric (not hyphen/underscore)
        if not SERVICE_NAME_PATTERN.match(service_name):
            logger.warning(f"Service name contains invalid characters: {service_name}")
            return False

        # Check for path traversal patterns
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in service_name:
                logger.warning(
                    f"Service name contains path traversal pattern: {pattern}"
                )
                return False

        return True

    def validate_service_file_path(self, service: str, file_path: str) -> str | None:
        """
        Validate and construct a safe file path within /srv/{service}/.

        Protects against:
        - Path traversal (../, ~/, etc.)
        - URL-encoded traversal (%2e%2e%2f)
        - Unicode dot variants (U+FF0E variants, zero-width spaces)
        - Null byte injection
        - Shell metacharacters (spaces, !, etc.)
        - Sensitive file access
        - Symlink attacks (remote symlinks can't be verified locally)

        Args:
            service: Service name (already validated)
            file_path: Relative file path within service directory

        Returns:
            Full safe path, or None if invalid
        """
        if not file_path or not isinstance(file_path, str):
            logger.warning(f"Invalid file path: {file_path}")
            return None

        # Check length
        if len(file_path) > 500:
            logger.warning(f"File path too long: {len(file_path)} chars")
            return None

        # Block null bytes
        if "\x00" in file_path:
            logger.warning("File path contains null byte")
            return None

        # Block URL-encoded traversal attempts
        file_path_lower = file_path.lower()
        for pattern in URL_ENCODED_TRAVERSAL:
            if pattern.lower() in file_path_lower:
                logger.warning(f"File path contains URL-encoded traversal: {pattern}")
                return None

        # Block Unicode dot variants (lookalike characters)
        for char in UNICODE_DOT_VARIANTS:
            if char in file_path:
                logger.warning("File path contains unicode dot variant: %r", char)
                return None

        # Check for path traversal
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in file_path:
                logger.warning(f"File path contains dangerous pattern: {pattern}")
                return None

        # Check for sensitive file patterns
        for pattern in SENSITIVE_FILE_PATTERNS:
            if pattern.lower() in file_path_lower:
                logger.warning(f"File path matches sensitive pattern: {pattern}")
                return None

        # Must be relative path (no leading /)
        if file_path.startswith("/"):
            logger.warning(f"File path must be relative, not absolute: {file_path}")
            return None

        # Use configured services_base_path (not hardcoded /srv)
        service_base = f"{self.services_base_path}/{service}"
        full_path = f"{service_base}/{file_path}"

        # Resolve to normalize the path (detect ../ that might slip through)
        try:
            resolved_path = str(Path(full_path).resolve())

            # Verify resolved path is still under the service directory
            is_under_base = resolved_path.startswith(service_base + "/")
            if not is_under_base and resolved_path != service_base:
                logger.warning(
                    f"Path resolution escaped service directory: {resolved_path}"
                )
                return None

            return resolved_path
        except Exception as e:
            logger.warning(f"Error resolving path: {e}")
            return None

    def validate_influxdb_query(self, query: str) -> str | None:
        """
        Validate an InfluxDB v3 SQL query for read-only safety.

        Blocks:
        - Write operations (DROP, DELETE, INSERT, UPDATE, etc.)
        - SQL injection characters (;, --, etc.)
        - Shell injection attempts

        Args:
            query: SQL query string to validate

        Returns:
            The query if valid, None if invalid
        """
        if not query or not isinstance(query, str):
            logger.warning("Empty or invalid InfluxDB query")
            return None

        # Limit length
        if len(query) > 5000:
            logger.warning(f"InfluxDB query too long: {len(query)} chars")
            return None

        # Check for write operations
        query_lower = query.lower()
        for pattern in WRITE_QUERY_PATTERNS:
            if pattern in query_lower:
                logger.warning(f"InfluxDB query contains write operation: {pattern}")
                return None

        # Check for dangerous characters (shell injection)
        for char in DANGEROUS_QUERY_CHARS:
            if char in query:
                logger.warning(f"InfluxDB query contains dangerous character: {char!r}")
                return None

        # Query must start with SELECT
        if not query_lower.strip().startswith("select"):
            logger.warning(f"InfluxDB query must start with SELECT: {query[:50]}")
            return None

        return query

    def validate_prometheus_query(self, query: str) -> str | None:
        """
        Validate a PromQL query for safety.

        PromQL is inherently read-only (no write operations exist in the
        query API), so we mainly block shell injection characters.

        Args:
            query: PromQL expression to validate

        Returns:
            The query if valid, None if invalid
        """
        if not query or not isinstance(query, str):
            logger.warning("Empty or invalid Prometheus query")
            return None

        # Limit length
        if len(query) > 5000:
            logger.warning(f"PromQL query too long: {len(query)} chars")
            return None

        # PromQL uses () and {} for valid syntax, so we don't block them
        # But block shell injection characters
        shell_injection_chars = [
            ";",  # Command separator
            "`",  # Command substitution
            "$",  # Variable expansion
            "|",  # Pipe
            "&",  # Background
            ">",  # Redirect
            "<",  # Redirect
            "\\",  # Escape
            "\n",  # Newline
            "\r",  # Carriage return
            "\x00",  # Null byte
            "'",  # Quote (could break curl quoting)
            '"',  # Quote (could break curl quoting)
        ]
        for char in shell_injection_chars:
            if char in query:
                logger.warning(
                    f"PromQL query contains shell injection character: {char!r}"
                )
                return None

        return query

    def sanitize_search_pattern(self, pattern: str) -> str:
        """
        Sanitize a search pattern to prevent shell injection.

        The sanitized pattern is used in: grep -F '{pattern}'
        So we must strip all characters that could break the quoting.

        Args:
            pattern: Raw search pattern

        Returns:
            Sanitized pattern safe for use in grep -F

        Raises:
            ValueError: If pattern becomes empty after sanitization
        """
        if not pattern or not isinstance(pattern, str):
            raise ValueError("Search pattern must not be empty")

        # Limit length
        pattern = pattern[:200]

        # Remove ALL shell special characters that could break grep quoting
        for char in [
            "'",  # Breaks single-quote quoting
            '"',
            "`",
            "$",
            "\\",  # Could escape the closing quote
            ";",
            "|",
            "&",
            ">",
            "<",
            "(",
            ")",
            "{",
            "}",
            "\n",
            "\r",
            "\t",
            "!",  # Bash history expansion
            "#",  # Comment character
            "~",  # Home directory expansion
            # Note: space is NOT stripped here because the pattern is
            # single-quoted in the grep command: grep -F '{pattern}'
            # Spaces inside quotes are safe. Stripping spaces would break
            # legitimate multi-word searches like "connection failed".
        ]:
            pattern = pattern.replace(char, "")

        # Check if pattern is empty after sanitization
        if not pattern.strip():
            raise ValueError(
                "Search pattern became empty after sanitization. "
                "This would cause grep to read from stdin (hang)."
            )

        return pattern

    def is_command_safe(self, command: str) -> bool:
        """
        Check if a pre-defined command is safe to execute.

        This validates commands constructed by the application code.
        Since these commands are built from whitelisted templates with
        validated inputs (service names, sanitized patterns), we use a
        more permissive policy that still blocks truly dangerous operations.

        Args:
            command: Command to validate

        Returns:
            True if safe
        """
        # Block truly dangerous operations that should NEVER appear in any command
        dangerous_patterns = [
            "sudo",
            "su ",
            "passwd",
            "useradd",
            "usermod",
            "userdel",
            "groupadd",
            "chmod",
            "chown",
            "mount ",
            "umount",
            "iptables",
            "kill -9",
            "rm -rf /",
            "mkfs",
            "fdisk",
            "/dev/",
            "/etc/shadow",
            "/etc/passwd",
            "wget ",
            "curl ",
            "bash ",
            "sh ",
            "zsh ",
            "python ",
            "python3 ",
            "perl ",
            "ruby ",
        ]

        command_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                logger.warning(f"Command contains dangerous pattern: {pattern}")
                return False

        # Allow shell operators and formatting used in legitimate commands:
        # - Redirection (>, 2>&1, >>)
        # - Pipes (|)
        # - Command separators (&&, ||, ;)
        # - Variable expansion ($()) - used in docker format strings like {{.Names}}
        # These are safe when the command template is application-controlled

        return True
