"""
Security Validator for Remote Server MCP

This module enforces strict security policies:
- No command execution escapes
- Path traversal prevention
- Service name validation
- Command injection prevention
- Sensitive file access protection

Design: Whitelist specific safe operations, don't try to blacklist dangerous ones.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Strict service name pattern: alphanumeric, hyphens, underscores only
SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

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

        # Check pattern
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

        # Check for path traversal
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern in file_path:
                logger.warning(f"File path contains dangerous pattern: {pattern}")
                return None

        # Check for sensitive file patterns
        file_path_lower = file_path.lower()
        for pattern in SENSITIVE_FILE_PATTERNS:
            if pattern.lower() in file_path_lower:
                logger.warning(f"File path matches sensitive pattern: {pattern}")
                return None

        # Must be relative path (no leading /)
        if file_path.startswith("/"):
            logger.warning(f"File path must be relative, not absolute: {file_path}")
            return None

        # Construct full path
        full_path = f"/srv/{service}/{file_path}"

        # Resolve to prevent any tricks (normalize ../ etc)
        try:
            resolved_path = str(Path(full_path).resolve())

            # Verify resolved path is still under /srv/{service}/
            service_base = f"/srv/{service}"
            if not resolved_path.startswith(service_base):
                logger.warning(
                    f"Path resolution escaped service directory: {resolved_path}"
                )
                return None

            return resolved_path
        except Exception as e:
            logger.warning(f"Error resolving path: {e}")
            return None

    def sanitize_search_pattern(self, pattern: str) -> str:
        """
        Sanitize a search pattern to prevent shell injection.

        Args:
            pattern: Raw search pattern

        Returns:
            Sanitized pattern safe for use in grep -F
        """
        if not pattern or not isinstance(pattern, str):
            return ""

        # Limit length
        pattern = pattern[:200]

        # Remove all shell special characters
        for char in [
            "'",
            '"',
            "`",
            "$",
            "\\",
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
        ]:
            pattern = pattern.replace(char, "")

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
