"""
Configuration loader for Remote Server MCP
"""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "ssh": {
        "host": "your-server.example.com",
        "port": 22,
        "username": "your-user",
        "password": None,  # Or use key_path
        "key_path": None,  # Path to SSH private key
    },
    "security": {
        # Service directory base path
        "services_path": "/srv",
        # NEVER allow generic command execution
        "allow_generic_commands": False,
    },
}


def load_config(config_path: Path | None = None) -> dict:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to config file (optional, uses default if not found)

    Returns:
        Configuration dictionary
    """
    if config_path and config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
            logger.warning("Using default configuration")

    logger.warning("No configuration file found, using defaults")
    return DEFAULT_CONFIG.copy()


def get_default_config_path() -> Path:
    """Get the default configuration file path."""
    return Path(__file__).parent.parent.parent / "config.yaml"
