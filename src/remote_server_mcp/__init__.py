"""
Remote Server MCP - Main entry point
"""

import asyncio

from .server import main, mcp

__version__ = "0.1.0"

__all__ = ["__version__", "main", "mcp"]

if __name__ == "__main__":
    asyncio.run(main())
