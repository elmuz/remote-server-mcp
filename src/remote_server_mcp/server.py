"""
MCP Server for Remote Server Management

SECURITY MODEL:
- NO generic command execution
- ONLY specific, safe operations
- All paths restricted to /srv/* and explicit safe paths
- No access to credentials, keys, or sensitive system files
- Docker operations limited to service management (not arbitrary commands)

Design Principle: Whitelist operations, don't blacklist commands.
"""

import asyncio
import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .config import load_config
from .security import SecurityValidator
from .ssh_manager import SSHManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
config_path = Path(__file__).parent.parent.parent / "config.yaml"
config = load_config(config_path)

# Initialize security validator
security = SecurityValidator(config)

# Initialize SSH manager
ssh_manager = SSHManager(config, security)

# Create MCP server
mcp = FastMCP("remote-server-mcp")


@mcp.tool()
async def list_services() -> str:
    """List all services in /srv/ directory.

    Returns:
        List of service directories and their status
    """
    try:
        cmd = (
            "ls -1 /srv/ 2>&1 && "
            "echo '---DOCKER STATUS---' && "
            "docker ps --format '{{.Names}}\t{{.Status}}' 2>&1"
        )
        result = await ssh_manager.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error listing services: {e}"


@mcp.tool()
async def get_service_logs(service: str, lines: int = 100) -> str:
    """Get logs for a specific service.

    Args:
        service: Service name (must exist in /srv/)
        lines: Number of log lines to retrieve (default: 100, max: 1000)

    Returns:
        Service logs
    """
    # Validate service name
    if not security.validate_service_name(service):
        msg = (
            f"❌ Invalid service name: {service}\n"
            "Service must be alphanumeric with hyphens/underscores only."
        )
        return msg

    # Check service exists
    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return f"❌ Service '{service}' does not exist in /srv/"

    # Limit lines to prevent abuse
    lines = min(lines, 1000)

    try:
        cmd = f"docker logs --tail {lines} {service} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error getting logs: {e}"


@mcp.tool()
async def get_service_status(service: str) -> str:
    """Get detailed status of a specific service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Service status including Docker state and resource usage
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return f"❌ Service '{service}' does not exist in /srv/"

    try:
        commands = [
            (
                f"echo '=== Docker Status ===' && docker inspect "
                f"--format='Name: {{{{.Name}}}}\nState: {{{{.State.Status}}}}\n"
                f"Running: {{{{.State.Running}}}}\n"
                f"RestartCount: {{{{.RestartCount}}}}\n"
                f"StartedAt: {{{{.State.StartedAt}}}}' {service} 2>&1"
            ),
            (
                f"echo '=== Resource Usage ===' && docker stats --no-stream {service} "
                f"--format='CPU: {{{{.CPUPerc}}}}\nMemory: {{{{.MemUsage}}}}\n"
                f"Net I/O: {{{{.NetIO}}}}' 2>&1"
            ),
            (
                f"echo '=== Ports ===' && docker port {service} "
                f"2>&1 || echo 'No ports exposed'"
            ),
        ]

        results = []
        for cmd in commands:
            output = await ssh_manager.execute_safe_command(cmd)
            results.append(output)

        return "\n\n".join(results)
    except Exception as e:
        return f"❌ Error getting service status: {e}"


@mcp.tool()
async def restart_service(service: str) -> str:
    """Restart a service (Docker container).

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Restart result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return f"❌ Service '{service}' does not exist in /srv/"

    try:
        cmd = f"docker restart {service} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return f"✅ Service '{service}' restarted\n{result}"
    except Exception as e:
        return f"❌ Error restarting service: {e}"


@mcp.tool()
async def start_service(service: str) -> str:
    """Start a stopped service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Start result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return f"❌ Service '{service}' does not exist in /srv/"

    try:
        cmd = f"docker start {service} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return f"✅ Service '{service}' started\n{result}"
    except Exception as e:
        return f"❌ Error starting service: {e}"


@mcp.tool()
async def stop_service(service: str) -> str:
    """Stop a running service.

    Args:
        service: Service name (must exist in /srv/)

    Returns:
        Stop result
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return f"❌ Service '{service}' does not exist in /srv/"

    try:
        cmd = f"docker stop {service} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return f"✅ Service '{service}' stopped\n{result}"
    except Exception as e:
        return f"❌ Error stopping service: {e}"


@mcp.tool()
async def get_service_file(service: str, file_path: str) -> str:
    """Get the contents of a file within a service directory.

    Args:
        service: Service name (must exist in /srv/)
        file_path: Relative path within /srv/{service}/ (e.g., 'docker-compose.yml')

    Returns:
        File contents
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    # Construct and validate full path
    full_path = security.validate_service_file_path(service, file_path)
    if full_path is None:
        return f"❌ Invalid file path: {file_path}\nFile must be within /srv/{service}/"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return f"❌ Service '{service}' does not exist in /srv/"

    try:
        cmd = f"cat {full_path} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error reading file: {e}"


@mcp.tool()
async def list_service_files(service: str, subdirectory: str = "") -> str:
    """List files in a service directory.

    Args:
        service: Service name (must exist in /srv/)
        subdirectory: Optional subdirectory within /srv/{service}/

    Returns:
        List of files
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    # Validate subdirectory path
    if subdirectory:
        full_path = security.validate_service_file_path(service, subdirectory)
        if full_path is None:
            return (
                f"❌ Invalid subdirectory: {subdirectory}\n"
                f"Must be within /srv/{service}/"
            )
    else:
        full_path = f"/srv/{service}"

    exists = await ssh_manager.check_service_exists(service)
    if not exists:
        return f"❌ Service '{service}' does not exist in /srv/"

    try:
        cmd = f"ls -lah {full_path} 2>&1"
        result = await ssh_manager.execute_safe_command(cmd)
        return result
    except Exception as e:
        return f"❌ Error listing files: {e}"


@mcp.tool()
async def search_service_logs(service: str, pattern: str, lines: int = 1000) -> str:
    """Search service logs for a specific pattern.

    Args:
        service: Service name (must exist in /srv/)
        pattern: Text pattern to search for (no regex, plain text only)
        lines: Number of log lines to search (default: 1000, max: 5000)

    Returns:
        Matching log lines
    """
    if not security.validate_service_name(service):
        return f"❌ Invalid service name: {service}"

    # Sanitize pattern - escape any shell special characters
    sanitized_pattern = security.sanitize_search_pattern(pattern)

    # Limit lines
    lines = min(lines, 5000)

    try:
        # Use grep with fixed strings (no regex) for safety
        cmd = (
            f"docker logs --tail {lines} {service} 2>&1 | grep -F '{sanitized_pattern}'"
        )
        result = await ssh_manager.execute_safe_command(cmd)

        if not result.strip():
            return f"No matches found for '{pattern}' in last {lines} lines"

        return result
    except Exception as e:
        return f"❌ Error searching logs: {e}"


@mcp.tool()
async def get_server_health() -> str:
    """Get overall server health (CPU, memory, disk) - no sensitive data.

    Returns:
        Server health metrics only
    """
    try:
        commands = [
            "echo '=== System Uptime ===' && uptime",
            "echo '=== Memory Usage ===' && free -h",
            "echo '=== Disk Usage ===' && df -h /srv",
            (
                "echo '=== Running Services ===' && docker ps "
                "--format '{{.Names}} ({{.Status}})'"
            ),
        ]

        results = []
        for cmd in commands:
            output = await ssh_manager.execute_safe_command(cmd)
            results.append(output)

        return "\n\n".join(results)
    except Exception as e:
        return f"❌ Error getting server health: {e}"


async def main():
    """Run the MCP server."""
    # Test SSH connection on startup
    logger.info("Testing SSH connection...")
    try:
        result = await ssh_manager.execute_safe_command("echo 'Connection successful'")
        logger.info(f"SSH connection test: {result.strip()}")
    except Exception as e:
        logger.warning(f"SSH connection test failed: {e}")
        logger.warning(
            "Server will start anyway, but tools may fail until SSH is configured"
        )

    logger.info("Starting Remote Server MCP (SECURE MODE)...")
    logger.info(
        "Available tools: list_services, get_service_logs, get_service_status, "
        "restart_service, start_service, stop_service, get_service_file, "
        "list_service_files, search_service_logs, get_server_health"
    )
    await mcp.run_stdio_async()


if __name__ == "__main__":
    asyncio.run(main())
