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
import json
import logging
from pathlib import Path

import aiohttp
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

# InfluxDB API endpoint whitelist (defense-in-depth)
# Limits the admin token to read-only / info endpoints only.
# Even if config or code is modified later, requests to destructive
# endpoints (/configure/database, /write_lp, etc.) are blocked here.
INFLUXDB_ALLOWED_ENDPOINTS: frozenset[str] = frozenset(
    {
        "/api/v3/query_sql",
        "/api/v3/query_influxql",
        "/health",
        "/metrics",
        "/ping",
    }
)


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
        # Use '--' to prevent Docker option injection even if service
        # validation is somehow bypassed (defense in depth)
        cmd = f"docker logs --tail {lines} -- {service} 2>&1"
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
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = (
            f"docker inspect "
            f"--format='Name: {{{{.Name}}}}\nState: {{{{.State.Status}}}}\n"
            f"Running: {{{{.State.Running}}}}\n"
            f"RestartCount: {{{{.RestartCount}}}}\n"
            f"StartedAt: {{{{.State.StartedAt}}}}' -- {service} 2>&1"
        )
        results = []
        output = await ssh_manager.execute_safe_command(cmd)
        results.append(f"=== Docker Status ===\n{output}")

        cmd = (
            f"docker stats --no-stream -- {service} "
            f"--format='CPU: {{{{.CPUPerc}}}}\nMemory: {{{{.MemUsage}}}}\n"
            f"Net I/O: {{{{.NetIO}}}}' 2>&1"
        )
        output = await ssh_manager.execute_safe_command(cmd)
        results.append(f"=== Resource Usage ===\n{output}")

        cmd = f"docker port -- {service} 2>&1 || echo 'No ports exposed'"
        output = await ssh_manager.execute_safe_command(cmd)
        results.append(f"=== Ports ===\n{output}")

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
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = f"docker restart -- {service} 2>&1"
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
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = f"docker start -- {service} 2>&1"
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
        # Use '--' to prevent Docker option injection (defense in depth)
        cmd = f"docker stop -- {service} 2>&1"
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

    # Sanitize pattern - raises ValueError if empty after sanitization
    try:
        sanitized_pattern = security.sanitize_search_pattern(pattern)
    except ValueError as e:
        return f"❌ Invalid search pattern: {e}"

    # Limit lines
    lines = min(lines, 5000)

    try:
        # Use grep with fixed strings (no regex) for safety
        cmd = (
            f"docker logs --tail {lines} -- {service} 2>&1 | "
            f"grep -F '{sanitized_pattern}'"
        )
        result = await ssh_manager.execute_safe_command(cmd)

        if not result.strip():
            return f"No matches found for '{pattern}' in last {lines} lines"

        return result
    except Exception as e:
        return f"❌ Error searching logs: {e}"


@mcp.tool()
async def query_influxdb(query: str, database: str | None = None) -> str:
    """Query InfluxDB v3 using SQL (read-only).

    Executes a SELECT query against the InfluxDB v3 HTTP API.
    Requires influxdb to be enabled in config.yaml.

    Args:
        query: SQL query (must start with SELECT)
        database: Database name (overrides config default)

    Returns:
        Query results in JSON format
    """
    influxdb_config = config.get("influxdb", {})
    if not influxdb_config.get("enabled", False):
        return (
            "❌ InfluxDB queries are not enabled.\n"
            "Set 'influxdb.enabled: true' in config.yaml and configure host/port."
        )

    # Validate the query
    validated_query = security.validate_influxdb_query(query)
    if validated_query is None:
        return (
            "❌ Invalid query. Queries must:\n"
            "- Start with SELECT (read-only only)\n"
            "- Not contain SQL injection characters (;, --, /*, etc.)\n"
            "- Not contain shell injection characters"
        )

    db = database or influxdb_config.get("database")
    if not db:
        return (
            "❌ No database specified. Provide 'database' parameter or set "
            "'influxdb.database' in config.yaml."
        )

    host = influxdb_config.get("host", "localhost")
    port = influxdb_config.get("port", 8181)
    use_https = influxdb_config.get("use_https", False)
    token = influxdb_config.get("token")
    limit = min(influxdb_config.get("query_limit", 1000), 10000)

    scheme = "https" if use_https else "http"
    path = "/api/v3/query_sql"
    url = f"{scheme}://{host}:{port}{path}"

    # Defense-in-depth: whitelist the endpoint so even if the path
    # construction changes, requests to admin/write endpoints are blocked
    if path not in INFLUXDB_ALLOWED_ENDPOINTS:
        return f"❌ Blocked: endpoint '{path}' is not in the allowed whitelist"

    params = {
        "db": db,
        "q": validated_query,
        "limit": limit,
    }

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, json=params, headers=headers, timeout=30
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    formatted = json.dumps(data, indent=2)
                    return f"✅ Query successful\n\n{formatted}"
                else:
                    error_body = await response.text()

                    # Prepend a hint for unbounded queries that fail.
                    # This is additive — the original error body is preserved
                    # verbatim, so Enterprise users see the real response too.
                    hint = ""
                    query_lower = validated_query.lower()
                    has_time_filter = "where" in query_lower and "time" in query_lower
                    if not has_time_filter:
                        hint = (
                            "💡 Tip: InfluxDB 3 Core has a file-scan limit. "
                            "Queries without a `WHERE time` clause may fail "
                            "with HTTP 500. Add a time range like:\n"
                            "   WHERE time > now() - INTERVAL '1 hour'\n\n"
                        )

                    return (
                        f"{hint}"
                        f"❌ InfluxDB query failed (HTTP {response.status})\n"
                        f"{error_body[:2000]}"
                    )
    except aiohttp.ClientError as e:
        return f"❌ Connection error: {e}"
    except TimeoutError:
        return "❌ Query timed out after 30 seconds"


@mcp.tool()
async def query_prometheus(query: str, time: str | None = None) -> str:
    """Query Prometheus using PromQL (read-only).

    Executes an instant query against the Prometheus HTTP API.
    Requires prometheus to be enabled in config.yaml.

    Args:
        query: PromQL expression
        time: Optional RFC3339 timestamp or Unix timestamp (defaults to now)

    Returns:
        Query results in JSON format
    """
    prometheus_config = config.get("prometheus", {})
    if not prometheus_config.get("enabled", False):
        return (
            "❌ Prometheus queries are not enabled.\n"
            "Set 'prometheus.enabled: true' in config.yaml and configure host/port."
        )

    # Validate the query
    validated_query = security.validate_prometheus_query(query)
    if validated_query is None:
        return (
            "❌ Invalid query. Queries must:\n"
            "- Not contain shell injection characters (;, `, $, |, etc.)\n"
            "- Not contain quotes or newlines"
        )

    host = prometheus_config.get("host", "localhost")
    port = prometheus_config.get("port", 9090)
    use_https = prometheus_config.get("use_https", False)
    token = prometheus_config.get("token")

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/api/v1/query"

    params: dict[str, str] = {"query": validated_query}
    if time:
        params["time"] = time

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, params=params, headers=headers, timeout=30
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        formatted = json.dumps(data["data"], indent=2)
                        return f"✅ Query successful\n\n{formatted}"
                    else:
                        error_type = data.get("errorType", "unknown")
                        error_msg = data.get("error", "Unknown error")
                        return (
                            f"❌ PromQL query error\n"
                            f"Type: {error_type}\n"
                            f"Error: {error_msg}"
                        )
                else:
                    error_body = await response.text()
                    return (
                        f"❌ Prometheus query failed (HTTP {response.status})\n"
                        f"{error_body[:2000]}"
                    )
    except aiohttp.ClientError as e:
        return f"❌ Connection error: {e}"
    except TimeoutError:
        return "❌ Query timed out after 30 seconds"


@mcp.tool()
async def get_prometheus_targets() -> str:
    """Get scrape targets from Prometheus.

    Returns the list of all configured scrape targets and their current state.
    Requires prometheus to be enabled in config.yaml.

    Returns:
        List of scrape targets with their status
    """
    prometheus_config = config.get("prometheus", {})
    if not prometheus_config.get("enabled", False):
        return (
            "❌ Prometheus queries are not enabled.\n"
            "Set 'prometheus.enabled: true' in config.yaml and configure host/port."
        )

    host = prometheus_config.get("host", "localhost")
    port = prometheus_config.get("port", 9090)
    use_https = prometheus_config.get("use_https", False)
    token = prometheus_config.get("token")

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/api/v1/targets"

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        targets = data.get("data", {}).get("activeTargets", [])
                        if not targets:
                            return "No active targets configured in Prometheus."

                        # Format target summary
                        lines = [f"✅ Found {len(targets)} active targets:\n"]
                        for target in targets:
                            labels = target.get("labels", {})
                            job = labels.get("job", "unknown")
                            instance = labels.get("instance", "unknown")
                            health = target.get("health", "unknown")
                            last_error = target.get("lastError", "")
                            lines.append(
                                f"  • {job}/{instance}: {health}"
                                + (f" ({last_error})" if last_error else "")
                            )
                        return "\n".join(lines)
                    else:
                        return f"❌ Unexpected response: {json.dumps(data, indent=2)}"
                else:
                    error_body = await response.text()
                    return (
                        f"❌ Failed to get targets (HTTP {response.status})\n"
                        f"{error_body[:2000]}"
                    )
    except aiohttp.ClientError as e:
        return f"❌ Connection error: {e}"
    except TimeoutError:
        return "❌ Request timed out after 30 seconds"


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
        "list_service_files, search_service_logs, get_server_health, "
        "query_influxdb, query_prometheus, get_prometheus_targets"
    )
    await mcp.run_stdio_async()


if __name__ == "__main__":
    asyncio.run(main())
