# Remote Server MCP

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: First](https://img.shields.io/badge/security-first-brightgreen.svg)](#security-model-)

A **security-first** MCP server that provides AI assistants with controlled, safe access to manage remote servers via SSH.

## Quick Start

```bash
# Install with dev dependencies
uv pip install -e ".[dev]" --python .venv

# Install pre-commit hooks
pre-commit install

# Configure
cp config.example.yaml config.yaml
nano config.yaml  # Add your SSH details

# Test
uv run pytest tests/ -v
```

## Security Model 🛡️

**Design Principle: Whitelist operations, don't blacklist commands.**

This server uses a **zero-trust approach**: only expose specific, safe operations that AI assistants actually need for debugging services.

### ❌ What You **CANNOT** Do

- ❌ Execute arbitrary commands on the server
- ❌ Access files outside `/srv/{service}/` directories
- ❌ Read sensitive files (`.env`, `.ssh/*`, `*.key`, `*.pem`, secrets)
- ❌ Use `sudo` or escalate privileges
- ❌ Access system files (`/etc/shadow`, `/etc/passwd`, etc.)
- ❌ Run shells (`bash`, `sh`, `python`, etc.)
- ❌ Download/upload arbitrary files
- ❌ Modify system configuration
- ❌ Use `docker exec`, `docker run`, or `docker build`

### ✅ What You **CAN** Do

- ✅ List all services in `/srv/`
- ✅ View service logs (Docker logs only)
- ✅ Check service status and resource usage
- ✅ Start/stop/restart services (Docker containers)
- ✅ Read **non-sensitive** files within `/srv/{service}/`
- ✅ List files in service directories
- ✅ Search logs for specific patterns (plain text only)
- ✅ View server health metrics (CPU, memory, disk)

### 🔒 Security Controls

1. **No Generic Command Execution** - `exec_command()` removed entirely
2. **Path Restriction** - All file access limited to `/srv/{service}/`
3. **Service Name Validation** - Only alphanumeric with hyphens/underscores
4. **Path Traversal Prevention** - Blocks `../`, symlinks, and escape attempts
5. **Sensitive File Blocking** - Patterns like `.env`, `*.key`, `secret`, `password`
6. **Command Injection Prevention** - All inputs sanitized, no shell escapes
7. **Search Pattern Sanitization** - Log searches can't inject commands
8. **Known Hosts Compatibility** - Handles ML-KEM and non-standard key formats

## Architecture

```
┌──────────────┐     ┌────────────────────────┐     ┌──────────────┐
│  AI Assistant│────▶│  MCP Server            │────▶│  SSH to      │
│  (Qwen Code) │◀────│  (Secure Tools Only)   │◀────│  Remote      │
└──────────────┘     │                        │     │  Server      │
                     │  10 Validated Tools:   │     └──────────────┘
                     │  • list_services       │
                     │  • get_service_logs    │
                     │  • get_service_status  │
                     │  • restart_service     │
                     │  • start_service       │
                     │  • stop_service        │
                     │  • get_service_file    │
                     │  • list_service_files  │
                     │  • search_service_logs │
                     │  • get_server_health   │
                     └────────────────────────┘
                            │
                     All inputs validated
                     against security policy
                     before execution
```

## Why This Approach?

**The problem with `exec_command()`:**
Even with sudo stripped and command whitelists, users could:
- Escape to shells via `cat file; bash`
- Read credentials from `.env` files
- Access SSH keys and secrets
- Use Docker to mount host filesystem
- Exploit command injection vulnerabilities

**The solution:**
Remove generic command execution entirely. Only expose **specific, safe operations** with comprehensive input validation.

## Installation

### Production Usage

```bash
uv pip install -e . --python .venv
```

### Development Setup

```bash
# Install with dev dependencies
uv pip install -e ".[dev]" --python .venv

# Install pre-commit hooks
pre-commit install
```

Dev dependencies include:
- **pytest** - Testing framework
- **ruff** - Fast linter and formatter
- **ty** - Type checker
- **pre-commit** - Git hooks

## Configuration

1. Copy the example config file:
```bash
cp config.example.yaml config.yaml
```

2. Edit `config.yaml` with your server details:
```yaml
ssh:
  host: "your-server.example.com"
  port: 22
  username: "your-username"

  # Option 1: SSH key authentication (recommended)
  key_path: "~/.ssh/id_rsa"

  # Option 2: Password authentication (less secure)
  # password: "your-password"

security:
  services_path: "/srv"  # All operations restricted to this path
  allow_generic_commands: false  # NEVER enable this
```

## Running the MCP Server

### With Qwen Code

Add to your `.qwen/settings.json`:

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "uv",
      "args": ["run", "python", "-m", "remote_server_mcp.server"],
      "cwd": "/path/to/remote-server-mcp"
    }
  }
}
```

Then restart Qwen Code.

### Standalone (for testing)

```bash
uv run python -m remote_server_mcp.server
```

## Available Tools

| Tool | Description | Safety |
|------|-------------|--------|
| `list_services` | List all services in `/srv/` | ✅ Safe |
| `get_service_logs` | Get Docker container logs | ✅ Safe, max 1000 lines |
| `get_service_status` | Get service status and resources | ✅ Safe |
| `restart_service` | Restart a Docker container | ✅ Safe, validates service |
| `start_service` | Start a Docker container | ✅ Safe |
| `stop_service` | Stop a Docker container | ✅ Safe |
| `get_service_file` | Read a file in `/srv/{service}/` | ✅ Safe, path validated |
| `list_service_files` | List files in service directory | ✅ Safe |
| `search_service_logs` | Search logs for pattern | ✅ Safe, plain text only |
| `get_server_health` | Get CPU/memory/disk metrics | ✅ Safe, no sensitive data |

## Development Workflow

```bash
# Run all tests
uv run pytest tests/ -v

# Run security tests only
uv run pytest tests/test_security.py -v

# Lint code
uv run ruff check .

# Fix linting issues
uv run ruff check --fix .

# Format code
uv run ruff format .

# Type checking
uv run ty check

# Run all checks (what pre-commit does)
uv run ruff check . && uv run ruff format . && uv run ty check && uv run pytest tests/ -v
```

## Security Deep Dive

### Service Name Validation

```python
# Only allows: alphanumeric, hyphens, underscores
SERVICE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

# Blocks:
# - Path traversal: "../etc"
# - Command injection: "app;rm -rf /"
# - Command substitution: "app$(whoami)"
# - Quote escapes: "app'quote"
# - And 15+ other attack patterns
```

### File Path Validation

```python
# All paths must be within /srv/{service}/
# Validates:
# 1. No path traversal (../)
# 2. No sensitive files (.env, *.key, etc.)
# 3. Path resolution prevents symlink escapes
# 4. Relative paths only (no absolute /etc/passwd)
```

### Command Safety

```python
# Blocked patterns include:
# - Privilege escalation: sudo, su, passwd
# - User management: useradd, usermod
# - System changes: chmod, chown, mount
# - Destructive: rm -rf, mkfs
# - Network: wget, curl
# - Shell execution: bash, sh, python, perl
# - Sensitive files: /etc/shadow, /etc/passwd
# - Command injection: ;, |, >, $(), ``
```

## Attack Scenario Tests

All these attacks are **blocked**:

```python
# Service name injection
"myapp;cat /etc/shadow"           # ❌ Blocked
"myapp$(whoami)"                  # ❌ Blocked
"myapp' && rm -rf / #"           # ❌ Blocked

# Path traversal
"../../../etc/passwd"             # ❌ Blocked
"config/../../../etc/shadow"      # ❌ Blocked
"~/.ssh/id_rsa"                   # ❌ Blocked

# Sensitive file access
".env"                            # ❌ Blocked
"secrets/api_key.txt"             # ❌ Blocked
"config/database.yml"             # ❌ Blocked (contains 'password' pattern)

# Log search injection
"'; cat /etc/passwd #"            # ❌ Blocked (sanitized)
"$(rm -rf /)"                     # ❌ Blocked (sanitized)
```

Run the tests:
```bash
uv run pytest tests/test_security.py -v
```

## Project Structure

```
remote-server-mcp/
├── src/remote_server_mcp/
│   ├── __init__.py              # Package entry point
│   ├── server.py                # MCP server with 10 secure tools
│   ├── ssh_manager.py           # SSH connection manager
│   ├── security.py              # Security validator (core logic)
│   └── config.py                # Configuration loader
│
├── tests/
│   ├── test_security.py         # 20 comprehensive security tests
│   └── test_ssh_connection.py   # 23 SSH connection tests
│
├── .pre-commit-config.yaml      # Pre-commit hooks configuration
├── config.example.yaml          # Configuration template
├── pyproject.toml               # Project dependencies
└── README.md                    # This file
```

## Testing

```bash
# All tests (43 total)
uv run pytest tests/ -v

# Security tests (20 tests)
uv run pytest tests/test_security.py -v

# SSH connection tests (23 tests)
uv run pytest tests/test_ssh_connection.py -v

# Skip integration tests (require real SSH connection)
uv run pytest tests/ -v -k "not integration"

# Verify tools are registered
uv run python test_tools.py
```

## What If I Need More Access?

**Need to run a custom command?** Edit the server code to add a new specific tool:

```python
@mcp.tool()
async def my_custom_operation(service: str, action: str) -> str:
    """A specific, safe operation."""
    if not security.validate_service_name(service):
        return "❌ Invalid service name"

    # Construct command from validated inputs
    cmd = f"your-specific-command {service} {action}"
    result = await ssh_manager.execute_safe_command(cmd)
    return result
```

**NEVER** enable `allow_generic_commands: true` in config.

## Docker Security Note

Docker itself can be a privilege escalation vector. This server:
- Only allows specific Docker commands (`ps`, `logs`, `start`, `stop`, `restart`, `inspect`, `stats`)
- Does **NOT** allow `docker exec`, `docker run`, or `docker build`
- Cannot mount host filesystem or access containers outside `/srv/`

## Troubleshooting

**Tests failing?**
```bash
uv run pytest tests/test_security.py -v
```

**Connection issues?**
```bash
# Test SSH manually
ssh -i ~/.ssh/id_rsa your-user@your-server
```

**Tools not appearing?**
- Restart Qwen Code
- Check `.qwen/settings.json` has `mcpServers` section
- Verify `config.yaml` exists with correct SSH settings

**SSH connection errors about "p must be exactly 1024, 2048, 3072, or 4096 bits long"?**
- This is a known issue with asyncssh and ML-KEM/post-quantum algorithms
- The server handles this automatically by disabling known_hosts checking
- Security trade-off: accepts any host key on first use (TOFU)

## License

MIT
