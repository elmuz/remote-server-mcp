# Playground Agents - Remote Server MCP

## Project Overview

**remote-server-mcp** is a security-first MCP (Model Context Protocol) server for managing remote servers via SSH. It provides AI assistants with controlled, safe operations for debugging services without exposing credentials or allowing dangerous commands.

This is the **main project** in this directory, not a subagent. It's a complete MCP server that can be used with Qwen Code, Claude Desktop, or any MCP client.

## Development Workflow

### Quick Start

```bash
# Install with dev dependencies
uv pip install -e ".[dev]" --python .venv

# Install pre-commit hooks
pre-commit install
```

### Development Commands

```bash
# Run tests
uv run pytest tests/ -v

# Run security tests only
uv run pytest tests/test_security.py -v

# Run linting
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

### Pre-commit Hooks

Pre-commit hooks run automatically on `git commit`:

- **ruff**: Linting and formatting
- **ty**: Type checking
- **pytest**: Run all tests

To run manually:

```bash
pre-commit run --all-files
```

## Security Philosophy

**Zero-trust design:**
- ❌ NO generic command execution
- ✅ ONLY specific, validated operations
- 🔒 All paths restricted to `/srv/{service}/`
- 🛡️ Comprehensive input validation and sanitization

See `README.md` for full security documentation.

## Quick Start (Server)

### 1. Install

```bash
uv pip install -e . --python .venv
```

### 2. Configure

```bash
cp config.example.yaml config.yaml
nano config.yaml  # Add your SSH details
```

### 3. Test

```bash
# Run security tests
uv run pytest tests/test_security.py -v

# Verify tools
uv run python test_tools.py
```

### 4. Use with Qwen Code

Already configured in `.qwen/settings.json`. Just restart Qwen Code!

## Available Tools

| Tool | Purpose |
|------|---------|
| `list_services` | List services in `/srv/` |
| `get_service_logs` | Get Docker container logs |
| `get_service_status` | Check service status |
| `restart_service` | Restart container |
| `start_service` | Start container |
| `stop_service` | Stop container |
| `get_service_file` | Read service files |
| `list_service_files` | List service files |
| `search_service_logs` | Search logs |
| `get_server_health` | Server metrics |
| `query_influxdb` | Query InfluxDB v3 via SQL (read-only) |
| `query_prometheus` | Query Prometheus via PromQL |
| `get_prometheus_targets` | List Prometheus scrape targets |

## Architecture

```text
src/remote_server_mcp/
├── server.py              # MCP server (10 tools)
├── ssh_manager.py         # SSH connection handler
├── security.py            # Security validator
└── config.py              # Configuration loader

tests/
└── test_security.py       # 20 security tests
```

## Security Controls

1. **No exec_command()** - Removed entirely
2. **Path restriction** - `/srv/{service}/` only
3. **Service validation** - Alphanumeric + hyphens/underscores
4. **Path traversal prevention** - Blocks `../` and escapes
5. **Sensitive file blocking** - `.env`, `*.key`, etc.
6. **Command injection prevention** - All inputs sanitized
7. **Docker restrictions** - Only safe commands allowed

## Testing

```bash
# All tests
uv run pytest tests/ -v

# Security tests only
uv run pytest tests/test_security.py -v

# Coverage report
uv run pytest tests/ --cov=remote_server_mcp
```

## What is MCP?

**MCP (Model Context Protocol)** is an open standard for connecting AI assistants to external tools. Works with:
- Qwen Code ✅
- Claude Desktop ✅
- Any MCP client ✅

Learn more: [modelcontextprotocol.io](https://modelcontextprotocol.io)

## Development

### Adding New Tools

Add a decorated function in `server.py`:

```python
@mcp.tool()
async def my_new_tool(service: str) -> str:
    """Description of the tool."""
    if not security.validate_service_name(service):
        return "❌ Invalid service name"
    
    cmd = f"safe-command {service}"
    return await ssh_manager.execute_safe_command(cmd)
```

### Security Requirements

All tools MUST:
1. Validate service names with `security.validate_service_name()`
2. Validate file paths with `security.validate_service_file_path()`
3. Use `ssh_manager.execute_safe_command()` (never raw execution)
4. NOT expose sensitive data
5. NOT allow command injection

### Pre-commit Verification

**Every time you finalize a feature or bugfix, run the full check suite:**

```bash
uv run ruff check . && uv run ruff format --check . && uv run ty check && uv run pymarkdown -c .pymarkdown scan . && uv run python scripts/check_md_links.py && uv run pytest tests/ -v --tb=short
```

This runs all pre-commit hooks in order:

| Check | Tool | What it catches |
|-------|------|----------------|
| Lint | `ruff check` | Style errors, unused imports, ambiguous characters |
| Format | `ruff format` | Code formatting consistency |
| Types | `ty check` | Type mismatches, invalid assignments |
| Markdown | `pymarkdown scan` | Formatting, heading duplicates, code block languages |
| Links | `check_md_links.py` | Broken relative links and anchors |
| Tests | `pytest` | Regressions, new test coverage |

**All must pass before committing.** If any fail, fix the issues first — never commit on a broken state.

## License

MIT
