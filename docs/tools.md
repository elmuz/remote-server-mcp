# Available Tools

All tools validate inputs against the security policy before execution. See [security-model.md](security-model.md) for details.

| Tool | Description | Safety Notes |
|------|-------------|--------------|
| `list_services` | List all service directories in `/srv/` and their Docker status | No input parameters |
| `get_service_logs` | Get Docker container logs for a service | Service validated; max 1000 lines |
| `get_service_status` | Get service status, resource usage, and exposed ports | Service validated; multiple Docker queries |
| `restart_service` | Restart a Docker container | Service validated |
| `start_service` | Start a stopped Docker container | Service validated |
| `stop_service` | Stop a running Docker container | Service validated |
| `get_service_file` | Read a file within `/srv/{service}/` | Path validated; sensitive files blocked |
| `list_service_files` | List files in a service directory | Subdirectory path validated |
| `search_service_logs` | Search logs for a plain-text pattern | Pattern sanitized; max 5000 lines |
| `get_server_health` | Get CPU, memory, disk metrics | No sensitive data exposed |

## Tool Details

### `list_services()`

Returns a list of directories under `/srv/` and the status of Docker containers. No parameters required.

### `get_service_logs(service, lines=100)`

- **service**: Validated service name
- **lines**: Capped at 1000

Command: `docker logs --tail {lines} -- {service}`

### `get_service_status(service)`

Runs three Docker queries:
1. `docker inspect` for container state
2. `docker stats` for CPU/memory/network
3. `docker port` for exposed ports

### `restart_service(service)` / `start_service(service)` / `stop_service(service)`

Simple Docker lifecycle commands with service validation.

### `get_service_file(service, file_path)`

- Validates `file_path` is relative and within `/srv/{service}/`
- Blocks sensitive file patterns (`.env`, `.git/`, `*.key`, etc.)
- Resolves path to prevent traversal escapes

### `list_service_files(service, subdirectory="")`

- Lists files in `/srv/{service}/` or a validated subdirectory
- Subdirectory goes through full path validation

### `search_service_logs(service, pattern, lines=1000)`

- **pattern**: Stripped of shell-special characters; must not be empty after sanitization
- **lines**: Capped at 5000
- Uses `grep -F` (fixed strings, no regex)

### `get_server_health()`

Returns:
- System uptime
- Memory usage (`free -h`)
- Disk usage for `/srv` (`df -h`)
- Running Docker services

No sensitive data is included in the output.
