# Matrix Gateway Test Harness

This directory contains a self-contained Docker Compose test harness for the Hermes Matrix gateway integration. It brings up a local Conduit Matrix homeserver and the Hermes gateway side-by-side, enabling integration testing without external dependencies.

## Architecture

The test harness consists of two main services:

### 1. Conduit Homeserver
- **Image**: `matrixconduit/matrix-conduit:latest`
- **Port**: 6167 (internal only)
- **Purpose**: Lightweight Matrix homeserver written in Rust
- **Features**:
  - Single container, no external dependencies
  - Fast boot time (<10s)
  - Healthcheck ensures readiness before tests run
  - Registration enabled (`allow_registration=true`)
  - Federation disabled (test-only environment)
  - Persistent data in Docker volume

### 2. Gateway Test Container
- **Image**: Built from `Dockerfile.gateway`
- **Purpose**: Runs Hermes gateway tests
- **Features**:
  - Python 3.11+ environment
  - Mounts hermes-agent source code read-only
  - Pre-installed: pytest, pytest-asyncio, mautrix
  - Waits for homeserver health check before starting

## Network Topology

```
┌─────────────────────────────────────────────────┐
│           matrix-test (bridge network)          │
│                                                  │
│  ┌─────────────┐        ┌──────────────────┐   │
│  │   Conduit   │◄───────│   Gateway Test   │   │
│  │  :6167      │        │   Container      │   │
│  └─────────────┘        └──────────────────┘   │
│     HS Port               Mounts:              │
│                            /hermes (ro)        │
└─────────────────────────────────────────────────┘
```

Both services communicate via the internal `matrix-test` bridge network. The homeserver port 6167 is NOT exposed to the host machine, ensuring the test environment is isolated.

## Quick Start

### 1. Start the Test Environment

```bash
cd test-harness
docker compose up -d --wait
```

This will:
- Pull/build the necessary images
- Start both services
- Wait for the homeserver to be healthy (~10-20s)

### 2. Run the Smoke Test

```bash
docker compose exec gateway pytest -v tests/gateway/test_matrix_smoke.py
```

Or run all Matrix tests:

```bash
docker compose exec gateway pytest -v tests/gateway/
```

### 3. Stop and Clean Up

```bash
docker compose down -v
```

The `-v` flag removes the homeserver data volume, ensuring a clean slate for the next run.

## Environment Variables

The gateway container uses these environment variables (configurable in `docker-compose.yml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `HERMES_HS_URL` | `http://conduit:6167` | Homeserver URL |
| `HERMES_MATRIX_USER` | `@gateway:conduit` | Gateway user MXID |
| `HERMES_MATRIX_PASSWORD` | `gateway_password` | Gateway user password |
| `HERMES_ADMIN_USERNAME` | `admin` | Admin username (optional) |
| `HERMES_ADMIN_PASSWORD` | `admin_password` | Admin password (optional) |

## Pytest Fixtures

The test harness provides reusable pytest fixtures in `tests/conftest.py`:

### Session-scoped Fixtures

#### `hs_url()`
Returns the homeserver URL from environment or default.

#### `admin_username()` / `admin_password()`
Admin credentials for test setup (optional).

#### `gateway_username()` / `gateway_password()`
Gateway user credentials for testing.

#### `admin_client()` (async)
Creates and authenticates an admin Matrix client with privileges for test setup.

#### `gateway_client()` (async)
Creates and authenticates the gateway Matrix client, handling registration if needed.

### Function-scoped Fixtures

#### `test_room()` (async)
Creates a new test room for each test function and automatically cleans it up afterward.

## Test Pattern for HERMES-GW-N Tickets

When implementing new HERMES-GW-N features, follow this pattern:

1. **Create a new test file** under `tests/gateway/`, e.g., `tests/gateway/test_matrix_rooms.py`
2. **Import fixtures** from `tests/conftest.py`:
   ```python
   import pytest
   from mautrix.types import RoomID

   @pytest.mark.asyncio
   async def test_my_feature(gateway_client, test_room: RoomID):
       # Your test code here
       pass
   ```
3. **Run your tests**:
   ```bash
   docker compose exec gateway pytest -v tests/gateway/test_matrix_rooms.py
   ```
4. **Use the fixtures**:
   - `gateway_client`: Already authenticated Matrix client
   - `test_room`: Auto-created and auto-cleaned room
   - `admin_client`: For admin operations if needed

## Troubleshooting

### Gateway container exits immediately

Check if the homeserver is healthy:
```bash
docker compose ps
docker compose logs conduwuit
```

### Tests fail with "Failed to both login and register"

The homeserver might not have registration enabled. Check the `CONDUIT_ALLOW_REGISTRATION=true` environment variable in `docker-compose.yml`.

### Volume cleanup issues

Force remove all volumes:
```bash
docker compose down -v
docker volume prune -f
```

### Conduit image changes

If the latest Conduit image changes behavior, pin a specific version:
```yaml
services:
  conduwuit:
    image: matrixconduit/matrix-conduit:v0.6.0  # Pin version
```

Document the working version in this README.

## Isolation Guarantees

The test harness ensures:
- ✅ No external network access (no real Matrix.org)
- ✅ No real LLM providers
- ✅ All communication stays within the compose network
- ✅ Clean state on each `docker compose down -v`
- ✅ Read-only source code mount in gateway container

## Notes on Conduit Homeserver

This harness uses Conduit, a lightweight Matrix homeserver written in Rust. Conduit offers:
- Single container deployment
- No external dependencies
- Fast boot time (<10s)
- Low resource requirements
- Active development

The `matrixconduit/matrix-conduit:latest` image is used. This is the original Conduit project, which is well-maintained and widely used for testing purposes. If you encounter issues, check the [Conduit documentation](https://conduit.rs/) for the latest configuration options.

**Note**: Conduwuit is a maintained fork of Conduit, but the original Conduit image is used here as it's freely available without authentication requirements and provides a stable base for testing.
