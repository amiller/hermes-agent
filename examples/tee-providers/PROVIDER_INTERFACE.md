# Hermes Agent Provider Interface

## Overview

This document summarizes the minimum contract a new provider must satisfy to integrate with Hermes Agent, based on analysis of the existing codebase (April 2026).

## Provider Registration Point

**File:** `hermes_cli/auth.py` (lines 90-138)

Providers are registered in the `PROVIDER_REGISTRY` dictionary:

```python
PROVIDER_REGISTRY: Dict[str, ProviderConfig] = {
    "nous": ProviderConfig(...),
    "zai": ProviderConfig(...),
    "kimi-coding": ProviderConfig(...),
    "minimax": ProviderConfig(...),
    "minimax-cn": ProviderConfig(...),
}
```

## ProviderConfig Schema

**File:** `hermes_cli/auth.py` (lines 73-88)

```python
@dataclass
class ProviderConfig:
    id: str                           # Unique provider identifier (e.g., "zai")
    name: str                         # Human-readable name (e.g., "Z.AI / GLM")
    auth_type: str                    # "oauth_device_code", "oauth_external", or "api_key"
    portal_base_url: str = ""         # OAuth: portal URL
    inference_base_url: str = ""      # API base URL for inference
    client_id: str = ""               # OAuth: client ID
    scope: str = ""                   # OAuth: OAuth scope
    extra: Dict[str, Any] = field(default_factory=dict)
    api_key_env_vars: tuple = ()      # For api_key providers: env vars to check
    base_url_env_var: str = ""        # Optional env var for base URL override
```

## Required Methods

### 1. Runtime Credential Resolution

**Function:** `resolve_<provider_id>_runtime_credentials()`

**File:** `hermes_cli/auth.py` (lines 1413-1451 for API key providers)

Returns a dictionary with:
```python
{
    "provider": str,        # Provider ID
    "api_key": str,         # API key or access token
    "base_url": str,        # Inference API base URL
    "source": str,          # Credential source (e.g., "env", "portal")
    # Optional fields:
    "expires_at": str,      # ISO timestamp for token expiry
    "expires_in": int,      # Seconds until expiry
    "key_id": str,          # Key identifier (for traceability)
}
```

**Usage:** Called from `hermes_cli/runtime_provider.py` (line 118-162)

### 2. Provider Resolution

**Function:** `resolve_provider()` (auth.py, lines 458-521)

This function determines which provider to use based on:
1. Active provider in auth store (OAuth)
2. Explicit CLI API key/base URL
3. Environment variables (OPENAI_API_KEY, OPENROUTER_API_KEY, etc.)
4. Provider-specific env vars (from ProviderConfig.api_key_env_vars)
5. Fallback to "openrouter"

### 3. Auth Status (Optional but Recommended)

**Function:** `get_<provider_id>_auth_status()`

**File:** `hermes_cli/auth.py` (lines 1363-1396 for API key providers)

Returns:
```python
{
    "configured": bool,     # Whether credentials are present
    "provider": str,        # Provider ID
    "name": str,            # Human-readable name
    "key_source": str,      # Which env var provided the key
    "base_url": str,        # Resolved base URL
    "logged_in": bool,      # For OAuth providers
}
```

## Integration Points

### Runtime Provider Resolution

**File:** `hermes_cli/runtime_provider.py` (lines 109-170)

The `resolve_runtime_provider()` function:
1. Calls `resolve_provider()` to pick the active provider
2. Dispatches to the appropriate `resolve_*_runtime_credentials()` function
3. Returns a standardized runtime provider dict

### CLI Integration

**File:** `cli.py` (line references vary by version)

Providers are exposed via:
- `--provider` flag for explicit provider selection
- `HERMES_INFERENCE_PROVIDER` environment variable
- `model.provider` config field

## Minimum Contract for New Provider

To add a new provider to Hermes Agent:

1. **Add ProviderConfig entry** to `PROVIDER_REGISTRY` in `hermes_cli/auth.py`
2. **Implement credential resolution** function following the `resolve_api_key_provider_credentials()` pattern (for API key providers) or OAuth patterns
3. **Add provider alias mapping** in `resolve_provider()` (line 477-481) if needed
4. **Implement status function** (optional but recommended) for `hermes status` output
5. **Add dispatch logic** in `resolve_runtime_provider()` (runtime_provider.py, lines 151-162)

## Example: API Key Provider (Z.AI)

**Reference:** `hermes_cli/auth.py` (lines 106-113)

```python
"zai": ProviderConfig(
    id="zai",
    name="Z.AI / GLM",
    auth_type="api_key",
    inference_base_url="https://api.z.ai/api/paas/v4",
    api_key_env_vars=("GLM_API_KEY", "ZAI_API_KEY", "Z_AI_API_KEY"),
    base_url_env_var="GLM_BASE_URL",
),
```

## Notes for TEE-Validating Providers

A TEE-validating provider would need to:

1. Extend the ProviderConfig with additional fields for attestation configuration
2. Implement attestation verification in the credential resolution flow
3. Potentially add a new `attestation_mode` auth_type or extend the existing types
4. Handle attestation failures gracefully (raise AuthError with appropriate code)
5. Consider adding attestation metadata to the runtime provider dict (e.g., `attestation_report`)

The provider interface is intentionally flexible - the core requirement is that `resolve_runtime_provider()` returns a dict with the standard keys that the rest of Hermes expects.
