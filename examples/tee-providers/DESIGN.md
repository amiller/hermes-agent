# Provider Attestation Capability Design

## Overview

This document proposes a `provider.attestation` capability for upstream Hermes Agent that enables TEE (Trusted Execution Environment) attestation verification before trusting inference outputs from remote providers.

## Motivation

As AI inference moves to cloud TEEs (Intel TDX, AMD SEV, etc.), agents need to:
1. Verify they're communicating with genuine TEE-protected endpoints
2. Ensure code and data haven't been tampered with
3. Validate hardware attestation from trusted sources
4. Fail securely when attestation fails

## Proposed Interface

### Config Schema Addition

Extend `~/.hermes/config.yaml` model configuration:

```yaml
model:
  provider: "near-ai"  # or "openrouter", "nous", etc.
  default: "deepseek-ai/DeepSeek-V3.1"
  attestation:
    enabled: true
    strict: false  # If true, fail on attestation error
    verify_tls_binding: true  # Verify gateway TLS certificate
    verify_gpu: true  # Verify GPU attestation (H100/H200)
    allow_insecure: false  # Development flag
```

### ProviderConfig Extension

Extend `ProviderConfig` in `hermes_cli/auth.py`:

```python
@dataclass
class ProviderConfig:
    # ... existing fields ...
    attestation_config: Optional[Dict[str, Any]] = None  # New field
    # Example:
    # {
    #     "type": "tdx",  # or "sev", "nitro"
    #     "endpoint": "/v1/attestation/report",
    #     "verifier": "nearai",  # or "custom"
    # }
```

## Provider Resolution Flow

### Current Flow

```
resolve_requested_provider()
  → resolve_provider()
  → resolve_*_runtime_credentials()
  → return {provider, api_key, base_url, ...}
```

### Proposed Flow

```
resolve_requested_provider()
  → resolve_provider()
  → resolve_*_runtime_credentials()
  → verify_attestation_if_enabled()  # NEW
  → return {provider, api_key, base_url, attestation_report, ...}
```

## Implementation

### 1. New Module: `hermes_cli/attestation.py`

```python
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class AttestationReport:
    """TEE attestation verification result."""
    valid: bool
    provider: str
    attestation_type: str  # "tdx", "sev", "nitro", "none"
    verified_at: str  # ISO timestamp
    details: Dict[str, Any]
    error: Optional[str] = None

def verify_attestation(
    provider_id: str,
    runtime_creds: Dict[str, Any],
    config: Dict[str, Any],
) -> AttestationReport:
    """
    Verify TEE attestation for a provider.

    Args:
        provider_id: Provider identifier (e.g., "near-ai")
        runtime_creds: Runtime credentials from resolve_*_runtime_credentials()
        config: Attestation configuration from model.attestation

    Returns:
        AttestationReport with verification result
    """
    # Dispatch to provider-specific verifier
    if provider_id == "near-ai":
        return _verify_near_ai_attestation(runtime_creds, config)
    elif provider_id == "openrouter":
        return _skip_attestation("no-tee-support")
    else:
        return _skip_attestation("not-implemented")
```

### 2. Integration in `runtime_provider.py`

Modify `resolve_runtime_provider()`:

```python
def resolve_runtime_provider(
    *,
    requested: Optional[str] = None,
    explicit_api_key: Optional[str] = None,
    explicit_base_url: Optional[str] = None,
    verify_attestation: bool = True,  # NEW
) -> Dict[str, Any]:
    """Resolve runtime provider credentials with optional attestation."""
    requested_provider = resolve_requested_provider(requested)

    provider = resolve_provider(
        requested_provider,
        explicit_api_key=explicit_api_key,
        explicit_base_url=explicit_base_url,
    )

    # Resolve credentials
    if provider == "nous":
        creds = resolve_nous_runtime_credentials(...)
    # ... other providers ...

    # NEW: Verify attestation if enabled
    if verify_attestation:
        attestation_config = _get_attestation_config(provider)
        if attestation_config.get("enabled", False):
            attestation_report = verify_attestation(provider, creds, attestation_config)
            if not attestation_report.valid and attestation_config.get("strict", False):
                raise AuthError(
                    f"Attestation verification failed: {attestation_report.error}",
                    provider=provider,
                    code="attestation_failed",
                )
            creds["attestation"] = attestation_report

    return creds
```

### 3. Configuration Loading

Add to `hermes_cli/config.py`:

```python
def get_attestation_config(provider_id: str) -> Dict[str, Any]:
    """Load attestation configuration for a provider."""
    config = load_config()
    model_cfg = config.get("model", {})

    if isinstance(model_cfg, dict):
        attestation_cfg = model_cfg.get("attestation", {})
        if isinstance(attestation_cfg, dict):
            return attestation_cfg

    # Default: disabled
    return {"enabled": False}
```

## Failure Mode Semantics

### Strict Mode (`attestation.strict: true`)

- Attestation failure → AuthError with code `attestation_failed`
- Agent execution stops before any inference
- User sees clear error message with remediation steps

### Non-Strict Mode (`attestation.strict: false`, default)

- Attestation failure → Warning logged, execution continues
- `attestation_report.valid = False` in runtime creds
- Agent can inspect attestation status and decide

### No Attestation (`attestation.enabled: false`)

- Provider works as before (no verification)
- `attestation_report = None` in runtime creds
- Backward compatible

## Provider-Specific Verifiers

### NEAR AI (`near-ai`)

- **Type**: Intel TDX
- **Endpoint**: `GET /v1/attestation/report?include_tls_fingerprint=true`
- **Verifier**: Vendor `nearai-cloud-verifier` or implement inline
- **Checks**: TDX quote, TLS binding, GPU attestation

### OpenRouter

- **Type**: None (no TEE support)
- **Behavior**: Skip verification, log warning

### Nous Portal

- **Type**: None (provider-side trust)
- **Behavior**: Skip verification (OAuth already provides auth)

## Files to Modify

### Core Changes

1. **`hermes_cli/auth.py`**
   - Extend `ProviderConfig` with `attestation_config` field
   - Add `near-ai` provider entry with attestation config
   - Add `resolve_near_ai_runtime_credentials()` function

2. **`hermes_cli/runtime_provider.py`**
   - Import `verify_attestation` from new module
   - Add attestation verification call in `resolve_runtime_provider()`
   - Add `verify_attestation` parameter to function signature

3. **`hermes_cli/config.py`**
   - Add `get_attestation_config()` function
   - Document attestation config in `.env.example`

### New Files

4. **`hermes_cli/attestation.py`**
   - Implement `AttestationReport` dataclass
   - Implement `verify_attestation()` dispatcher
   - Implement `_verify_near_ai_attestation()`
   - Implement `_skip_attestation()` helper

5. **`hermes_cli/verifiers/`** (optional, for extensibility)
   - `near_ai_verifier.py` - NEAR AI-specific verification
   - `__init__.py` - Verifier registry

## Testing

### Unit Tests

```python
# tests/test_attestation.py

def test_attestation_config_loading():
    config = get_attestation_config("near-ai")
    assert config["enabled"] is True

def test_attestation_verification_success():
    creds = {"api_key": "sk-...", "base_url": "https://cloud-api.near.ai"}
    report = verify_attestation("near-ai", creds, {"enabled": True})
    assert report.valid is True
    assert report.attestation_type == "tdx"

def test_attestation_verification_failure():
    creds = {"api_key": "sk-...", "base_url": "https://cloud-api.near.ai"}
    report = verify_attestation("near-ai", creds, {
        "enabled": True,
        "strict": True,
    })
    # Would fail if attestation endpoint is down
    # In tests, mock the HTTP response

def test_strict_mode_raises_on_failure():
    # Test that AuthError is raised when strict mode and attestation fails
    with pytest.raises(AuthError) as exc_info:
        resolve_runtime_provider(
            requested="near-ai",
            verify_attestation=True,
        )
    assert exc_info.value.code == "attestation_failed"
```

### Integration Tests

```python
# tests/test_runtime_provider_attestation.py

def test_near_ai_provider_with_attestation():
    """End-to-end test of NEAR AI with attestation verification."""
    runtime = resolve_runtime_provider(
        requested="near-ai",
        verify_attestation=True,
    )
    assert runtime["provider"] == "near-ai"
    assert runtime["attestation"].valid is True
    assert runtime["attestation"].attestation_type == "tdx"
```

## Migration Path

### Phase 1: Add Capability (Non-Breaking)

- Add `attestation` module without modifying existing providers
- Add configuration support (disabled by default)
- Add CLI flag `--verify-attestation` for opt-in testing

### Phase 2: Add NEAR AI Provider

- Implement `near-ai` provider with attestation support
- Vendor or integrate `nearai-cloud-verifier`
- Add tests and documentation

### Phase 3: Enable by Default for NEAR AI

- Set `attestation.enabled: true` as default for `near-ai` provider
- Keep `attestation.strict: false` as default (warn, don't fail)
- Document security implications

### Phase 4: Extend to Other Providers

- Add attestation support for other TEE providers as they emerge
- Maintain backward compatibility with non-TEE providers

## Security Considerations

### Trust Model

- **TEE Provider**: Trusted if attestation verifies successfully
- **Verification Library**: Must be vendored and audited (e.g., nearai-cloud-verifier)
- **Configuration**: User-controlled, can be disabled for development

### Attack Surface

- **Attestation Replay**: Mitigated by random nonce in each request
- **Man-in-the-Middle**: Mitigated by TLS certificate binding
- **Compromised Verifier**: Mitigated by vendoring and pinning versions

### Failure Modes

- **Attestation Unavailable**: Fail open (warning) or fail closed (error) based on config
- **Verification Error**: Log full error, provide clear remediation steps
- **Network Issues**: Retry with exponential backoff, timeout after 30s

## Open Questions

1. **Should attestation be verified per-request or once per session?**
   - Recommendation: Once per session (on credential resolution) for performance
   - Per-request may be needed for high-security use cases

2. **How to handle GPU attestation (H100/H200)?**
   - NEAR AI provides NRAS (NVIDIA Remote Attestation Service)
   - May require additional dependencies (nvidia-verifier-sdk)

3. **Should we cache attestation results?**
   - Yes, with TTL (e.g., 5 minutes) to balance security and performance
   - Cache key: provider_id + base_url + signing_address

4. **How to extend to custom/private TEE providers?**
   - Provide plugin interface for custom verifiers
   - Document attestation report format for provider implementers

## References

- NEAR AI Cloud Verifier: https://github.com/nearai/nearai-cloud-verifier
- Intel TDX: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- NVIDIA NRAS: https://developer.nvidia.com/nvidia-remote-attestation-service

## Conclusion

This design provides a flexible, non-breaking way to add TEE attestation verification to Hermes Agent. It allows:
- Opt-in attestation verification per provider
- Clear failure modes (strict vs non-strict)
- Extensible architecture for future TEE providers
- Backward compatibility with existing providers

The proof-of-concept in `near_validating_provider.py` demonstrates feasibility with NEAR AI Cloud.
