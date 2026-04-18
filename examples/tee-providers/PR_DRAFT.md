# Add NEAR AI as a First-Class TEE-Attested Provider

## Summary

This PR wires NEAR AI into `hermes_cli/` as a real, first-class provider with opt-in TEE (Trusted Execution Environment) attestation verification. The `examples/tee-providers/` probe remains as a historical reference and demo, but NEAR AI can now be used by setting `provider: near-ai` in the hermes config and routing inference through the attested path.

## What Changed

### Core Hermes CLI Integration

- **`hermes_cli/attestation.py`** (NEW, ~180 lines)
  - `AttestationReport` dataclass for verification results
  - `verify_attestation()` dispatcher for provider-specific verification
  - `_verify_near_ai_attestation()` implementation using vendored nearai-cloud-verifier
  - `_skip_attestation()` helper for non-TEE providers

- **`hermes_cli/auth.py`** (MODIFIED)
  - Extended `ProviderConfig` with `attestation_config: Optional[Dict[str, Any]]` field
  - Added `'near-ai'` entry to `PROVIDER_REGISTRY` with TDX attestation config
  - Added `resolve_near_ai_runtime_credentials()` function
  - Added `get_near_ai_auth_status()` function

- **`hermes_cli/runtime_provider.py`** (MODIFIED)
  - Added dispatch branch for `provider='near-ai'` calling `resolve_near_ai_runtime_credentials`
  - Added `verify_attestation: bool = True` parameter to `resolve_runtime_provider()`
  - Integrated attestation verification after credential resolution
  - Implemented strict mode: raises `AuthError(code='attestation_failed')` when verification fails
  - Implemented non-strict mode: logs warnings and continues with invalid attestation

- **`hermes_cli/config.py`** (MODIFIED)
  - Added `get_attestation_config()` helper to load attestation settings from config

### Provider Implementation

- **`hermes_cli/providers/__init__.py`** (NEW)
  - Package initialization for provider implementations

- **`hermes_cli/providers/near_ai.py`** (NEW, ~110 lines)
  - `NEARAIProvider` class for direct provider usage
  - `create_near_ai_provider()` factory function
  - Cleaned-up version of the original `examples/tee-providers/near_validating_provider.py`
  - Historical note pointing to the original probe file

### Testing

- **`tests/integration/test_near_provider_integration.py`** (NEW)
  - Requires `NEAR_API_KEY` environment variable (skipped if absent)
  - Tests credential resolution with attestation verification
  - Tests actual inference call to NEAR AI Cloud with retries
  - Documents expected behavior for strict mode failure (test implementation pending config override)

### Documentation

- **`examples/tee-providers/PR_DRAFT.md`** (REWRITTEN)
  - Updated to reflect that NEAR AI is now a first-class provider
  - Removed "Fully backward compatible - only adds files under examples/" claim
  - Added explicit backward compatibility note (opt-in via config)
  - Added Known Caveats section linking to security findings

## Configuration

Users can enable attestation verification by adding to `~/.hermes/config.yaml`:

```yaml
model:
  provider: "near-ai"
  default: "deepseek-ai/DeepSeek-V3.1"
  attestation:
    enabled: true
    strict: false  # If true, fail on attestation error
```

## Test Plan

### Integration Tests

```bash
# Run integration tests (requires NEAR_API_KEY)
cd /home/amiller/projects/hermes-agent-tee-probe
NEAR_API_KEY=sk-... pytest tests/integration/test_near_provider_integration.py -v
```

### Manual Testing

```bash
# Set up environment
export NEAR_API_KEY=sk-...

# Test with attestation verification enabled
python -c "
from hermes_cli.runtime_provider import resolve_runtime_provider
creds = resolve_runtime_provider(requested='near-ai', verify_attestation=True)
print(f'Provider: {creds[\"provider\"]}')
print(f'Base URL: {creds[\"base_url\"]}')
print(f'Attestation valid: {creds.get(\"attestation\", {}).get(\"valid\", \"N/A\")}')
"
```

### Docker Test

```bash
# Build and run in Docker (from examples/tee-providers/)
docker build -t hermes-tee-provider examples/tee-providers
docker run --rm --env-file /path/to/.env.near hermes-tee-provider
```

## Backward Compatibility

This PR is backward compatible because:
- NEAR AI is an **opt-in** provider (only activated when `model.provider: near-ai`)
- Attestation verification is **disabled by default** (`model.attestation.enabled: false`)
- Existing providers (nous, openrouter, zai, etc.) are completely unaffected
- The `examples/tee-providers/` probe remains intact as historical reference

## Known Caveats

Before deploying this for sensitive workloads, users should be aware of:

1. **Model Substitution Risk** (HERMES-TEE-3): TEE attestation verifies the hardware and gateway, but does not guarantee that the specified model (e.g., `deepseek-ai/DeepSeek-V3.1`) is the actual model serving the request. See `/home/amiller/projects/ai-workflows/smithers-workspace/reports/tasks/HERMES-TEE-3.html` for details.

2. **Prompt Exfiltration Risk** (HERMES-TEE-4): While TEE protects the inference process, prompts and responses may still be logged or processed by the provider in ways not covered by attestation. See `/home/amiller/projects/ai-workflows/smithers-workspace/reports/tasks/HERMES-TEE-4.html` for details.

3. **Attestation Replay**: The implementation uses a random nonce per verification to prevent replay attacks.

4. **Network Dependencies**: Attestation verification requires network access to `cloud-api.near.ai` and Intel TDX verification services. Failures are handled per the `strict` mode setting.

5. **Vendor Lock-in**: This implementation is specific to NEAR AI's attestation format. Other TEE providers would require different verifiers.

## Dependencies

This PR uses the **vendored** `nearai-cloud-verifier` at commit `ec304017`:
- Location: `examples/tee-providers/vendor/nearai-cloud-verifier/`
- No new PyPI dependencies added
- Verifier is imported via `sys.path` manipulation in `hermes_cli/attestation.py`

## Future Work

1. **Config Override for Testing**: Add a mechanism to override attestation config in tests (needed for strict mode failure test)

2. **Per-Request Verification**: Option to verify attestation on each request (vs once per session)

3. **GPU Attestation**: Verify H100/H200 attestation via NVIDIA NRAS (vendor supports it, not yet integrated)

4. **Additional TEE Providers**: Extend framework to support other TEE providers (e.g., AMD SEV, AWS Nitro)

5. **Attestation Caching**: Cache verification results with TTL to balance security and performance

## Checklist

- [x] Code compiles and runs without errors
- [x] Integration tests added (with skip if NEAR_API_KEY absent)
- [x] Documentation updated (PR_DRAFT.md)
- [x] Backward compatible (opt-in provider, attestation disabled by default)
- [x] Security considerations documented (Known Caveats section)
- [x] No new PyPI dependencies (uses vendored verifier)
- [x] Historical probe file preserved in examples/

---

**To open this PR, run:**

```bash
gh pr create --draft --repo NousResearch/hermes-agent --base main --head amiller:feat/tee-attestation-probe --title 'feat: promote NEAR AI validating provider to hermes_cli (first-class TEE-attested provider)' --body-file examples/tee-providers/PR_DRAFT.md
```
