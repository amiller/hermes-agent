# Add TEE Attestation Verification for NEAR AI Provider

## Summary

This PR adds a proof-of-concept TEE (Trusted Execution Environment) attestation verification capability for Hermes Agent, focusing on NEAR AI Cloud as the first supported provider. The implementation validates Intel TDX quotes, gateway TLS certificate binding, and attestation report data before trusting inference outputs.

## Changes

### New Files

- `examples/tee-providers/near_validating_provider.py` - TEE-validating provider wrapper for NEAR AI
- `examples/tee-providers/venice_client.py` - Venice AI client (attestation not available, documented)
- `examples/tee-providers/test_validating_provider.py` - End-to-end tests (happy path + negative path)
- `examples/tee-providers/Dockerfile` - Container for isolated testing
- `examples/tee-providers/README.md` - Build/run instructions
- `examples/tee-providers/PROVIDER_INTERFACE.md` - Provider interface documentation
- `examples/tee-providers/VENDOR.md` - Vendored nearai-cloud-verifier metadata
- `examples/tee-providers/DESIGN.md` - Design for upstream `provider.attestation` capability
- `examples/tee-providers/vendor/nearai-cloud-verifier/` - Vendored NEAR AI verifier SDK (commit: ec304017)

### Vendored Dependencies

- `nearai-cloud-verifier@ec304017` - Official NEAR AI Cloud verifier (Python modules for TDX quote validation, TLS binding, GPU attestation)

## What This PR Does

### For Users

- Enables TEE-verified inference from NEAR AI Cloud
- Provides clear error messages when attestation fails
- Offers strict/non-strict modes for different security requirements
- Includes Docker container for isolated testing

### For Developers

- Demonstrates how to compose TEE verifiers into Hermes Agent providers
- Documents the provider interface contract (PROVIDER_INTERFACE.md)
- Provides design proposal for upstream integration (DESIGN.md)
- Includes working tests that can be extended

## Test Plan

### Unit Tests

```bash
# Run in Docker
docker build -t hermes-tee-provider examples/tee-providers
docker run --rm --env-file /path/to/.env.near hermes-tee-provider

# Run directly
cd examples/tee-providers
python test_validating_provider.py
```

### Test Cases

1. **Happy Path** ✓
   - Fetch attestation report from `cloud-api.near.ai`
   - Verify Intel TDX quote
   - Verify report_data binding (signing address + TLS fingerprint + nonce)
   - Verify gateway TLS certificate fingerprint
   - Successfully send chat completion
   - Receive non-empty response

2. **Negative Path** ✓
   - Attempt verification with wrong domain (`wrong-domain.example`)
   - Attestation verification fails
   - `AttestationError` raised in strict mode
   - No completion returned

3. **Non-Strict Mode** ✓
   - Attestation failure returns `False` instead of raising exception
   - Warning logged, execution continues (for development)

### Manual Verification

```bash
# Demo with strict mode
NEAR_API_KEY=sk-... NEAR_STRICT_MODE=1 python near_validating_provider.py

# Should see:
# ✓ Gateway attestation found
# ✓ TDX quote valid
# ✓ Report data binding verified
# ✓ TLS certificate fingerprint verified
# ✅ Attestation verification PASSED
```

## Risks and Mitigations

### Risk 1: Additional Dependencies

**Risk**: Vendoring `nearai-cloud-verifier` adds ~200KB of code and requires `dcap-qvl` (Intel TDX verification library).

**Mitigation**:
- Vendored at specific commit (ec304017) for reproducibility
- Dependencies are optional (only used for TEE providers)
- Documented in VENDOR.md with upgrade path

### Risk 2: False Positives

**Risk**: Attestation verification may fail due to transient network issues or API changes, blocking valid inference.

**Mitigation**:
- Default to non-strict mode (warn, don't fail)
- Clear error messages with remediation steps
- User can disable attestation if needed
- Timeout and retry logic in verification

### Risk 3: Maintenance Burden

**Risk**: TEE verification logic requires ongoing maintenance as providers update their attestation formats.

**Mitigation**:
- This is a proof-of-concept in `examples/` (not core)
- Uses official NEAR AI verifier (maintained by NEAR team)
- Design.md proposes upstream integration path with clear ownership

### Risk 4: Security Through Obscurity

**Risk**: Users may think TEE attestation provides complete security guarantees.

**Mitigation**:
- Clear documentation of what is/is not verified
- Explicit warnings for non-TEE providers (Venice AI)
- DESIGN.md explains threat model and limitations

## Documentation

- `examples/tee-providers/README.md` - Quick start, usage, test results
- `examples/tee-providers/PROVIDER_INTERFACE.md` - Provider contract (with line number references)
- `examples/tee-providers/DESIGN.md` - Upstream integration design (proposed `provider.attestation` config)
- `examples/tee-providers/VENDOR.md` - Vendored dependencies and rationale

## Backward Compatibility

✓ **Fully backward compatible** - This PR only adds files under `examples/tee-providers/` and does not modify existing Hermes Agent code.

## Future Work

1. **Upstream Integration** - Implement `provider.attestation` capability as proposed in DESIGN.md
2. **Additional Providers** - Add TEE support for other providers (e.g., OpenAI, Anthropic) if they expose attestation
3. **Per-Request Verification** - Option to verify attestation on each request (vs once per session)
4. **GPU Attestation** - Verify H100/H200 attestation via NVIDIA NRAS
5. **Plugin System** - Allow custom attestation verifiers for private TEE deployments

## References

- NEAR AI Cloud Verifier: https://github.com/nearai/nearai-cloud-verifier
- Intel TDX: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- Related Issue: #2205 (Venice integration - does not mention TEE, open whitespace)

## Checklist

- [x] Code compiles and runs without errors
- [x] Tests pass (happy path and negative path)
- [x] Documentation updated (README, DESIGN, PROVIDER_INTERFACE)
- [x] Vendored dependencies documented (VENDOR.md)
- [x] Backward compatible (no existing code modified)
- [x] Security considerations documented
- [x] Test plan executed and documented

---

**To open this PR, run:**

```bash
gh pr create --draft --repo NousResearch/hermes-agent --base main --head amiller:feat/tee-attestation-probe --title 'Add TEE Attestation Verification for NEAR AI Provider (Proof of Concept)' --body-file examples/tee-providers/PR_DRAFT.md
```
