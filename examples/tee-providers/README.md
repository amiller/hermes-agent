# TEE-Validating Provider Wrapper

Proof-of-concept for Hermes Agent providers that validate remote TEE attestation before trusting inference outputs.

## Overview

This directory contains:

- `near_validating_provider.py` - TEE-validating wrapper for NEAR AI Cloud
- `venice_client.py` - Venice AI client (attestation not available, skips gracefully)
- `test_validating_provider.py` - End-to-end tests
- `vendor/nearai-cloud-verifier/` - Vendored NEAR AI verifier SDK
- `Dockerfile` - Container for isolated testing

## Supported Providers

### NEAR AI Cloud ✓

- **TEE Attestation**: Fully supported
- **Verification**: Intel TDX quotes, gateway TLS binding, GPU attestation
- **Status**: Production-ready

### Venice AI ✗

- **TEE Attestation**: Not publicly available (as of 2026-04-14)
- **Status**: Client will skip if no API key, logs clear warning

## Quick Start

### 1. Build Docker Image

```bash
cd examples/tee-providers
docker build -t hermes-tee-provider .
```

### 2. Run Tests

```bash
# With NEAR API key from environment
docker run --rm \
  --env-file /home/amiller/projects/hermes-agent/deploy-notes/.env.near \
  hermes-tee-provider

# Or with inline API key
docker run --rm \
  -e NEAR_API_KEY=sk-your-key-here \
  hermes-tee-provider
```

### 3. Run Provider Demo

```bash
docker run --rm \
  --env-file /home/amiller/projects/hermes-agent/deploy-notes/.env.near \
  hermes-tee-provider \
  python near_validating_provider.py
```

## Usage (Outside Docker)

### Requirements

```bash
pip install requests eth-account cryptography dcap-qvl pytest
```

### Set Environment Variables

```bash
export NEAR_API_KEY="sk-your-key-here"
export NEAR_BASE_URL="https://cloud-api.near.ai"  # optional
export NEAR_STRICT_MODE="1"  # optional: raise on attestation failure
```

### Run Tests

```bash
# With pytest
pytest test_validating_provider.py -v

# Or directly
python test_validating_provider.py
```

### Use Provider in Code

```python
from near_validating_provider import ValidatingNearProvider

# Initialize with API key
provider = ValidatingNearProvider(
    api_key="sk-your-key-here",
    strict_mode=True  # Raise on attestation failure
)

# Verify attestation
if provider.verify_endpoint("cloud-api.near.ai"):
    # Send chat completion
    messages = [{"role": "user", "content": "Hello!"}]
    response = provider.chat(messages)
    print(response["choices"][0]["message"]["content"])
```

## Test Results

### Happy Path

```
=== Verifying TEE attestation for cloud-api.near.ai ===
✓ Gateway attestation found
✓ TDX quote valid
✓ Report data binding verified
✓ TLS certificate fingerprint verified
✅ Attestation verification PASSED

=== Sending chat completion to https://cloud-api.near.ai/v1/chat/completions ===
✓ Response received (status 200)
✓ Completion: Hello from TEE-verified endpoint!
```

### Negative Path

```
=== Verifying TEE attestation for wrong-domain.example ===
❌ Attestation verification FAILED: TLS fingerprint mismatch
AttestationError: Attestation verification failed for wrong-domain.example
```

## Architecture

### NEAR AI Verification Flow

1. **Fetch Attestation Report**: GET `/v1/attestation/report?include_tls_fingerprint=true`
2. **Verify TDX Quote**: Intel TDX quote validation via dcap-qvl
3. **Check Report Data**: Verify report_data binds signing address + TLS fingerprint + nonce
4. **Verify TLS Binding**: Compare TLS certificate fingerprint with live server cert
5. **Gate Inference**: Only proceed if all checks pass

### Venice AI Behavior

- Probes for attestation endpoint
- Logs finding: "Venice AI does not expose a public TEE attestation endpoint"
- Skips gracefully if no API key
- Allows chat completion with warning (no TEE guarantee)

## Security Properties

### NEAR AI Cloud

- ✓ Cryptographic attestation from Intel TDX
- ✓ Gateway TLS certificate binding
- ✓ Request nonce embedded in attestation
- ✓ GPU attestation via NVIDIA NRAS (H100/H200)
- ✓ ECDSA signature verification for responses

### Venice AI

- ✗ No TEE attestation available
- ⚠️  Standard API without hardware guarantees

## Vendored Dependencies

See `VENDOR.md` for details on vendored `nearai-cloud-verifier`.

## Design for Upstream Integration

See `DESIGN.md` for proposed `provider.attestation` capability for upstream Hermes Agent.

## Contributing

This is a proof-of-concept probe. For production integration, see the PR draft in `PR_DRAFT.md`.
