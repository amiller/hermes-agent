# TEE-Validating Provider Wrapper Design

## Overview

This document describes a design for a hermes-agent provider wrapper that validates TEE attestation from remote inference endpoints before trusting their outputs. The wrapper sits between hermes-agent's provider system and the upstream inference API, acting as a pre-flight verification layer.

## Motivation

As AI inference services increasingly run in Trusted Execution Environments (TEEs), consumers need mechanisms to verify that:
1. The inference actually occurred in a genuine TEE
2. The TEE meets required security properties (SGX, TDX, SEV-SNP, etc.)
3. The code identity within the TEE can be cryptographically verified
4. The attestation is fresh and from a trusted source

This is particularly important for:
- Confidential computing workloads
- Privacy-sensitive AI applications
- Regulatory compliance scenarios
- Multi-party AI systems where trust is critical

## Provider Interface Analysis

Based on analysis of hermes-agent's provider system (`hermes_cli/auth.py`), providers currently implement:

### Existing Provider Config Structure
```python
@dataclass
class ProviderConfig:
    id: str
    name: str
    auth_type: str  # "oauth_device_code", "oauth_external", or "api_key"
    portal_base_url: str = ""
    inference_base_url: str = ""
    client_id: str = ""
    scope: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    api_key_env_vars: tuple = ()
    base_url_env_var: str = ""
```

### Provider Resolution Flow
1. `resolve_provider()` picks the active provider
2. `resolve_*_runtime_credentials()` handles token/key retrieval
3. `resolve_runtime_provider()` returns final runtime config
4. Runtime config includes: provider, api_mode, base_url, api_key, source

## TEE Wrapper Design

### New Provider Type: `tee_validated`

Add a new auth type for TEE-validated providers:

```python
@dataclass
class ProviderConfig:
    # ... existing fields ...
    auth_type: str  # Add: "tee_validated"
    # ... existing fields ...
    
    # TEE-specific fields
    tee_type: str = ""  # "sgx", "tdx", "sev", "nitro", etc.
    attestation_endpoint: str = ""  # Separate endpoint for attestation verification
    verification_public_key: str = ""  # Expected public key for attestation
    min_quote_version: str = ""  # Minimum acceptable TEE quote version
    attestation_ttl_seconds: int = 300  # How long attestation is valid
```

### TEE Provider Registry Entry

```python
PROVIDER_REGISTRY["near-tee"] = ProviderConfig(
    id="near-tee",
    name="NEAR AI (TEE-validated)",
    auth_type="tee_validated",
    inference_base_url="https://api.near.ai/v1",
    api_key_env_vars=("NEAR_API_KEY",),
    tee_type="sgx",  # Example: if NEAR uses SGX
    attestation_endpoint="https://api.near.ai/v1/attestation/verify",
    verification_public_key="",  # Load from secure config
    min_quote_version="3",
    attestation_ttl_seconds=300,
)
```

### Attestation Verification Flow

```python
def verify_tee_attestation(
    provider_config: ProviderConfig,
    attestation_data: Dict[str, Any],
    inference_request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Verify TEE attestation before trusting inference output.
    
    Returns:
        {
            "valid": bool,
            "tee_type": str,
            "quote_version": str,
            "measurement": str,
            "timestamp": str,
            "verification_details": {...},
        }
    """
    
    # 1. Extract attestation blob from response
    quote = attestation_data.get("quote") or attestation_data.get("attestation")
    if not quote:
        raise AttestationError("No attestation data found")
    
    # 2. Verify quote format and structure
    if provider_config.tee_type == "sgx":
        verified = verify_sgx_quote(quote, provider_config)
    elif provider_config.tee_type == "tdx":
        verified = verify_tdx_quote(quote, provider_config)
    elif provider_config.tee_type == "sev":
        verified = verify_sev_quote(quote, provider_config)
    else:
        raise AttestationError(f"Unsupported TEE type: {provider_config.tee_type}")
    
    # 3. Check attestation freshness
    quote_time = parse_attestation_timestamp(quote)
    if time.time() - quote_time > provider_config.attestation_ttl_seconds:
        raise AttestationError("Attestation expired")
    
    # 4. Verify code measurement matches expected values
    expected_measurement = provider_config.extra.get("expected_measurement")
    if expected_measurement and verified["measurement"] != expected_measurement:
        raise AttestationError("Code measurement mismatch")
    
    # 5. Optionally: Call provider's attestation verification endpoint
    if provider_config.attestation_endpoint:
        provider_verified = call_provider_verification_endpoint(
            provider_config.attestation_endpoint,
            quote,
            inference_request,
        )
        if not provider_verified.get("valid"):
            raise AttestationError("Provider verification failed")
    
    return {
        "valid": True,
        "tee_type": provider_config.tee_type,
        "quote_version": verified["version"],
        "measurement": verified["measurement"],
        "timestamp": quote_time,
        "verification_details": verified,
    }
```

### Runtime Provider Resolution with TEE

```python
def resolve_tee_runtime_credentials(provider_id: str) -> Dict[str, Any]:
    """
    Resolve credentials and TEE configuration for a TEE-validated provider.
    """
    pconfig = PROVIDER_REGISTRY.get(provider_id)
    if not pconfig or pconfig.auth_type != "tee_validated":
        raise AuthError(f"Provider '{provider_id}' is not a TEE-validated provider")
    
    # Get API key (same as api_key providers)
    api_key = ""
    key_source = ""
    for env_var in pconfig.api_key_env_vars:
        val = os.getenv(env_var, "").strip()
        if val:
            api_key = val
            key_source = env_var
            break
    
    return {
        "provider": provider_id,
        "api_mode": "chat_completions",
        "base_url": pconfig.inference_base_url.rstrip("/"),
        "api_key": api_key,
        "source": key_source or "default",
        "tee_config": {
            "tee_type": pconfig.tee_type,
            "attestation_endpoint": pconfig.attestation_endpoint,
            "verification_public_key": pconfig.verification_public_key,
            "attestation_ttl_seconds": pconfig.attestation_ttl_seconds,
        },
    }
```

### TEE-Aware Inference Call

```python
class TEEValidatedInferenceClient:
    """
    OpenAI-compatible client that validates TEE attestation before returning results.
    """
    
    def __init__(self, runtime_config: Dict[str, Any]):
        self.config = runtime_config
        self.tee_config = runtime_config["tee_config"]
        self.base_client = httpx.Client(
            base_url=runtime_config["base_url"],
            headers={
                "Authorization": f"Bearer {runtime_config['api_key']}",
                "Content-Type": "application/json",
            },
        )
    
    def chat_completions(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute chat completion with TEE attestation verification.
        """
        # 1. Send inference request
        response = self.base_client.post(
            "/v1/chat/completions",
            json=payload,
        )
        
        if response.status_code != 200:
            raise InferenceError(f"Inference failed: {response.status_code}")
        
        result = response.json()
        
        # 2. Extract attestation from response
        attestation_data = self._extract_attestation(result, response.headers)
        
        # 3. Verify attestation
        verification_result = verify_tee_attestation(
            self.tee_config,
            attestation_data,
            payload,
        )
        
        # 4. Attach verification metadata to result
        result["tee_verification"] = verification_result
        
        return result
    
    def _extract_attestation(
        self,
        response_body: Dict[str, Any],
        response_headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Extract attestation data from response body or headers.
        
        Supports multiple attestation formats:
        - Inline in response body (e.g., result["attestation"])
        - In response headers (e.g., X-TEE-Attestation)
        - Reference to external attestation (e.g., result["attestation_url"])
        """
        
        # Check body first
        if "attestation" in response_body:
            return response_body["attestation"]
        
        if "quote" in response_body:
            return {"quote": response_body["quote"]}
        
        # Check headers
        for key, value in response_headers.items():
            if "attestation" in key.lower() or "quote" in key.lower():
                return {"quote": value}
        
        # Check for attestation URL
        if "attestation_url" in response_body:
            # Fetch external attestation
            attestation = self._fetch_external_attestation(
                response_body["attestation_url"]
            )
            return attestation
        
        raise AttestationError("No attestation data found in response")
    
    def _fetch_external_attestation(self, url: str) -> Dict[str, Any]:
        """
        Fetch attestation from external URL.
        """
        response = httpx.get(url)
        if response.status_code != 200:
            raise AttestationError(f"Failed to fetch attestation: {response.status_code}")
        return response.json()
```

## Integration with Hermes-Agent

### New CLI Command

```bash
hermes model --verify-tee near-tee
```

### Config Extension

```yaml
model:
  provider: near-tee
  default: meta-llama/Meta-Llama-3.1-8B-Instruct
  tee_verification:
    enabled: true
    strict: true  # Fail if attestation invalid
    cache_ttl_seconds: 300
```

### Error Handling

```python
class AttestationError(AuthError):
    """Raised when TEE attestation verification fails."""
    
    def __init__(
        self,
        message: str,
        *,
        provider: str = "",
        reason: str = "",  # "expired", "invalid_measurement", "bad_signature", etc.
        details: Dict[str, Any] = None,
    ):
        super().__init__(message, provider=provider, code="attestation_failed")
        self.reason = reason
        self.details = details or {}
```

## Attestation Format Examples

### SGX Quote Format (Intel)
```json
{
  "quote": "base64-encoded-sgx-quote",
  "quote_version": "3",
  "measurement": "a1b2c3d4e5f6...",
  "report_data": "user-provided-data-hash",
  "timestamp": "2024-04-14T10:30:00Z"
}
```

### TDX Quote Format (Intel)
```json
{
  "tdx_quote": "base64-encoded-tdx-quote",
  "td_report_data": "hash-of-report-data",
  "measurement": {
    "rtmr0": "...",
    "rtmr1": "...",
    "rtmr2": "...",
    "rtmr3": "..."
  }
}
```

### Generic Attestation Reference
```json
{
  "attestation_url": "https://api.provider.com/v1/attestation/abc123",
  "attestation_id": "abc123",
  "expires_at": "2024-04-14T11:00:00Z"
}
```

## Security Considerations

1. **Public Key Management**: Provider verification keys must be securely stored and rotated
2. **Replay Protection**: Include request hash in attestation verification
3. **Fallback Behavior**: Define behavior when attestation verification fails (fail-open vs fail-closed)
4. **Performance Impact**: Attestation verification adds latency; consider caching
5. **Forward Compatibility**: Design for new TEE types and attestation formats

## Limitations and Open Questions

1. **Provider Support**: Currently unknown if NEAR AI or Venice expose attestation data
2. **Standardization**: No industry-wide standard for TEE attestation in AI inference
3. **Verification Complexity**: Different providers may use different attestation formats
4. **Key Distribution**: How to securely distribute and manage verification public keys
5. **Performance**: Attestation verification adds latency to every inference call

## Future Work

1. **Attestation Caching**: Cache valid attestments to reduce latency
2. **Batch Verification**: Verify multiple attestations in parallel
3. **Fallback Strategies**: Graceful degradation when attestation unavailable
4. **Audit Logging**: Log all attestation verifications for compliance
5. **Multi-TEE Support**: Support multiple TEE types in single provider

## Conclusion

This design provides a framework for integrating TEE attestation verification into hermes-agent's provider system. The key innovation is the `tee_validated` auth type, which extends the existing provider interface to include TEE-specific configuration and verification logic.

The wrapper approach allows hermes-agent to:
- Support new TEE-enabled inference providers without core changes
- Verify attestation in a standardized way across providers
- Fail gracefully when attestation is unavailable or invalid
- Maintain backward compatibility with existing providers

The next step is to test this design with actual providers (NEAR AI, Venice) to understand their attestation surfaces and refine the verification logic accordingly.
