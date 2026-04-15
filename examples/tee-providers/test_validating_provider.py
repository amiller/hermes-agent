#!/usr/bin/env python3
"""
Tests for TEE-validating provider wrapper.

Tests:
1. Happy path: Valid attestation → successful chat completion
2. Negative path: Invalid domain → AttestationError raised

Run with pytest or directly: python test_validating_provider.py
"""

import os
import sys
import pytest

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from near_validating_provider import ValidatingNearProvider, AttestationError


def test_happy_path_valid_attestation():
    """
    Happy path: Valid attestation verification → successful chat completion.

    This test verifies that:
    1. The provider can fetch and verify TEE attestation from cloud-api.near.ai
    2. Domain verification succeeds with correct domain
    3. Chat completion returns a non-empty response
    """
    print("\n" + "=" * 70)
    print("TEST: Happy path - valid attestation")
    print("=" * 70)

    # Skip if no API key
    api_key = os.getenv("NEAR_API_KEY")
    if not api_key:
        pytest.skip("NEAR_API_KEY not set")

    provider = ValidatingNearProvider(strict_mode=True)

    # Verify attestation with correct domain
    result = provider.verify_endpoint("cloud-api.near.ai")
    assert result is True, "Endpoint verification should succeed"

    # Send chat completion
    messages = [{"role": "user", "content": "Say 'Hello'"}]
    response = provider.chat(messages, model="deepseek-ai/DeepSeek-V3.1", max_tokens=10)

    # Verify response structure
    print(f"\nDEBUG: Response type: {type(response)}")
    print(f"DEBUG: Response keys: {response.keys() if isinstance(response, dict) else 'N/A'}")

    assert isinstance(response, dict), f"Response should be a dict, got {type(response)}"
    assert "choices" in response, "Response should have 'choices' field"
    assert len(response["choices"]) > 0, "Response should have at least one choice"
    assert "message" in response["choices"][0], "Choice should have 'message' field"

    message = response["choices"][0]["message"]
    # Try to get content, fall back to reasoning if content is None
    completion = message.get("content")
    if completion is None:
        completion = message.get("reasoning", "")

    assert len(completion.strip()) > 0, "Completion should not be empty"

    print("\n✅ Happy path test PASSED")
    print(f"   Attestation verified for cloud-api.near.ai")
    print(f"   Completion received: {completion[:50]}...")
    print("=" * 70)


def test_negative_path_invalid_domain():
    """
    Negative path: Invalid domain → AttestationError raised.

    This test verifies that:
    1. The provider fails attestation verification for wrong domain
    2. AttestationError is raised in strict mode
    3. No completion is returned when attestation fails
    """
    print("\n" + "=" * 70)
    print("TEST: Negative path - invalid domain")
    print("=" * 70)

    # Skip if no API key
    api_key = os.getenv("NEAR_API_KEY")
    if not api_key:
        pytest.skip("NEAR_API_KEY not set")

    provider = ValidatingNearProvider(strict_mode=True)

    # Verify attestation with WRONG domain - should fail
    with pytest.raises(AttestationError) as exc_info:
        provider.verify_endpoint("wrong-domain.example")

    error_msg = str(exc_info.value)
    assert "Attestation verification failed" in error_msg, f"Expected attestation error, got: {error_msg}"

    print("\n✅ Negative path test PASSED")
    print(f"   AttestationError raised as expected for wrong domain")
    print(f"   Error message: {error_msg}")
    print("=" * 70)


def test_negative_path_wrong_tls_fingerprint():
    """
    Negative path: Tampered TLS fingerprint → verification fails.

    This test verifies that the provider detects when the TLS certificate
    fingerprint in the attestation response has been tampered with.
    """
    print("\n" + "=" * 70)
    print("TEST: Negative path - TLS fingerprint tampering detection")
    print("=" * 70)

    # Skip if no API key
    api_key = os.getenv("NEAR_API_KEY")
    if not api_key:
        pytest.skip("NEAR_API_KEY not set")

    from unittest.mock import patch, MagicMock
    import requests

    # First, fetch a real attestation response to use as a template
    provider = ValidatingNearProvider(strict_mode=True)
    base_url = provider.base_url

    # Fetch the real response first
    nonce = "a" * 64  # Fixed nonce for consistency
    url = f"{base_url}/v1/attestation/report"
    params = {"nonce": nonce, "signing_algo": "ecdsa", "include_tls_fingerprint": "true"}
    headers = {"Authorization": f"Bearer {api_key}"}

    real_response = requests.get(url, params=params, headers=headers, timeout=30)
    real_response.raise_for_status()
    real_report = real_response.json()

    # Extract the original TLS fingerprint and flip one byte
    original_fingerprint = real_report["gateway_attestation"]["tls_cert_fingerprint"]
    fingerprint_bytes = bytes.fromhex(original_fingerprint)

    # Flip the first byte to create a tampered fingerprint
    tampered_bytes = bytearray(fingerprint_bytes)
    tampered_bytes[0] = tampered_bytes[0] ^ 0xFF  # Flip all bits in first byte
    tampered_fingerprint = tampered_bytes.hex()

    print(f"Original fingerprint: {original_fingerprint}")
    print(f"Tampered fingerprint: {tampered_fingerprint}")

    # Create a tampered report
    tampered_report = real_report.copy()
    tampered_report["gateway_attestation"] = real_report["gateway_attestation"].copy()
    tampered_report["gateway_attestation"]["tls_cert_fingerprint"] = tampered_fingerprint

    # Mock the requests.get to return the tampered response
    mock_response = MagicMock()
    mock_response.json.return_value = tampered_report
    mock_response.raise_for_status = MagicMock()

    with patch('requests.get', return_value=mock_response) as mock_get:
        provider_tampered = ValidatingNearProvider(
            api_key=api_key,
            base_url=base_url,
            strict_mode=True
        )

        # Verify that the tampered fingerprint causes an AttestationError
        with pytest.raises(AttestationError) as exc_info:
            provider_tampered.verify_endpoint("cloud-api.near.ai")

        error_msg = str(exc_info.value)
        # Assert the error message mentions TLS or fingerprint binding
        assert ("tls" in error_msg.lower() or "fingerprint" in error_msg.lower() or
                "binds" in error_msg.lower()), \
            f"Expected error about TLS/fingerprint binding, got: {error_msg}"

        # Verify the mock was called with correct parameters
        assert mock_get.called
        call_args = mock_get.call_args
        assert call_args[0][0].startswith(base_url)
        assert "include_tls_fingerprint" in call_args[1].get("params", {})

    print("\n✅ TLS fingerprint tampering detection test PASSED")
    print(f"   Provider correctly rejected tampered TLS fingerprint")
    print(f"   Error message: {error_msg}")
    print("=" * 70)


def test_non_strict_mode_continues_on_failure():
    """
    Non-strict mode: Attestation failure → warning, but continues.

    This test verifies that in non-strict mode, the provider logs
    a warning but allows the request to proceed (for development/testing).
    """
    print("\n" + "=" * 70)
    print("TEST: Non-strict mode - continues on attestation failure")
    print("=" * 70)

    # Skip if no API key
    api_key = os.getenv("NEAR_API_KEY")
    if not api_key:
        pytest.skip("NEAR_API_KEY not set")

    provider = ValidatingNearProvider(strict_mode=False)

    # Verify attestation with wrong domain - should return False, not raise
    result = provider.verify_endpoint("wrong-domain.example")
    assert result is False, "Should return False on attestation failure in non-strict mode"

    print("\n✅ Non-strict mode test PASSED")
    print(f"   Provider returned False instead of raising exception")
    print("=" * 70)


def main():
    """Run tests directly without pytest."""
    print("Running TEE-validating provider tests...\n")

    try:
        test_happy_path_valid_attestation()
        print()
    except Exception as e:
        print(f"❌ Happy path test FAILED: {e}\n")
        import traceback
        traceback.print_exc()

    try:
        test_negative_path_invalid_domain()
        print()
    except Exception as e:
        print(f"❌ Negative path test FAILED: {e}\n")
        import traceback
        traceback.print_exc()

    try:
        test_negative_path_wrong_tls_fingerprint()
        print()
    except Exception as e:
        print(f"❌ Tampering detection test FAILED: {e}\n")
        import traceback
        traceback.print_exc()

    try:
        test_non_strict_mode_continues_on_failure()
        print()
    except Exception as e:
        print(f"❌ Non-strict mode test FAILED: {e}\n")
        import traceback
        traceback.print_exc()

    print("\nAll tests completed!")


if __name__ == "__main__":
    main()
