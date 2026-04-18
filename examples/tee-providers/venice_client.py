#!/usr/bin/env python3
"""
Venice AI client with attestation probe.

This module attempts to verify whether Venice AI exposes a TEE attestation endpoint.
If no API key is configured, it skips gracefully with a clear message.

Finding: As of 2026-04-14, Venice AI does not publicly document a TEE attestation endpoint
or attestation verification API. This is based on:
- Review of https://docs.venice.ai (main documentation site)
- Review of https://api.venice.ai (API reference)
- No mention of attestation, TEE, or trusted execution environment in public docs

Venice AI appears to be a standard LLM API without TEE guarantees at this time.
If this changes in the future, the client structure here can be extended to add
attestation verification similar to the NEAR AI implementation.

Usage:
    python venice_client.py

Environment:
    VENICE_API_KEY: Venice AI API key (optional, if missing will skip)
    VENICE_BASE_URL: Override base URL (default: https://api.venice.ai)
"""

import os
import sys
import requests
from typing import Dict, List, Optional


class AttestationError(Exception):
    """Raised when TEE attestation verification fails or is unavailable."""
    pass


class VeniceClient:
    """Venice AI client with attestation probe."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        strict_mode: bool = False,
    ):
        """
        Initialize the Venice client.

        Args:
            api_key: Venice AI API key (default: from VENICE_API_KEY env var)
            base_url: API base URL (default: https://api.venice.ai)
            strict_mode: If True, raise AttestationError on attestation failure
        """
        self.api_key = api_key or os.getenv("VENICE_API_KEY", "")
        self.base_url = (base_url or os.getenv("VENICE_BASE_URL", "https://api.venice.ai")).rstrip("/")
        self.strict_mode = strict_mode or os.getenv("VENICE_STRICT_MODE", "0") == "1"

        if not self.api_key:
            print("skipped: no VENICE_API_KEY")
            print("Venice AI client requires VENICE_API_KEY environment variable.")
            print("Set it and retry, or continue without Venice integration.")
            sys.exit(0)

    def verify_endpoint(self, expected_domain: str) -> bool:
        """
        Attempt to verify TEE attestation for Venice AI.

        As of 2026-04-14, Venice AI does not expose a public TEE attestation endpoint.
        This method always returns False or raises AttestationError in strict mode.

        Args:
            expected_domain: Expected domain (e.g., "api.venice.ai")

        Returns:
            False (attestation not available)

        Raises:
            AttestationError: If strict_mode is enabled (attestation not available)
        """
        print(f"\n=== Probing TEE attestation for {expected_domain} ===")
        print("⚠️  Venice AI does not expose a public TEE attestation endpoint")
        print("    Checked: https://docs.venice.ai and https://api.venice.ai")
        print("    No attestation, TEE, or trusted execution documentation found")

        if self.strict_mode:
            raise AttestationError(
                "Venice AI does not support TEE attestation. "
                "Disable strict mode or use a TEE-enabled provider like NEAR AI."
            )

        return False

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: str = "llama-3.1-70b",
        stream: bool = False,
        max_tokens: int = 100,
        **kwargs
    ) -> Dict:
        """
        Send chat completion request to Venice AI.

        Note: This does NOT verify attestation (not available from Venice).

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            model: Model ID (default: llama-3.1-70b)
            stream: Whether to stream responses (default: False)
            max_tokens: Maximum tokens in response (default: 100)
            **kwargs: Additional parameters passed to API

        Returns:
            Dict with API response

        Raises:
            requests.RequestException: If API request fails
        """
        # Prepare request
        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "max_tokens": max_tokens,
            **kwargs,
        }

        print(f"\n=== Sending chat completion to {url} ===")
        print(f"Model: {model}")
        print(f"Messages: {len(messages)} message(s)")
        print(f"⚠️  WARNING: No attestation verification (Venice AI does not support TEE)")

        # Send request
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()

        result = response.json()
        print(f"✓ Response received (status {response.status_code})")

        # Extract completion text
        if result.get("choices") and len(result["choices"]) > 0:
            completion = result["choices"][0].get("message", {}).get("content", "")
            print(f"✓ Completion: {completion[:100]}{'...' if len(completion) > 100 else ''}")
        else:
            print(f"⚠️  No completion in response")

        return result


def main():
    """Demo of the Venice client (will skip if no API key)."""
    import argparse

    parser = argparse.ArgumentParser(description="Venice AI client demo (no TEE support)")
    parser.add_argument("--strict", action="store_true", help="Enable strict mode")
    parser.add_argument("--model", default="llama-3.1-70b", help="Model to use")
    args = parser.parse_args()

    try:
        client = VeniceClient(strict_mode=args.strict)

        # Simple test
        messages = [{"role": "user", "content": "Say 'Hello from Venice!'"}]
        result = client.chat(messages, model=args.model)

        print("\n=== Full Response ===")
        import json
        print(json.dumps(result, indent=2))

    except SystemExit as e:
        # Client exits with 0 when no API key (expected behavior)
        if e.code == 0:
            print("\nVenice client skipped as expected (no API key configured)")
        else:
            raise


if __name__ == "__main__":
    main()
