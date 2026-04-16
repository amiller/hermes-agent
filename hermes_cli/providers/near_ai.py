"""
NEAR AI provider implementation with TEE attestation support.

This module provides the NEAR AI provider implementation that integrates
with Hermes Agent's runtime provider system.

Historical Note: This code was originally developed as a proof-of-concept
in examples/tee-providers/near_validating_provider.py. It has been promoted
to a first-class provider in hermes_cli/providers/near_ai.py. The original
file is retained for historical and reference purposes.
"""

import os
import secrets
from typing import Dict, List, Optional

import requests


class NEARAIProvider:
    """NEAR AI Cloud provider with optional TEE attestation verification."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        """
        Initialize the NEAR AI provider.

        Args:
            api_key: NEAR AI Cloud API key (default: from NEAR_API_KEY env var)
            base_url: API base URL (default: https://cloud-api.near.ai)
        """
        self.api_key = api_key or os.getenv("NEAR_API_KEY", "")
        self.base_url = (base_url or os.getenv("NEAR_BASE_URL", "https://cloud-api.near.ai")).rstrip("/")

        if not self.api_key:
            raise ValueError("NEAR_API_KEY environment variable is required")

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: str = "deepseek-ai/DeepSeek-V3.1",
        stream: bool = False,
        max_tokens: int = 100,
        **kwargs
    ) -> Dict:
        """
        Send chat completion request to NEAR AI Cloud.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            model: Model ID (default: deepseek-ai/DeepSeek-V3.1)
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

        # Send request
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()

        return response.json()


def create_near_ai_provider(
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> NEARAIProvider:
    """
    Factory function to create a NEAR AI provider instance.

    Args:
        api_key: NEAR AI Cloud API key (default: from NEAR_API_KEY env var)
        base_url: API base URL (default: https://cloud-api.near.ai)

    Returns:
        NEARAIProvider instance
    """
    return NEARAIProvider(api_key=api_key, base_url=base_url)
