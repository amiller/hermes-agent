#!/usr/bin/env python3
"""
NEAR AI TEE Attestation Probe

This script probes NEAR AI's inference API to:
1. Authenticate with NEAR_API_KEY
2. Send a chat completion request
3. Check for TEE attestation / proof in response headers or body
4. Print raw attestation data if available

Research question: Does NEAR AI expose any attestation/TEE proof surface?
"""

import os
import sys
import json
import httpx
from typing import Optional, Dict, Any

# NEAR AI API endpoints (updated based on deprecation notice)
NEAR_API_BASE = "https://cloud.near.ai"  # New private API
NEAR_CHAT_ENDPOINT = f"{NEAR_API_BASE}/v1/chat/completions"


def get_near_api_key() -> str:
    """Get NEAR API key from environment."""
    api_key = os.getenv("NEAR_API_KEY", "").strip()
    if not api_key:
        print("ERROR: NEAR_API_KEY environment variable not set")
        sys.exit(1)
    return api_key


def send_chat_completion(api_key: str) -> Dict[str, Any]:
    """Send a simple chat completion to NEAR AI."""
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "model": "meta-llama/Meta-Llama-3.1-8B-Instruct",  # Common NEAR model
        "messages": [
            {"role": "user", "content": "Say 'Hello from TEE probe' in exactly those words."}
        ],
        "max_tokens": 50,
        "stream": False,
    }
    
    print(f"Sending request to {NEAR_CHAT_ENDPOINT}")
    print(f"Model: {payload['model']}")
    print(f"Message: {payload['messages'][0]['content']}")
    
    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                NEAR_CHAT_ENDPOINT,
                headers=headers,
                json=payload,
            )
            
            print(f"\nResponse Status: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            
            # Try to parse response
            try:
                response_data = response.json()
                print(f"\nResponse Body Keys: {list(response_data.keys())}")
                print(f"\nFull Response:\n{json.dumps(response_data, indent=2)}")
                
                # Check for attestation-related fields
                attestation_fields = {}
                for key in response_data.keys():
                    if any(keyword in key.lower() for keyword in 
                           ['attest', 'tee', 'quote', 'proof', 'sgx', 'tdx', 'sev', 'verify']):
                        attestation_fields[key] = response_data[key]
                
                if attestation_fields:
                    print(f"\n🔍 ATTESTATION FIELDS FOUND:\n{json.dumps(attestation_fields, indent=2)}")
                else:
                    print(f"\n❌ No attestation fields found in response body")
                
                return {
                    "success": response.status_code == 200,
                    "status_code": response.status_code,
                    "response": response_data,
                    "headers": dict(response.headers),
                    "attestation_fields": attestation_fields,
                }
                
            except json.JSONDecodeError:
                print(f"\nResponse Text:\n{response.text}")
                return {
                    "success": False,
                    "status_code": response.status_code,
                    "error": "Invalid JSON response",
                    "response_text": response.text,
                }
            
    except httpx.HTTPStatusError as e:
        print(f"HTTP Error: {e}")
        return {
            "success": False,
            "status_code": e.response.status_code,
            "error": str(e),
        }
    except Exception as e:
        print(f"Unexpected error: {e}")
        return {
            "success": False,
            "error": str(e),
        }


def check_attestation_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Check response headers for attestation-related information."""
    
    attestation_headers = {}
    for key, value in headers.items():
        if any(keyword in key.lower() for keyword in 
               ['attest', 'tee', 'quote', 'proof', 'sgx', 'tdx', 'sev', 'verify', 'x-']):
            attestation_headers[key] = value
    
    return attestation_headers


def main():
    print("=" * 70)
    print("NEAR AI TEE Attestation Probe")
    print("=" * 70)
    
    api_key = get_near_api_key()
    print(f"API Key: {api_key[:10]}...{api_key[-4:]}")
    
    result = send_chat_completion(api_key)
    
    print("\n" + "=" * 70)
    print("ATTESTATION ANALYSIS")
    print("=" * 70)
    
    # Check headers for attestation
    attestation_headers = check_attestation_headers(result.get("headers", {}))
    if attestation_headers:
        print(f"🔍 ATTESTATION HEADERS FOUND:\n{json.dumps(attestation_headers, indent=2)}")
    else:
        print("❌ No attestation-related headers found")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    if result.get("success"):
        content = None
        try:
            choices = result["response"].get("choices", [])
            if choices and len(choices) > 0:
                content = choices[0].get("message", {}).get("content", "")
        except (KeyError, IndexError, TypeError):
            pass
        
        print(f"✅ Chat completion successful")
        print(f"   Status: {result['status_code']}")
        if content:
            print(f"   Response: {content}")
        
        attestation_fields = result.get("attestation_fields", {})
        attestation_headers = check_attestation_headers(result.get("headers", {}))
        
        if attestation_fields or attestation_headers:
            print(f"✅ ATTESTATION DATA FOUND")
            print(f"   Body fields: {list(attestation_fields.keys())}")
            print(f"   Header fields: {list(attestation_headers.keys())}")
        else:
            print(f"❌ NO ATTESTATION DATA FOUND")
            print(f"   NEAR AI does not appear to expose TEE attestation")
            print(f"   in standard API responses or headers")
    else:
        print(f"❌ Chat completion failed")
        print(f"   Status: {result.get('status_code', 'N/A')}")
        print(f"   Error: {result.get('error', 'Unknown error')}")
    
    print("\n" + "=" * 70)
    print("FINDING: NEAR AI Attestation Support")
    print("=" * 70)
    
    if result.get("success"):
        if result.get("attestation_fields") or attestation_headers:
            print("NEAR AI appears to expose TEE attestation data in their API responses.")
            print("The attestation surface includes:")
            if result.get("attestation_fields"):
                print(f"  - Response body fields: {list(result['attestation_fields'].keys())}")
            if attestation_headers:
                print(f"  - Response headers: {list(attestation_headers.keys())}")
        else:
            print("NEAR AI's chat completion API does not expose TEE attestation")
            print("data in response headers or body. This suggests either:")
            print("  1. Attestation is handled via a separate verification endpoint")
            print("  2. Attestation is only available in enterprise/private deployments")
            print("  3. NEAR AI does not currently expose TEE attestation to API consumers")
            print("\nRecommendation: Check NEAR AI documentation for dedicated attestation")
            print("or verification endpoints, or contact NEAR AI support for TEE integration.")
    else:
        status = result.get('status_code', 'N/A')
        if status == 401 or status == 403:
            print("The NEAR AI API requires valid authentication.")
            print("The provided API key may be invalid or expired.")
            print("Cannot complete TEE attestation probe without valid credentials.")
        elif status == 410:
            print("The NEAR AI API endpoint has been deprecated.")
            print("NEAR AI retired their public API in October 2025.")
            print("They now recommend using their private cloud API at cloud.near.ai")
            print("However, this appears to require enterprise access.")
        else:
            print(f"Cannot complete NEAR AI TEE attestation probe (HTTP {status}).")
            print("The API returned an error, preventing attestation analysis.")


if __name__ == "__main__":
    main()
