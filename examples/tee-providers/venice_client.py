#!/usr/bin/env python3
"""
Venice TEE Attestation Probe

This script probes Venice's inference API to:
1. Check if Venice API is accessible (no auth provided per task)
2. Send a chat completion request if possible
3. Check for TEE attestation / proof in response headers or body
4. Print raw attestation data if available

Research question: Does Venice expose any attestation/TEE proof surface?
Note: Venice claims TEE inference - we need to find their verification surface.
"""

import os
import sys
import json
import httpx
from typing import Optional, Dict, Any

# Venice API endpoints (based on public information)
# Venice uses OpenAI-compatible API format
VENICE_API_BASE = "https://api.venice.ai"  # May need adjustment
VENICE_CHAT_ENDPOINT = f"{VENICE_API_BASE}/v1/chat/completions"


def send_chat_completion() -> Dict[str, Any]:
    """Send a simple chat completion to Venice (no auth required for testing)."""
    
    headers = {
        "Content-Type": "application/json",
    }
    
    # Try a common model that Venice might support
    payload = {
        "model": "llama-3.1-8b",  # Common open model on Venice
        "messages": [
            {"role": "user", "content": "Say 'Hello from Venice TEE probe' in exactly those words."}
        ],
        "max_tokens": 50,
        "stream": False,
    }
    
    print(f"Sending request to {VENICE_CHAT_ENDPOINT}")
    print(f"Model: {payload['model']}")
    print(f"Message: {payload['messages'][0]['content']}")
    print(f"Note: No API key provided - testing public endpoint access")
    
    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                VENICE_CHAT_ENDPOINT,
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


def probe_alternative_endpoints() -> Dict[str, Any]:
    """Try to find Venice attestation verification endpoints."""
    
    alternative_endpoints = [
        # Possible attestation endpoints based on common patterns
        f"{VENICE_API_BASE}/v1/attestation",
        f"{VENICE_API_BASE}/v1/verify",
        f"{VENICE_API_BASE}/v1/quote",
        f"{VENICE_API_BASE}/attestation",
        f"{VENICE_API_BASE}/tee/info",
        f"{VENICE_API_BASE}/health",  # Sometimes includes TEE status
    ]
    
    findings = {}
    
    for endpoint in alternative_endpoints:
        try:
            print(f"\nProbing alternative endpoint: {endpoint}")
            with httpx.Client(timeout=10.0) as client:
                response = client.get(endpoint, timeout=10.0)
                
                if response.status_code != 404:
                    findings[endpoint] = {
                        "status": response.status_code,
                        "headers": dict(response.headers),
                    }
                    
                    if response.status_code == 200:
                        try:
                            findings[endpoint]["body"] = response.json()
                        except:
                            findings[endpoint]["body"] = response.text[:500]
                    
                    print(f"  ✅ Status: {response.status_code}")
                else:
                    print(f"  ❌ Not found (404)")
                    
        except Exception as e:
            print(f"  ❌ Error: {str(e)[:100]}")
    
    return findings


def main():
    print("=" * 70)
    print("Venice TEE Attestation Probe")
    print("=" * 70)
    
    result = send_chat_completion()
    
    print("\n" + "=" * 70)
    print("ATTESTATION ANALYSIS")
    print("=" * 70)
    
    # Check headers for attestation
    attestation_headers = check_attestation_headers(result.get("headers", {}))
    if attestation_headers:
        print(f"🔍 ATTESTATION HEADERS FOUND:\n{json.dumps(attestation_headers, indent=2)}")
    else:
        print("❌ No attestation-related headers found")
    
    # Probe alternative endpoints
    print("\n" + "=" * 70)
    print("PROBING ALTERNATIVE ATTESTATION ENDPOINTS")
    print("=" * 70)
    
    alternative_findings = probe_alternative_endpoints()
    
    if alternative_findings:
        print(f"\n🔍 ALTERNATIVE ENDPOINTS FOUND:\n{json.dumps(alternative_findings, indent=2)}")
    else:
        print("\n❌ No alternative attestation endpoints found")
    
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
            print(f"❌ NO ATTESTATION DATA FOUND in main endpoint")
            
        if alternative_findings:
            print(f"✅ ALTERNATIVE ENDPOINTS FOUND")
            print(f"   Discovered {len(alternative_findings)} potential attestation endpoints")
        else:
            print(f"❌ NO ALTERNATIVE ATTESTATION ENDPOINTS FOUND")
            
    else:
        print(f"❌ Chat completion failed")
        print(f"   Status: {result.get('status_code', 'N/A')}")
        print(f"   Error: {result.get('error', 'Unknown error')}")
        
        # If 401/403, might need auth
        if result.get('status_code') in [401, 403]:
            print(f"\n⚠️  Endpoint requires authentication")
            print(f"   Venice API may require an API key for access")
            print(f"   Cannot complete TEE attestation probe without valid credentials")
    
    print("\n" + "=" * 70)
    print("FINDING: Venice Attestation Support")
    print("=" * 70)
    
    if result.get("success"):
        if result.get("attestation_fields") or attestation_headers or alternative_findings:
            print("Venice appears to expose some form of attestation or verification")
            print("endpoints. Further investigation needed to understand the full")
            print("attestation surface and verification process.")
        else:
            print("Venice's standard chat completion API does not expose TEE attestation")
            print("data in response headers or body, and no alternative attestation")
            print("endpoints were found. This suggests either:")
            print("  1. Attestation requires authentication and proper API keys")
            print("  2. Attestation is only available in enterprise/private deployments")
            print("  3. Venice uses a different attestation mechanism not discoverable via API probing")
            print("\nRecommendation: Obtain Venice API credentials and check documentation for")
            print("dedicated attestation or verification endpoints.")
    else:
        print("Cannot complete Venice TEE attestation probe due to access restrictions.")
        print("The endpoint returned authentication/authorization errors, suggesting that")
        print("valid API credentials are required to access Venice's inference API and")
        print("any associated attestation features.")


if __name__ == "__main__":
    main()
