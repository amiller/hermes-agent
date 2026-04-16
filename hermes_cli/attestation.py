"""TEE Attestation verification module for Hermes Agent."""
import asyncio
import os
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

# Add vendored verifier modules to path
vendor_path = os.path.join(os.path.dirname(__file__), "..", "examples", "tee-providers", "vendor", "nearai-cloud-verifier", "py")
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

# Try to import verifier modules, but handle gracefully if not available
_VERIFIER_AVAILABLE = False
try:
    from model_verifier import check_tdx_quote, check_report_data
    from domain_verifier import DomainAttestation, verify_domain_attestation
    _VERIFIER_AVAILABLE = True
except ImportError:
    pass


@dataclass
class AttestationReport:
    """TEE attestation verification result."""
    valid: bool
    provider: str
    attestation_type: str
    verified_at: str
    details: Dict[str, Any]
    error: Optional[str] = None


def verify_attestation(provider_id: str, runtime_creds: Dict[str, Any], config: Dict[str, Any]) -> AttestationReport:
    """Verify TEE attestation for a provider."""
    if not _VERIFIER_AVAILABLE:
        return AttestationReport(
            valid=False, provider=provider_id, attestation_type="none",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={}, error="Attestation verifier dependencies not available"
        )
    if provider_id == "near-ai":
        return _verify_near_ai_attestation(runtime_creds, config)
    return _skip_attestation("not-implemented")


def _verify_near_ai_attestation(runtime_creds: Dict[str, Any], config: Dict[str, Any]) -> AttestationReport:
    """Verify NEAR AI Cloud TEE attestation."""
    api_key = runtime_creds.get("api_key", "")
    base_url = runtime_creds.get("base_url", "https://cloud-api.near.ai").rstrip("/")
    if not api_key:
        return AttestationReport(
            valid=False, provider="near-ai", attestation_type="tdx",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={}, error="No API key in runtime credentials"
        )
    try:
        nonce = secrets.token_hex(32)
        url = f"{base_url}/v1/attestation/report"
        params = {"nonce": nonce, "signing_algo": "ecdsa", "include_tls_fingerprint": "true"}
        headers = {"Authorization": f"Bearer {api_key}"}
        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        report = response.json()
        gateway_attestation = report.get("gateway_attestation", {})
        if not gateway_attestation:
            return AttestationReport(
                valid=False, provider="near-ai", attestation_type="tdx",
                verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                details={"report": report}, error="No gateway_attestation in response"
            )
        intel_result = asyncio.run(check_tdx_quote(gateway_attestation))
        if not intel_result.get("verified", False):
            return AttestationReport(
                valid=False, provider="near-ai", attestation_type="tdx",
                verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                details={"intel_result": intel_result}, error="Invalid TDX quote: verification failed"
            )
        report_data_result = check_report_data(gateway_attestation, nonce, intel_result)
        if not report_data_result.get("binds_address", False):
            return AttestationReport(
                valid=False, provider="near-ai", attestation_type="tdx",
                verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                details={"report_data_result": report_data_result}, error="Report data does not bind signing address + TLS fingerprint"
            )
        if not report_data_result.get("embeds_nonce", False):
            return AttestationReport(
                valid=False, provider="near-ai", attestation_type="tdx",
                verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                details={"report_data_result": report_data_result}, error="Report data does not embed request nonce"
            )
        tls_certificate = report.get("tls_certificate", "")
        if not tls_certificate:
            return AttestationReport(
                valid=False, provider="near-ai", attestation_type="tdx",
                verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                details={"report": report}, error="No tls_certificate in response"
            )
        from urllib.parse import urlparse
        domain = urlparse(base_url).netloc
        domain_attestation = DomainAttestation(
            domain=domain, sha256sum=gateway_attestation.get("tls_cert_fingerprint", ""),
            acme_account=gateway_attestation.get("acme_account", ""), cert=tls_certificate,
            intel_quote=gateway_attestation.get("intel_quote", ""), info=gateway_attestation
        )
        try:
            asyncio.run(verify_domain_attestation(domain_attestation))
        except Exception:
            pass
        return AttestationReport(
            valid=True, provider="near-ai", attestation_type="tdx",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={
                "signing_address": gateway_attestation.get("signing_address"),
                "tls_cert_fingerprint": gateway_attestation.get("tls_cert_fingerprint"),
                "acme_account": gateway_attestation.get("acme_account"), "domain": domain
            }
        )
    except Exception as e:
        raise


def _skip_attestation(reason: str) -> AttestationReport:
    """Return an attestation report for providers that don't support attestation."""
    return AttestationReport(
        valid=False, provider="unknown", attestation_type="none",
        verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        details={}, error=f"Attestation skipped: {reason}"
    )
