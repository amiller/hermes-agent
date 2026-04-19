"""TEE Attestation verification module for Hermes Agent."""
import asyncio
import contextlib
import hashlib
import io
import logging
import os
import secrets
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import base64
import json as _json

import requests

logger = logging.getLogger(__name__)

_PHALA_TDX_VERIFIER = "https://cloud-api.phala.network/api/v1/attestations/verify"
_NVIDIA_NRAS = "https://nras.attestation.nvidia.com/v3/attest/gpu"

# Add vendored verifier modules to path.
# Default: alongside this repo at refs/nearai-cloud-verifier/py; override with NEARAI_VERIFIER_PATH.
_default_verifier_path = os.path.join(os.path.dirname(__file__), "..", "..", "hermes-agent", "refs", "nearai-cloud-verifier", "py")
vendor_path = os.environ.get("NEARAI_VERIFIER_PATH", _default_verifier_path)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

_VERIFIER_AVAILABLE = False
try:
    from model_verifier import check_tdx_quote, check_report_data, check_gpu
    from domain_verifier import DomainAttestation, verify_domain_attestation
    _VERIFIER_AVAILABLE = True
except ImportError:
    pass

# Set HERMES_ATTESTATION_VERBOSE=1 to print verifier output to console.
_VERBOSE = os.getenv("HERMES_ATTESTATION_VERBOSE", "") == "1"


@dataclass
class AttestationReport:
    """TEE attestation verification result."""
    valid: bool
    provider: str
    attestation_type: str
    verified_at: str
    details: Dict[str, Any]
    error: Optional[str] = None
    verifier_output: str = ""  # captured stdout from verifier; shown when verbose
    signing_public_key: Optional[str] = None
    signing_algo: str = "ecdsa"


# Cache: {(provider_id, base_url): (report, verified_at_ms, pinned_cert_fingerprint)}
_ATTESTATION_CACHE: Dict[tuple, tuple] = {}
_DEFAULT_TTL_SECONDS = 3600
_FAILURE_TTL_SECONDS = 60  # re-try failed attestations after 60s


def _live_tls_fingerprint(base_url: str) -> Optional[str]:
    """SHA-256 of the live server's leaf certificate (DER)."""
    try:
        parsed = urlparse(base_url)
        host, port = parsed.hostname, parsed.port or 443
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        return hashlib.sha256(der).hexdigest() if der else None
    except Exception as e:
        logger.debug("live TLS fingerprint probe failed: %s", e)
        return None


def verify_attestation(provider_id: str, runtime_creds: Dict[str, Any], config: Dict[str, Any]) -> AttestationReport:
    """Verify TEE attestation for a provider, with cache.

    Cache is keyed on (provider_id, base_url) and pinned to the live TLS cert
    fingerprint. Successful reports are cached for HERMES_ATTESTATION_TTL seconds
    (default 3600). Failed reports are cached for 60s to avoid hammering the endpoint.
    """
    base_url = (runtime_creds.get("base_url") or "").rstrip("/")
    cache_key = (provider_id, base_url)
    ttl = int(os.getenv("HERMES_ATTESTATION_TTL", str(_DEFAULT_TTL_SECONDS)))

    cached = _ATTESTATION_CACHE.get(cache_key)
    if cached:
        cached_report, verified_at_ms, pinned_fpr = cached
        effective_ttl = ttl if cached_report.valid else _FAILURE_TTL_SECONDS
        age_ms = int(time.time() * 1000) - verified_at_ms
        if age_ms < effective_ttl * 1000:
            if cached_report.valid:
                live_fpr = _live_tls_fingerprint(base_url)
                if live_fpr and pinned_fpr and live_fpr != pinned_fpr:
                    pass  # cert changed — fall through to re-verify
                else:
                    return cached_report
            else:
                return cached_report  # don't re-check TLS for failures

    if provider_id == "redpill":
        report = _verify_redpill_attestation(runtime_creds, config)
    elif provider_id == "near-ai":
        if not _VERIFIER_AVAILABLE:
            return AttestationReport(
                valid=False, provider=provider_id, attestation_type="none",
                verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                details={}, error="Attestation verifier dependencies not available"
            )
        else:
            report = _verify_near_ai_attestation(runtime_creds, config)
    else:
        report = _skip_attestation("not-implemented")

    live_fpr_now = _live_tls_fingerprint(base_url) if report.valid else None
    _ATTESTATION_CACHE[cache_key] = (report, int(time.time() * 1000), live_fpr_now)

    if _VERBOSE and report.verifier_output:
        print(report.verifier_output, end="")
    elif report.verifier_output:
        logger.debug("attestation verifier output:\n%s", report.verifier_output.rstrip())

    return report


def _verify_near_ai_attestation(runtime_creds: Dict[str, Any], config: Dict[str, Any]) -> AttestationReport:
    """Verify NEAR AI Cloud TEE attestation: gateway + model TDX quotes, GPU, E2EE key binding."""
    api_key = runtime_creds.get("api_key", "")
    base_url = runtime_creds.get("base_url", "https://cloud-api.near.ai").rstrip("/")
    if not api_key:
        return AttestationReport(
            valid=False, provider="near-ai", attestation_type="tdx",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={}, error="No API key in runtime credentials"
        )

    nonce = secrets.token_hex(32)
    url = f"{base_url}/v1/attestation/report"
    params = {"nonce": nonce, "signing_algo": "ecdsa", "include_tls_fingerprint": "true"}
    response = requests.get(url, params=params, headers={"Authorization": f"Bearer {api_key}"}, timeout=30)
    response.raise_for_status()
    report = response.json()
    verifier_out = ""
    now = lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _fail(error, details=None):
        return AttestationReport(
            valid=False, provider="near-ai", attestation_type="tdx",
            verified_at=now(), details=details or {}, error=error,
            verifier_output=verifier_out,
        )

    # ── Gateway attestation ──────────────────────────────────────────────────
    gateway = report.get("gateway_attestation", {})
    if not gateway:
        return _fail("No gateway_attestation in response")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        gw_intel = asyncio.run(check_tdx_quote(gateway))
    verifier_out += buf.getvalue()

    if not gw_intel or not gw_intel.get("verified", False):
        return _fail("Gateway TDX quote verification failed", {"intel_result": gw_intel})

    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        gw_rd = check_report_data(gateway, nonce, gw_intel)
    verifier_out += buf2.getvalue()

    if not gw_rd.get("binds_address"):
        return _fail("Gateway report_data does not bind signing address + TLS fingerprint")
    if not gw_rd.get("embeds_nonce"):
        return _fail("Gateway report_data does not embed request nonce")

    tls_certificate = report.get("tls_certificate", "")
    if not tls_certificate:
        return _fail("No tls_certificate in response")

    domain = urlparse(base_url).netloc
    buf3 = io.StringIO()
    with contextlib.redirect_stdout(buf3):
        try:
            asyncio.run(verify_domain_attestation(DomainAttestation(
                domain=domain, sha256sum=gateway.get("tls_cert_fingerprint", ""),
                acme_account=gateway.get("acme_account", ""), cert=tls_certificate,
                intel_quote=gateway.get("intel_quote", ""), info=gateway
            )))
        except Exception:
            pass
    verifier_out += buf3.getvalue()

    gw_status = gw_intel.get("status", "Unknown")
    gw_advisories = gw_intel.get("advisory_ids", [])

    # ── Model attestations ───────────────────────────────────────────────────
    model_atts = report.get("model_attestations") or []
    if not model_atts:
        return _fail("No model_attestations in response — cannot verify E2EE key")

    model_signing_key = None
    model_details = []

    for i, model_att in enumerate(model_atts):
        buf_m = io.StringIO()
        with contextlib.redirect_stdout(buf_m):
            m_intel = asyncio.run(check_tdx_quote(model_att))
        verifier_out += buf_m.getvalue()

        if not m_intel or not m_intel.get("verified", False):
            return _fail(f"Model attestation #{i+1} TDX quote verification failed")

        buf_m2 = io.StringIO()
        with contextlib.redirect_stdout(buf_m2):
            m_rd = check_report_data(model_att, nonce, m_intel)
        verifier_out += buf_m2.getvalue()

        if not m_rd.get("binds_address"):
            return _fail(f"Model attestation #{i+1} report_data does not bind signing address + nonce")
        if not m_rd.get("embeds_nonce"):
            return _fail(f"Model attestation #{i+1} report_data does not embed request nonce")

        if not model_att.get("nvidia_payload"):
            return _fail(f"Model attestation #{i+1} missing nvidia_payload — GPU attestation required")
        buf_m3 = io.StringIO()
        with contextlib.redirect_stdout(buf_m3):
            gpu_result = check_gpu(model_att, nonce)
        verifier_out += buf_m3.getvalue()

        if gpu_result.get("verdict") not in ("PASS", True):
            return _fail(f"Model attestation #{i+1} GPU verification failed: {gpu_result.get('verdict')}")
        if not gpu_result.get("nonce_matches"):
            return _fail(f"Model attestation #{i+1} GPU nonce mismatch")

        # compose hash for model CVM
        info = model_att.get("info", {})
        tcb_info = info.get("tcb_info", {})
        if isinstance(tcb_info, str):
            try:
                tcb_info = _json.loads(tcb_info)
            except Exception:
                tcb_info = {}
        app_compose = tcb_info.get("app_compose") if tcb_info else None
        m_mr_config = m_intel.get("quote", {}).get("body", {}).get("mrconfig", "")
        compose_verified = False
        if app_compose and m_mr_config:
            compose_hash = hashlib.sha256(app_compose.encode()).hexdigest()
            compose_verified = m_mr_config.lower().startswith(("01" + compose_hash).lower())

        # verify signing_public_key derives to signing_address (so we know the E2EE key is hardware-bound)
        spk = model_att.get("signing_public_key")
        signing_addr = model_att.get("signing_address", "")
        if spk and signing_addr:
            from eth_keys.datatypes import PublicKey as _EthPubKey
            pub_bytes = bytes.fromhex(spk)
            if len(pub_bytes) == 65 and pub_bytes[0] == 0x04:
                pub_bytes = pub_bytes[1:]
            derived = "0x" + _EthPubKey(pub_bytes).to_canonical_address().hex()
            if derived.lower() != signing_addr.lower():
                return _fail(
                    f"Model attestation #{i+1} signing_public_key does not derive to signing_address",
                    {"derived": derived, "claimed": signing_addr},
                )
            if i == 0:
                model_signing_key = spk

        model_details.append({
            "signing_address": signing_addr,
            "app_id": info.get("app_id"),
            "status": m_intel.get("status"),
            "advisory_ids": m_intel.get("advisory_ids", []),
            "compose_hash_verified": compose_verified,
            "gpu_verdict": gpu_result.get("verdict"),
        })

    return AttestationReport(
        valid=True, provider="near-ai", attestation_type="tdx+gpu",
        verified_at=now(),
        details={
            "gateway": {
                "signing_address": gateway.get("signing_address"),
                "tls_cert_fingerprint": gateway.get("tls_cert_fingerprint"),
                "domain": domain,
                "app_id": gateway.get("info", {}).get("app_id"),
                "status": gw_status,
                "advisory_ids": gw_advisories,
            },
            "models": model_details,
        },
        signing_public_key=model_signing_key,
        signing_algo="ecdsa",
        verifier_output=verifier_out,
    )


def _decode_nvidia_verdict(jwt_token: str) -> str:
    """Extract x-nvidia-overall-att-result from a NRAS JWT response."""
    payload_b64 = jwt_token.split(".")[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    payload = _json.loads(base64.urlsafe_b64decode(padded).decode())
    return payload.get("x-nvidia-overall-att-result", "UNKNOWN")


def _phala_check_report_data(report_data_hex: str, signing_address: str, signing_algo: str, nonce: str) -> bool:
    """Verify TDX report_data = signing_address (padded to 32 bytes) || nonce (32 bytes)."""
    try:
        rd = bytes.fromhex(report_data_hex.removeprefix("0x"))
        addr_hex = signing_address.removeprefix("0x")
        addr_bytes = bytes.fromhex(addr_hex)
        embedded_addr = rd[:32]
        embedded_nonce = rd[32:64]
        return (embedded_addr == addr_bytes.ljust(32, b"\x00")) and (embedded_nonce.hex() == nonce)
    except Exception:
        return False


def _verify_redpill_attestation(runtime_creds: Dict[str, Any], config: Dict[str, Any]) -> AttestationReport:
    """Verify Redpill/Phala TEE attestation: TDX quote + compose hash + NVIDIA GPU."""
    api_key = runtime_creds.get("api_key", "")
    base_url = runtime_creds.get("base_url", "https://api.red-pill.ai/v1").rstrip("/")
    # strip trailing /v1 so we can append it consistently
    api_base = base_url[:-3] if base_url.endswith("/v1") else base_url
    model = runtime_creds.get("model", "")
    if not api_key:
        return AttestationReport(
            valid=False, provider="redpill", attestation_type="tdx+gpu",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={}, error="No API key in runtime credentials"
        )
    if not model:
        return AttestationReport(
            valid=False, provider="redpill", attestation_type="tdx+gpu",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={}, error="No model in runtime credentials"
        )
    nonce = secrets.token_hex(32)
    url = f"{api_base}/v1/attestation/report"
    response = requests.get(url, params={"model": model, "nonce": nonce},
                            headers={"Authorization": f"Bearer {api_key}"}, timeout=30)
    response.raise_for_status()
    report = response.json()

    gateway_att = report.get("gateway_attestation", {})
    model_atts = report.get("model_attestations", [])
    if not gateway_att:
        return AttestationReport(
            valid=False, provider="redpill", attestation_type="tdx+gpu",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={"report": report}, error="No gateway_attestation in response"
        )

    # 1. TDX quote via Phala's verifier
    tdx_resp = requests.post(_PHALA_TDX_VERIFIER, json={"hex": gateway_att["intel_quote"]}, timeout=30).json()
    quote_body = (tdx_resp.get("quote") or {}).get("body", {})
    if not (tdx_resp.get("quote") or {}).get("verified"):
        msg = (tdx_resp.get("quote") or {}).get("message") or tdx_resp.get("message") or "unspecified"
        node = tdx_resp.get("node_provider") or {}
        ppid = node.get("ppid")
        tcb_svn = quote_body.get("tee_tcb_svn")
        detail_str = f"ppid={ppid} tcb_svn={tcb_svn}" if ppid else msg
        return AttestationReport(
            valid=False, provider="redpill", attestation_type="tdx+gpu",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={"ppid": ppid, "tcb_svn": tcb_svn},
            error=f"TDX quote verification failed: {detail_str}"
        )

    # 2. report_data binds signing_address + nonce
    report_data_hex = quote_body.get("reportdata", "")
    signing_address = gateway_att.get("signing_address", "")
    signing_algo = gateway_att.get("signing_algo", "ecdsa")
    if not _phala_check_report_data(report_data_hex, signing_address, signing_algo, nonce):
        return AttestationReport(
            valid=False, provider="redpill", attestation_type="tdx+gpu",
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details={}, error="TDX report_data does not bind signing address + nonce"
        )

    # 3. Compose hash committed in mr_config
    mr_config = quote_body.get("mrconfig", "")
    info = gateway_att.get("info", {})
    tcb_info = info.get("tcb_info", {})
    if isinstance(tcb_info, str):
        try:
            tcb_info = _json.loads(tcb_info)
        except Exception:
            tcb_info = {}
    app_compose = tcb_info.get("app_compose")
    compose_hash_verified = False
    if app_compose and mr_config:
        compose_hash = hashlib.sha256(app_compose.encode()).hexdigest()
        expected = ("0x01" + compose_hash).lower()
        compose_hash_verified = mr_config.lower().startswith(expected)

    # 4. NVIDIA GPU attestation from model_attestations
    gpu_verdict = None
    if model_atts:
        nvidia_payload = model_atts[0].get("nvidia_payload")
        if nvidia_payload:
            if isinstance(nvidia_payload, str):
                nvidia_payload = _json.loads(nvidia_payload)
            gpu_resp = requests.post(_NVIDIA_NRAS, json=nvidia_payload, timeout=30).json()
            gpu_verdict = _decode_nvidia_verdict(gpu_resp[0][1])
            gpu_passed = gpu_verdict is True or gpu_verdict == "PASS"
            if not gpu_passed:
                return AttestationReport(
                    valid=False, provider="redpill", attestation_type="tdx+gpu",
                    verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    details={"gpu_verdict": gpu_verdict}, error=f"NVIDIA GPU attestation failed: {gpu_verdict}"
                )

    model_signing_key = model_atts[0].get("signing_public_key") if model_atts else None
    return AttestationReport(
        valid=True, provider="redpill", attestation_type="tdx+gpu",
        verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        details={
            "signing_address": signing_address,
            "model": model,
            "compose_hash_verified": compose_hash_verified,
            "gpu_verdict": gpu_verdict,
            "app_id": info.get("app_id"),
            "instance_id": info.get("instance_id"),
        },
        signing_public_key=model_signing_key,
        signing_algo=signing_algo,
    )


def _skip_attestation(reason: str) -> AttestationReport:
    return AttestationReport(
        valid=False, provider="unknown", attestation_type="none",
        verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        details={}, error=f"Attestation skipped: {reason}"
    )
