#!/usr/bin/env python3
"""Attestation Status Tool — introspect TEE attestation from inside the agent.

Returns the verified attestation report(s) for TEE-attested inference providers
(near-ai, redpill, venice). Reads the in-process verification cache populated
by ``hermes_cli.attestation`` when the runtime client was created — no network
calls, no re-verification.

This tool exists so the agent can give a grounded answer when the user asks
"is your inference attested? what did you verify?" instead of guessing from
priors. The verification itself happens client-side at session start; this tool
just surfaces the cached result.
"""

import json
from typing import Any, Dict, Optional


def _serialize_report(report) -> Dict[str, Any]:
    """Convert an AttestationReport into a JSON-friendly dict."""
    return {
        "valid": report.valid,
        "provider": report.provider,
        "attestation_type": report.attestation_type,
        "verified_at": report.verified_at,
        "signing_public_key": report.signing_public_key,
        "signing_algo": report.signing_algo,
        "details": report.details,
        "error": report.error,
    }


def attestation_status(
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    """Return verified attestation reports from the in-process cache.

    Args:
        provider: Optional provider id (``near-ai``, ``redpill``, ``venice``).
        model:    Optional model id, e.g. ``deepseek-ai/DeepSeek-V3.1``.

    With both ``provider`` and ``model``, returns that single report.
    Otherwise returns every report cached this session.
    """
    from hermes_cli.attestation import _MODEL_ATTESTATION_CACHE

    if provider and model:
        rep = _MODEL_ATTESTATION_CACHE.get((provider, model))
        if rep is None:
            return json.dumps({
                "found": False,
                "error": (
                    f"No verified attestation cached for {provider}/{model}. "
                    "Either the model has not been used in this session, or "
                    "attestation is disabled in config (model.attestation.enabled)."
                ),
            })
        return json.dumps(
            {"found": True, "report": _serialize_report(rep)},
            default=str,
        )

    per_model = {
        f"{p}/{m}": _serialize_report(rep)
        for (p, m), rep in _MODEL_ATTESTATION_CACHE.items()
    }
    if not per_model:
        return json.dumps({
            "found": False,
            "error": (
                "No attestation reports cached. Either (a) the active provider is "
                "not TEE-attested (only near-ai, redpill, and venice are), "
                "(b) attestation is disabled in config, or "
                "(c) no model has been used yet this session."
            ),
        })
    return json.dumps(
        {"found": True, "verified_models": per_model},
        default=str,
    )


def check_attestation_requirements() -> bool:
    """Available whenever ``hermes_cli.attestation`` is importable."""
    try:
        import hermes_cli.attestation  # noqa: F401
        return True
    except Exception:
        return False


ATTESTATION_STATUS_SCHEMA = {
    "name": "attestation_status",
    "description": (
        "Return the verified TEE attestation report(s) for the current "
        "inference session. Reads the in-process verification cache "
        "populated by hermes_cli.attestation when the runtime client was "
        "created — no network calls, no re-verification.\n\n"
        "Use this whenever the user asks about attestation, the TEE, "
        "the signing key, GPU/NRAS verification, TDX quotes, app_id, "
        "compose hash, or whether the model is hardware-bound. Prefer "
        "this over speculating: if the cache is empty the tool says so, "
        "and you can answer 'attestation isn't enabled for this provider' "
        "without inventing details.\n\n"
        "Each report includes: ``valid`` (bool), ``provider``, "
        "``attestation_type`` (e.g. ``tdx+gpu``), ``verified_at``, "
        "``signing_public_key`` (the E2EE inner-channel key, hardware-"
        "bound to the TEE), ``signing_algo``, and ``details`` (gateway "
        "and per-model signing addresses, app_id from the CVM's tcb_info, "
        "TCB status with Intel advisory IDs, ``compose_hash_verified`` "
        "flag, and GPU verdict from NVIDIA NRAS).\n\n"
        "Without arguments, returns all cached reports for this session. "
        "With ``provider`` and ``model``, returns that one report."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "description": "Provider id (e.g. 'near-ai'). Optional.",
            },
            "model": {
                "type": "string",
                "description": "Model id (e.g. 'deepseek-ai/DeepSeek-V3.1'). Optional.",
            },
        },
        "required": [],
    },
}


from tools.registry import registry

registry.register(
    name="attestation_status",
    toolset="attestation",
    schema=ATTESTATION_STATUS_SCHEMA,
    handler=lambda args, **kw: attestation_status(
        provider=args.get("provider"),
        model=args.get("model"),
    ),
    check_fn=check_attestation_requirements,
    emoji="🔐",
)
