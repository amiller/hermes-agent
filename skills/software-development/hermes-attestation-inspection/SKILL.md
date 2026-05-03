---
name: hermes-attestation-inspection
description: Answer user questions about TEE attestation by calling the attestation_status tool — never speculate.
version: 3.0.0
author: amiller (Hermes Agent)
license: MIT
metadata:
  hermes:
    tags: [attestation, tdx, gpu, nras, phala, redpill, near-ai, venice, e2ee]
    related_skills: []
---

# When to use

The user asks anything about attestation, the TEE, the signing key, TDX quotes,
GPU/NRAS verification, the model's app_id, compose hash, or "is this verified."

# How

Call the **`attestation_status`** tool. Without arguments it returns every
verified attestation cached this session; with `provider` + `model` it
returns one specific report.

The tool reads `hermes_cli.attestation`'s in-process cache — no network calls,
no re-verification. The verification itself ran client-side at session start;
this tool just surfaces what was found.

# What you'll get back

A JSON blob per verified `(provider, model)` with:
- `valid` — overall verdict (bool)
- `attestation_type` — e.g. `tdx+gpu` for near-ai
- `signing_public_key` / `signing_algo` — the E2EE inner-channel key,
  hardware-bound to the TEE
- `details.gateway` — gateway signing address, TLS fingerprint, app_id, TCB
  status with Intel advisory IDs
- `details.models[]` — per-model signing address, app_id, `compose_hash_verified`,
  GPU verdict from NVIDIA NRAS
- `error` — populated and `valid=False` if anything failed

# Important constraints

- **Don't invent details.** If the tool returns `found: false`, say
  attestation isn't cached for this session — don't make up TDX/GPU
  specifics.
- **SGX is not used** anywhere in this code path. If you find yourself
  about to mention SGX, you're guessing — call the tool instead.
- **No persistent DB.** Reports live only in process memory. A hermes
  restart means a re-verify on next use.

# Ground truth

Verifier source: `hermes_cli/attestation.py`. The tool is a thin read-only
wrapper over `_MODEL_ATTESTATION_CACHE`.
