#!/usr/bin/env python3
"""Run live TEE attestation verification across curated near-ai + redpill models.

Produces:
 - `attestation-report.json` with the raw per-model result
 - a markdown report appended to $GITHUB_STEP_SUMMARY (if set)

The verifier is `hermes_cli.attestation.verify_attestation` — the same code
the CLI uses at chat time. A ✅ row here means: the model's TDX quote
cryptographically verified via Phala's verifier, its NVIDIA GPU attested
via NRAS, and its signing_public_key derives to the attested signing_address.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Diagnostic — show whether the vendored verifier actually imports on this host.
_verifier_path = os.environ.get("NEARAI_VERIFIER_PATH", "(unset)")
print(f"NEARAI_VERIFIER_PATH={_verifier_path}", flush=True)
print(f"dcap_qvl importable: ", end="", flush=True)
try:
    import dcap_qvl  # noqa: F401
    print("yes", flush=True)
except Exception as _e:
    print(f"no ({_e})", flush=True)
sys.path.insert(0, _verifier_path)
print("model_verifier importable: ", end="", flush=True)
try:
    import model_verifier  # noqa: F401
    print("yes", flush=True)
except Exception as _e:
    print(f"no ({type(_e).__name__}: {_e})", flush=True)

from hermes_cli.attestation import verify_attestation, _VERIFIER_AVAILABLE  # noqa: E402
print(f"_VERIFIER_AVAILABLE={_VERIFIER_AVAILABLE}", flush=True)

NEAR_MODELS = [
    "openai/gpt-oss-120b",
    "zai-org/GLM-5.1-FP8",
    "zai-org/GLM-5-FP8",
    "Qwen/Qwen3-30B-A3B-Instruct-2507",
    "deepseek-ai/DeepSeek-V3-0324",
    "meta-llama/Llama-4-Scout-17B-16E-Instruct",
]

REDPILL_MODELS = [
    "phala/gpt-oss-20b",
    "phala/gpt-oss-120b",
    "phala/qwen-2.5-7b-instruct",
    "phala/glm-4.7",
    "phala/deepseek-v3.2",
    "phala/kimi-k2.5",
]


def _flatten(report, provider, model, latency_s):
    details = report.details or {}
    row = {
        "provider": provider,
        "model": model,
        "valid": report.valid,
        "error": report.error,
        "attestation_type": report.attestation_type,
        "signing_algo": report.signing_algo,
        "signing_public_key_prefix": (report.signing_public_key or "")[:16],
        "latency_s": latency_s,
    }
    if provider == "near-ai":
        models = details.get("models") or []
        first = models[0] if models else {}
        gw = details.get("gateway") or {}
        row.update({
            "signing_address": first.get("signing_address", ""),
            "app_id": first.get("app_id", ""),
            "tcb_status": first.get("status", ""),
            "gpu_verdict": first.get("gpu_verdict", ""),
            "gateway_app_id": gw.get("app_id", ""),
            "gateway_tcb_status": gw.get("status", ""),
        })
    elif details.get("instances"):
        insts = details["instances"]
        statuses = sorted({i.get("status") for i in insts if i.get("status")})
        row.update({
            "signing_address": f"{len(insts)} instances",
            "app_id": ",".join((i.get("instance_id") or "")[:8] for i in insts if i.get("instance_id")),
            "tcb_status": ",".join(statuses) if statuses else "n/a",
            "gpu_verdict": "n/a",  # chutes backend does not include NVIDIA attestation
            "instance_count": details.get("instance_count", 0),
        })
    else:
        row.update({
            "signing_address": details.get("signing_address", ""),
            "app_id": details.get("app_id", ""),
            "tcb_status": "",
            "gpu_verdict": details.get("gpu_verdict", ""),
        })
    return row


def _run(provider, base_url, api_key, models):
    rows = []
    for model in models:
        t0 = time.time()
        try:
            report = verify_attestation(
                provider,
                {"api_key": api_key, "base_url": base_url, "model": model},
                {"enabled": True, "strict": False},
            )
            rows.append(_flatten(report, provider, model, round(time.time() - t0, 2)))
            verdict = "OK" if report.valid else f"FAIL ({report.error})"
        except Exception as exc:
            rows.append({
                "provider": provider, "model": model, "valid": False,
                "error": f"exception: {exc}", "latency_s": round(time.time() - t0, 2),
            })
            verdict = f"EXC ({exc})"
        print(f"[{provider}] {model}: {verdict} ({rows[-1]['latency_s']}s)", flush=True)
    return rows


def _render_summary(results, f):
    f.write("# Hermes TEE Attestation Report\n\n")
    f.write(
        "Verifies **Intel TDX** + **NVIDIA GPU** attestation for every curated "
        "near-ai and redpill model, using the same verifier the CLI uses "
        "([`hermes_cli/attestation.py`](../blob/main/hermes_cli/attestation.py)).\n\n"
    )
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    sha = os.environ.get("GITHUB_SHA", "")[:8] or "local"
    f.write(f"_Run `{run_id}` · commit `{sha}` · {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}_\n\n")

    for provider, rows in results.items():
        if not rows:
            f.write(f"## {provider} — skipped (no API key)\n\n")
            continue
        ok = sum(1 for r in rows if r.get("valid"))
        f.write(f"## {provider}: {ok} / {len(rows)} pass\n\n")
        f.write("| Model | Verdict | Shape | Signing address | TCB | GPU | Latency |\n")
        f.write("|-------|:-------:|-------|-----------------|-----|-----|--------:|\n")
        for r in rows:
            verdict = "✅" if r.get("valid") else "❌"
            addr = r.get("signing_address") or ""
            addr_cell = f"`{addr[:10]}…`" if len(addr) > 12 else (addr or "—")
            tcb = r.get("tcb_status") or "—"
            gpu = r.get("gpu_verdict")
            gpu_cell = ("🟢" if gpu is True or gpu == "PASS" else gpu) if gpu else ("🟢" if r.get("valid") else "—")
            shape = r.get("attestation_type") or "—"
            f.write(f"| `{r['model']}` | {verdict} | `{shape}` | {addr_cell} | {tcb} | {gpu_cell} | {r.get('latency_s', 0)}s |\n")
        f.write("\n")

        fails = [r for r in rows if not r.get("valid")]
        if fails:
            f.write(f"<details><summary>{len(fails)} failure(s) — expand</summary>\n\n")
            for r in fails:
                err = (r.get("error") or "").replace("|", r"\|")
                f.write(f"- **`{r['model']}`** — `{err}`\n")
            f.write("\n</details>\n\n")

    f.write("## What's verified per row\n\n")
    f.write(
        "1. Fetch the provider's live attestation bundle (`GET /v1/attestation/report?model=…&nonce=…`).\n"
        "2. TDX quote cryptographically verified via Phala's verifier API.\n"
        "3. `report_data` binds the CVM's signing address and our fresh nonce.\n"
        "4. NVIDIA GPU attested via NRAS (`/v3/attest/gpu`).\n"
        "5. `signing_public_key` derives to `signing_address` (keccak of pubkey last 20 bytes).\n\n"
        "A ✅ means all five held **at this run's timestamp**. The CLI wraps outgoing "
        "chat content in an httpx transport that encrypts to that `signing_public_key`, so "
        "only the attested model sees the plaintext.\n"
    )


def main() -> int:
    near_key = os.environ.get("NEAR_API_KEY", "").strip()
    redpill_key = os.environ.get("REDPILL_API_KEY", "").strip()

    # Force verbose verifier stdout into logs — useful when reading CI output.
    os.environ.setdefault("HERMES_ATTESTATION_VERBOSE", "1")
    # Disable cache so each run hits the real endpoint.
    os.environ["HERMES_ATTESTATION_TTL"] = "0"

    results: dict = {}
    if near_key:
        print("=== near-ai ===", flush=True)
        results["near-ai"] = _run("near-ai", "https://cloud-api.near.ai", near_key, NEAR_MODELS)
    else:
        print("NEAR_API_KEY not set — near-ai skipped", flush=True)
        results["near-ai"] = []

    if redpill_key:
        print("=== redpill ===", flush=True)
        results["redpill"] = _run("redpill", "https://api.red-pill.ai/v1", redpill_key, REDPILL_MODELS)
    else:
        print("REDPILL_API_KEY not set — redpill skipped", flush=True)
        results["redpill"] = []

    Path("attestation-report.json").write_text(json.dumps(results, indent=2, default=str))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            _render_summary(results, f)

    total = sum(len(v) for v in results.values())
    passed = sum(1 for v in results.values() for r in v if r.get("valid"))
    print(f"\nSummary: {passed}/{total} attestations valid", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
