# TEE Attestation Probe Results — NEAR AI & Redpill

Probed on **2026-04-20** using the hermes-cli strict attestation verifier (TDX
quote + NVIDIA NRAS GPU + E2EE key binding + compose hash). No fallbacks,
no skipped steps. Source verifier for Redpill: the four-backend docs in
`refs/redpill-verifier/`.

## Provider Summary

| Provider | Endpoint                                      | Models tested | Passing | Failing |
|----------|-----------------------------------------------|--------------:|--------:|--------:|
| NEAR AI  | `https://cloud-api.near.ai/v1`                |             8 |       2 |       6 |
| Redpill  | `https://api.red-pill.ai/v1`                  |            15 |      12 |       3 |

## Redpill — model × backend shape

Redpill routes to four backend types per their verifier docs. Our probe
dispatches on the response shape:

| Model                                       | Shape                 | Attestation type | Verdict | Probe time | Error |
|---------------------------------------------|-----------------------|------------------|:-------:|-----------:|-------|
| `phala/gpt-oss-20b`                         | phala-simple          | tdx+gpu          | ✅ pass | 2.9s       |       |
| `phala/glm-4.7-flash`                       | phala-simple          | tdx+gpu          | ✅ pass | 2.9s       |       |
| `phala/qwen-2.5-7b-instruct`                | phala-simple          | tdx+gpu          | ✅ pass | 3.2s       |       |
| `phala/qwen2.5-vl-72b-instruct`             | phala-simple          | tdx+gpu          | ✅ pass | 2.6s       |       |
| `phala/qwen3-vl-30b-a3b-instruct`           | phala-simple          | tdx+gpu          | ✅ pass | 2.9s       |       |
| `phala/qwen3.5-27b`                         | phala-simple          | tdx+gpu          | ✅ pass | 2.4s       |       |
| `phala/gemma-3-27b-it`                      | phala-simple          | tdx+gpu          | ✅ pass | 3.4s       |       |
| `phala/uncensored-24b`                      | phala-simple          | tdx+gpu          | ✅ pass | 2.7s       |       |
| `phala/glm-4.7`                             | nearai-via-redpill    | tdx+gpu          | ✅ pass | 5.0s       |       |
| `phala/deepseek-chat-v3.1`                  | nearai-via-redpill    | tdx+gpu          | ✅ pass | 79.1s      |       |
| `phala/deepseek-v3.2`                       | chutes                | chutes+tdx       | ✅ pass | 35.7s      |       |
| `phala/kimi-k2.5`                           | chutes                | chutes+tdx       | ✅ pass | 93.5s      |       |
| `phala/gpt-oss-120b`                        | nearai-via-redpill    | tdx+gpu          | ❌ fail | 3.2s       | TDX quote verification failed: ppid=`ca98bce2d0f6c53afd2a37537fcc3c3a` tcb_svn=`0b010200000000000000000000000000` |
| `phala/glm-5`                               | nearai-via-redpill    | tdx+gpu          | ❌ fail | 3.1s       | TDX quote verification failed: ppid=`ca98bce2d0f6c53afd2a37537fcc3c3a` tcb_svn=`0b010200000000000000000000000000` (same host as `gpt-oss-120b`) |
| `phala/qwen3-30b-a3b-instruct-2507`         | nearai-via-redpill    | tdx+gpu          | ❌ fail | 3.0s       | NVIDIA GPU attestation failed: NRAS returned `False` |

### Shape distribution

| Shape                 | Count | Observations |
|-----------------------|------:|--------------|
| `phala-simple`        |     8 | Fast (~3s). Top-level `intel_quote` + `nvidia_payload`. All passing. |
| `nearai-via-redpill`  |     5 | 2–80s. `gateway_attestation` + `model_attestations[]`. Two share a broken host (same PPID). |
| `chutes`              |     2 | 35–94s. `attestation_type="chutes"` + `all_attestations[]`. Anti-tamper binding: `SHA256(nonce‖e2e_pubkey) == report_data[0:32]`. Debug-mode check on `td_attributes & 1`. |
| `tinfoil`             |     0 | Not observed in the curated list. Spec: hw policy + Sigstore golden values. |

### Redpill findings to share

1. **Two Phala-backend models stuck on out-of-date firmware.**
   `phala/gpt-oss-120b` and `phala/glm-5` both TDX-fail with the same PPID
   (`ca98bce2d0f6c53afd2a37537fcc3c3a`) and the same `tee_tcb_svn`
   (`0b010200000000000000000000000000`) — they're evidently co-located on a
   node whose firmware hasn't been patched. Users who pick these models get a
   confusing "quote invalid" error with no path to remediation.

2. **`phala/qwen3-30b-a3b-instruct-2507` has a persistently broken GPU
   attestation.** NRAS returns `False` deterministically — the model's
   NVIDIA payload is rejected by Nvidia's remote service.

3. **Chutes latency.** 35–94s per probe because the response bundles five
   instances × per-instance TDX quotes, each cross-verified via Phala's
   verifier. Workable for a one-shot verify, too slow to be in any hot path.
   Would be great if the Chutes aggregate endpoint exposed a cached `verified_at`
   that clients could trust inside a short window.

4. **Shape dispatch is undocumented in the public API.** The presence/absence
   of `attestation_type` / `gateway_attestation` / top-level `intel_quote` is
   the only way for a client to know which verifier to run. Worth documenting.

## NEAR AI — full results

| Model                                             | Verdict | Probe time | Error |
|---------------------------------------------------|:-------:|-----------:|-------|
| `zai-org/GLM-5.1-FP8`                             | ✅ pass | 16.6s      |       |
| `zai-org/GLM-5-FP8`                               | ✅ pass | 11.2s      |       |
| `openai/gpt-oss-120b`                             | ❌ fail | 5.7s       | Model attestation #1 GPU verification failed (NRAS `False`) |
| `Qwen/Qwen3-30B-A3B-Instruct-2507`                | ❌ fail | 18.0s      | Model attestation #1 GPU verification failed (NRAS `False`) |
| `Qwen/Qwen3.5-122B-A10B`                          | ❌ fail | 8.8s       | Model attestation #1 GPU verification failed (NRAS `False`) |
| `Qwen/Qwen3-VL-30B-A3B-Instruct`                  | ❌ fail | 8.1s       | Model attestation #1 GPU verification failed (NRAS `False`) |
| `deepseek-ai/DeepSeek-V3-0324`                    | ❌ fail | 0.5s       | HTTP 503 from `/v1/attestation/report` |
| `meta-llama/Llama-4-Scout-17B-16E-Instruct`       | ❌ fail | 0.4s       | HTTP 503 from `/v1/attestation/report` |

### NEAR AI findings to share

1. **Only 2 of 8 curated models pass strict attestation today.** The passing
   pair is both `zai-org/GLM-*`; every other model fails GPU attestation or
   503s at the attestation endpoint. This is surprisingly consistent with the
   first-run probe we did last week — the GPU-failing set has not rotated.

2. **`Qwen/Qwen3-30B-A3B-Instruct-2507` fails on both NEAR AI and Redpill.**
   On NEAR AI the model's GPU attestation is rejected by NRAS; on Redpill the
   same model (routed via the `nearai-via-redpill` shape) hits the same NRAS
   rejection. Likely the same upstream NEAR AI fleet node.

3. **TCB is OutOfDate on the gateway CVM.** Gateway TDX quote verifies, but
   the platform TCB carries advisories INTEL-SA-01036 / 01079 / 01099 / 01103
   / 01111. The quote passes (as it should — OutOfDate ≠ invalid), but the
   firmware on the gateway host is behind. We log a `warning` rather than
   fail; still worth flagging to the operator.

4. **503s on `deepseek-v3` and `llama-4-scout` are deterministic in this
   window** (sub-500ms from the endpoint). Either the attestation service
   doesn't know about those models yet, or the backing CVM is offline. Either
   way the `/v1/attestation/report` route should distinguish "unknown model"
   from "transient 503".

## Method

- Verifier: `hermes_cli/attestation.py` in this branch. Strict; no skips.
- Parallel probes via `ThreadPoolExecutor` (near-ai max_workers=4,
  redpill max_workers=6).
- Cache cleared between shape-detection and full-verification passes.
- Nonces are fresh per call; cache key is `(provider, base_url, model_id)`.
- TLS cert fingerprint pinned on successful verify; invalidated on cert
  change.
- Run command (reproducible):
  ```
  export HERMES_HOME=/home/amiller/.hermes-near-test
  set -a; source $HERMES_HOME/.env; set +a
  hermes attest-probe near-ai   # TODO: expose as subcommand; today it's the
  hermes attest-probe redpill   # probe_models_for_provider helper in attestation.py
  ```
