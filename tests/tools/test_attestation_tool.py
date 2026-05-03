"""Tests for tools/attestation_tool.py — TEE attestation introspection."""

import json

import pytest

from tools.attestation_tool import (
    ATTESTATION_STATUS_SCHEMA,
    attestation_status,
    check_attestation_requirements,
)


@pytest.fixture
def fresh_cache():
    """Empty _MODEL_ATTESTATION_CACHE for the duration of a test."""
    from hermes_cli import attestation as att_mod
    saved = dict(att_mod._MODEL_ATTESTATION_CACHE)
    att_mod._MODEL_ATTESTATION_CACHE.clear()
    try:
        yield att_mod._MODEL_ATTESTATION_CACHE
    finally:
        att_mod._MODEL_ATTESTATION_CACHE.clear()
        att_mod._MODEL_ATTESTATION_CACHE.update(saved)


def _make_report(valid=True, provider="near-ai", error=None):
    from hermes_cli.attestation import AttestationReport
    return AttestationReport(
        valid=valid,
        provider=provider,
        attestation_type="tdx+gpu",
        verified_at="2026-05-03T14:00:00Z",
        details={
            "gateway": {"signing_address": "0xgw", "app_id": "appgw", "status": "UpToDate"},
            "models": [{"signing_address": "0xm0", "app_id": "appm0", "gpu_verdict": "PASS"}],
        },
        signing_public_key="04abcd",
        signing_algo="ecdsa",
        error=error,
    )


class TestAttestationStatus:
    def test_empty_cache_returns_not_found(self, fresh_cache):
        out = json.loads(attestation_status())
        assert out["found"] is False
        assert "No attestation reports cached" in out["error"]

    def test_dump_all_returns_every_cached_report(self, fresh_cache):
        fresh_cache[("near-ai", "deepseek-ai/DeepSeek-V3.1")] = _make_report()
        fresh_cache[("near-ai", "openai/gpt-oss-120b")] = _make_report()
        out = json.loads(attestation_status())
        assert out["found"] is True
        assert set(out["verified_models"].keys()) == {
            "near-ai/deepseek-ai/DeepSeek-V3.1",
            "near-ai/openai/gpt-oss-120b",
        }

    def test_targeted_lookup_returns_single_report(self, fresh_cache):
        fresh_cache[("near-ai", "deepseek-ai/DeepSeek-V3.1")] = _make_report()
        out = json.loads(attestation_status(
            provider="near-ai", model="deepseek-ai/DeepSeek-V3.1",
        ))
        assert out["found"] is True
        assert out["report"]["valid"] is True
        assert out["report"]["provider"] == "near-ai"
        assert out["report"]["signing_public_key"] == "04abcd"
        assert out["report"]["details"]["gateway"]["app_id"] == "appgw"

    def test_targeted_lookup_misses_returns_helpful_error(self, fresh_cache):
        out = json.loads(attestation_status(provider="near-ai", model="not/cached"))
        assert out["found"] is False
        assert "near-ai/not/cached" in out["error"]

    def test_invalid_report_surfaces_error_field(self, fresh_cache):
        fresh_cache[("near-ai", "broken/model")] = _make_report(
            valid=False, error="GPU verification failed",
        )
        out = json.loads(attestation_status(provider="near-ai", model="broken/model"))
        assert out["report"]["valid"] is False
        assert out["report"]["error"] == "GPU verification failed"


class TestCheckRequirements:
    def test_returns_true_when_module_importable(self):
        assert check_attestation_requirements() is True


class TestSchema:
    def test_schema_name(self):
        assert ATTESTATION_STATUS_SCHEMA["name"] == "attestation_status"

    def test_schema_no_required_args(self):
        assert ATTESTATION_STATUS_SCHEMA["parameters"]["required"] == []

    def test_schema_describes_provider_and_model(self):
        props = ATTESTATION_STATUS_SCHEMA["parameters"]["properties"]
        assert "provider" in props
        assert "model" in props


class TestRegistryWiring:
    def test_tool_registered_after_import(self):
        import tools.attestation_tool  # noqa: F401  (registers on import)
        from tools.registry import registry
        entry = registry.get_entry("attestation_status")
        assert entry is not None
        assert entry.toolset == "attestation"

    def test_listed_in_hermes_core_tools(self):
        from toolsets import _HERMES_CORE_TOOLS
        assert "attestation_status" in _HERMES_CORE_TOOLS

    def test_attestation_toolset_defined(self):
        from toolsets import TOOLSETS
        assert "attestation" in TOOLSETS
        assert TOOLSETS["attestation"]["tools"] == ["attestation_status"]
