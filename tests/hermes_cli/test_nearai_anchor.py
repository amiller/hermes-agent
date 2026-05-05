"""Tests for NEAR AI static anchor enforcement (Block B-static).

Until on-chain Base RPC reads land, hermes_cli/anchors/nearai_mainnet.json
is the authority for "is this CVM permitted to serve model M". These
tests cover the four pinned fields (app_id, compose_hash, os_image_hash,
key_provider_info.id) and the not-anchored model case. Live integration
coverage is in test_nearai_e2ee.py::TestNearAILiveAttestation."""

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from hermes_cli import attestation as att_mod
from hermes_cli.anchors import expected_for_model, load_nearai_anchor


_ANCHOR = load_nearai_anchor()
_GLM = "zai-org/GLM-5.1-FP8"


_FIXTURE_MRTD = "ab" * 48
_FIXTURE_RTMR3 = "cd" * 48
_FIXTURE_INNER_FILE = "GLM-5.1.yaml"
_FIXTURE_INNER_COMMIT = "cc38dabcfac34b6d3873111e33df4ba5e6cc73cf"
_FIXTURE_INNER_SHA = "3ac0d022eb5d2a135e1727cb3552f11101f6c00e3d9da687aa93fb09e33979cb"


def _override_anchor(compose_hash_hex, *, with_inner_yaml=True):
    """Build a fresh anchor dict that pins a synthetic compose_hash for GLM and
    install it as att_mod._NEARAI_ANCHOR (which the verifier reads at call time)."""
    glm_entry = {
        "app_id": _ANCHOR["models"][_GLM]["app_id"],
        "compose_hashes": [compose_hash_hex],
    }
    if with_inner_yaml:
        glm_entry["inner_yaml"] = {
            "file": _FIXTURE_INNER_FILE,
            "commits": [_FIXTURE_INNER_COMMIT],
            "file_sha256s": [_FIXTURE_INNER_SHA],
        }
    return {
        "kms_contract_addr": _ANCHOR["kms_contract_addr"],
        "kms_provider_info_id": _ANCHOR["kms_provider_info_id"],
        "os_image_hashes": list(_ANCHOR["os_image_hashes"]),
        "models": {_GLM: glm_entry},
    }


def _mock_check_tdx_quote_for(compose_hash_hex, *, cm_actions_hash=None, cm_nonce=None):
    """Returns a fake check_tdx_quote.

    The verifier calls this twice per request: once on the outer model attestation,
    once on the compose-manager attestation. Distinguish by the `quote` field —
    compose-manager's contains "compose-manager-quote" so we return matching
    report_data = actions_hash || nonce.
    """
    async def _fake(payload):
        if payload.get("intel_quote") == "compose-manager-quote":
            rd = (cm_actions_hash or "") + (cm_nonce or "")
            return {
                "verified": True, "status": "OK", "advisory_ids": [],
                "quote": {"body": {"reportdata": rd, "mrconfig": "01" + compose_hash_hex + ("00" * 16)}},
            }
        return {
            "verified": True, "status": "OK", "advisory_ids": [],
            "quote": {"body": {"mrconfig": "01" + compose_hash_hex + ("00" * 16)}},
        }
    return _fake


def _mock_extract_cm(_quote_hex):
    return _FIXTURE_MRTD, _FIXTURE_RTMR3


def _mock_check_report_data(_payload, _nonce, _intel):
    return {"binds_address": True, "embeds_nonce": True}


def _mock_check_gpu(_payload, _nonce):
    return {"verdict": "PASS", "nonce_matches": True}


def _mock_verify_domain(_atte):
    return None


def _build_compose_manager_attestation(*, file=_FIXTURE_INNER_FILE, commit=_FIXTURE_INNER_COMMIT,
                                       file_sha256=_FIXTURE_INNER_SHA, action="compose_up",
                                       actions_override=None, actions_hash="aa" * 32, nonce="bb" * 32):
    actions = actions_override if actions_override is not None else [
        {"action": action, "commit": commit, "file": file, "file_sha256": file_sha256,
         "tag": "v0.0.135", "timestamp": "2026-05-05T13:17:55.256851865+00:00"}
    ]
    return {
        "actions": actions,
        "actions_hash": actions_hash,
        "nonce": nonce,
        "nonce_source": "client",
        "quote": "compose-manager-quote",
        "report_data": actions_hash + nonce,
        "vm_config": {},
    }


def _build_payload(app_id, compose_str, os_image_hash, kpi_id, signing_pub_hex, signing_addr,
                   *, model_name=None, compose_manager_attestation=None,
                   tcb_info_extra=None):
    """Construct an attestation HTTP payload that the verifier will accept up to
    the anchor check (TDX/report_data/GPU/domain mocked as success)."""
    tcb_info = {"app_compose": compose_str, "mrtd": _FIXTURE_MRTD, "rtmr3": _FIXTURE_RTMR3}
    if tcb_info_extra:
        tcb_info.update(tcb_info_extra)
    info = {
        "app_id": app_id,
        "os_image_hash": os_image_hash,
        "key_provider_info": json.dumps({"name": "kms", "id": kpi_id}),
        "tcb_info": json.dumps(tcb_info),
    }
    model_att = {
        "info": info,
        "signing_address": signing_addr,
        "signing_public_key": signing_pub_hex,
        "nvidia_payload": "x",
        "intel_quote": "model-quote",
        "model_name": model_name if model_name is not None else _GLM,
        "compose_manager_attestation": (
            compose_manager_attestation
            if compose_manager_attestation is not None
            else _build_compose_manager_attestation()
        ),
    }
    gateway = {
        "info": {"app_id": app_id},
        "signing_address": "0xdeadbeef" + "00" * 16,
        "tls_cert_fingerprint": "ab" * 32,
        "intel_quote": "gateway-quote",
    }
    return {
        "gateway_attestation": gateway,
        "model_attestations": [model_att],
        "tls_certificate": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
    }


def _patched_run(payload, *, model=None):
    """Drive _verify_near_ai_attestation through the anchor logic with all
    upstream verifier checks mocked to PASS."""
    fake_resp = type("R", (), {
        "json": lambda self: payload,
        "raise_for_status": lambda self: None,
    })()
    compose_hash = hashlib.sha256(json.loads(payload["model_attestations"][0]["info"]["tcb_info"])["app_compose"].encode()).hexdigest()
    cm = payload["model_attestations"][0].get("compose_manager_attestation") or {}
    cm_actions_hash = cm.get("actions_hash", "")
    cm_nonce_in_payload = cm.get("nonce", "")
    with patch.object(att_mod.requests, "get", return_value=fake_resp), \
         patch.object(att_mod, "check_tdx_quote",
                      _mock_check_tdx_quote_for(compose_hash, cm_actions_hash=cm_actions_hash, cm_nonce=cm_nonce_in_payload)), \
         patch.object(att_mod, "check_report_data", _mock_check_report_data), \
         patch.object(att_mod, "check_gpu", _mock_check_gpu), \
         patch.object(att_mod, "verify_domain_attestation", _mock_verify_domain), \
         patch.object(att_mod, "_extract_cm_td_measurements", _mock_extract_cm), \
         patch.object(att_mod, "secrets", new_secrets_with(cm_nonce_in_payload)):
        return att_mod._verify_near_ai_attestation(
            {"api_key": "x", "base_url": "https://example.test", "model": model or _GLM},
            {},
        )


def new_secrets_with(token_hex_value):
    """Replace att_mod.secrets with a stub whose token_hex returns the test's nonce.

    The verifier captures `nonce = secrets.token_hex(32)` early; if we don't
    pin this, it won't match the compose_manager_attestation.nonce we built."""
    class _Stub:
        @staticmethod
        def token_hex(_n=32):
            return token_hex_value
    return _Stub()


# A fixed signing keypair whose public derives to a known address.
# Pulled from a deterministic test vector (private = b"\x01" * 32 -> known pub).
# eth_keys: PrivateKey(b'\x01'*32).public_key
_SIGNING_PUB_HEX = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1"
_SIGNING_ADDR = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1"


class _AnchorTestBase(unittest.TestCase):
    SYNTHETIC = "appcompose-fixture"

    def setUp(self):
        self.synthetic_hash = hashlib.sha256(self.SYNTHETIC.encode()).hexdigest()
        self._anchor_patcher = patch.object(
            att_mod, "_NEARAI_ANCHOR", _override_anchor(self.synthetic_hash)
        )
        self._anchor_patcher.start()

    def tearDown(self):
        self._anchor_patcher.stop()

    def _payload(self, **overrides):
        glm = att_mod._NEARAI_ANCHOR["models"][_GLM]
        defaults = dict(
            app_id=glm["app_id"],
            compose_str=self.SYNTHETIC,
            os_image_hash=att_mod._NEARAI_ANCHOR["os_image_hashes"][0],
            kpi_id=att_mod._NEARAI_ANCHOR["kms_provider_info_id"],
            signing_pub_hex=_SIGNING_PUB_HEX,
            signing_addr=_SIGNING_ADDR,
        )
        defaults.update(overrides)
        return _build_payload(**defaults)


class TestAnchorPositive(_AnchorTestBase):
    """Anchor matches → valid=True."""

    def test_matching_attestation_validates(self):
        report = _patched_run(self._payload())
        self.assertTrue(report.valid, f"expected valid; got error={report.error}")
        self.assertTrue(report.details["models"][0]["anchor_matched"])


class TestAnchorRefusals(_AnchorTestBase):
    """Each pinned field should fail closed independently."""

    def test_wrong_app_id_fails(self):
        report = _patched_run(self._payload(app_id="ff" * 20))
        self.assertFalse(report.valid)
        self.assertIn("app_id", report.error)

    def test_wrong_compose_fails(self):
        report = _patched_run(self._payload(compose_str="something-else"))
        self.assertFalse(report.valid)
        self.assertIn("compose_hash", report.error)

    def test_wrong_os_image_fails(self):
        report = _patched_run(self._payload(os_image_hash="ee" * 32))
        self.assertFalse(report.valid)
        self.assertIn("os_image_hash", report.error)

    def test_wrong_kpi_id_fails(self):
        report = _patched_run(self._payload(kpi_id="3059" + "ab" * 87))
        self.assertFalse(report.valid)
        self.assertIn("key_provider_info", report.error)

    def test_unanchored_model_fails(self):
        payload = self._payload()
        fake_resp = type("R", (), {
            "json": lambda self: payload,
            "raise_for_status": lambda self: None,
        })()
        with patch.object(att_mod.requests, "get", return_value=fake_resp), \
             patch.object(att_mod, "check_tdx_quote", _mock_check_tdx_quote_for(self.synthetic_hash)), \
             patch.object(att_mod, "check_report_data", _mock_check_report_data), \
             patch.object(att_mod, "check_gpu", _mock_check_gpu), \
             patch.object(att_mod, "verify_domain_attestation", _mock_verify_domain):
            report = att_mod._verify_near_ai_attestation(
                {"api_key": "x", "base_url": "https://example.test", "model": "not-in-anchor/foo"},
                {},
            )
        self.assertFalse(report.valid)
        self.assertIn("not-in-anchor/foo", report.error)


class TestAnchorSchema(unittest.TestCase):
    """The shipped anchor file is well-formed."""

    def test_schema(self):
        a = load_nearai_anchor()
        self.assertIn("kms_contract_addr", a)
        self.assertIn("kms_provider_info_id", a)
        self.assertIn("os_image_hashes", a)
        self.assertIsInstance(a["models"], dict)
        for model, e in a["models"].items():
            self.assertIn("app_id", e, f"{model} missing app_id")
            self.assertIn("compose_hashes", e, f"{model} missing compose_hashes")
            self.assertGreater(len(e["compose_hashes"]), 0, f"{model} empty compose_hashes")


class TestModelNameSubstitution(_AnchorTestBase):
    """The verifier must refuse when returned model_name != requested model.

    Live observation 2026-05-05: requesting deepseek-ai/DeepSeek-V3.1 returns
    Qwen/Qwen3.5-122B-A10B. Without a model_name check the user encrypts to
    the wrong TD's signing key for a model they didn't ask for."""

    def test_model_name_mismatch_fails(self):
        report = _patched_run(self._payload(model_name="some-other/model"))
        self.assertFalse(report.valid)
        self.assertIn("model_name", report.error)
        self.assertIn("substitution", report.error)


class TestBlockCInnerCompose(_AnchorTestBase):
    """Block C-static: compose_manager_attestation must verify and the latest
    compose_up for the expected file must match anchored (commit, file_sha256)."""

    def test_missing_compose_manager_fails(self):
        payload = self._payload(compose_manager_attestation={})
        # Pass an empty dict so the verifier's "missing" branch fires.
        report = _patched_run(payload)
        self.assertFalse(report.valid)
        self.assertIn("compose_manager_attestation", report.error)

    def test_empty_actions_log_fails(self):
        cm = _build_compose_manager_attestation(actions_override=[])
        report = _patched_run(self._payload(compose_manager_attestation=cm))
        self.assertFalse(report.valid)
        self.assertIn("actions=[]", report.error)

    def test_latest_action_compose_down_fails(self):
        cm = _build_compose_manager_attestation(action="compose_down")
        report = _patched_run(self._payload(compose_manager_attestation=cm))
        self.assertFalse(report.valid)
        self.assertIn("compose_down", report.error)

    def test_wrong_inner_commit_fails(self):
        cm = _build_compose_manager_attestation(commit="ff" * 20)
        report = _patched_run(self._payload(compose_manager_attestation=cm))
        self.assertFalse(report.valid)
        self.assertIn("inner_yaml commit", report.error)

    def test_wrong_inner_file_sha_fails(self):
        cm = _build_compose_manager_attestation(file_sha256="ee" * 32)
        report = _patched_run(self._payload(compose_manager_attestation=cm))
        self.assertFalse(report.valid)
        self.assertIn("file_sha256", report.error)

    def test_wrong_inner_file_name_fails(self):
        cm = _build_compose_manager_attestation(file="some-other.yaml")
        report = _patched_run(self._payload(compose_manager_attestation=cm))
        self.assertFalse(report.valid)
        self.assertIn("expected file", report.error)

    def test_compose_manager_actions_hash_mismatch_fails(self):
        # Force report_data to commit to a different actions_hash than what's
        # in the parsed cm response — i.e., the TDX hardware says SHA256(X) but
        # the JSON we'd verify against says X' ≠ X. Mock check_tdx_quote to
        # return report_data using one hash; the cm payload says a different one.
        from unittest.mock import patch as _p
        cm = _build_compose_manager_attestation(actions_hash="00" * 32)
        payload = self._payload(compose_manager_attestation=cm)
        fake_resp = type("R", (), {
            "json": lambda self: payload, "raise_for_status": lambda self: None,
        })()
        compose_hash = hashlib.sha256(
            json.loads(payload["model_attestations"][0]["info"]["tcb_info"])["app_compose"].encode()
        ).hexdigest()
        # Mock returns report_data using a DIFFERENT actions_hash than cm["actions_hash"]:
        with _p.object(att_mod.requests, "get", return_value=fake_resp), \
             _p.object(att_mod, "check_tdx_quote",
                       _mock_check_tdx_quote_for(compose_hash, cm_actions_hash="ff" * 32, cm_nonce=cm["nonce"])), \
             _p.object(att_mod, "check_report_data", _mock_check_report_data), \
             _p.object(att_mod, "check_gpu", _mock_check_gpu), \
             _p.object(att_mod, "verify_domain_attestation", _mock_verify_domain), \
             _p.object(att_mod, "_extract_cm_td_measurements", _mock_extract_cm), \
             _p.object(att_mod, "secrets", new_secrets_with(cm["nonce"])):
            report = att_mod._verify_near_ai_attestation(
                {"api_key": "x", "base_url": "https://example.test", "model": _GLM}, {},
            )
        self.assertFalse(report.valid)
        self.assertIn("actions_hash", report.error)

    def test_compose_manager_mrtd_mismatch_fails(self):
        # Patch _extract_cm_td_measurements to return an mr_td that doesn't
        # match the outer mrtd in tcb_info.
        from unittest.mock import patch as _p
        payload = self._payload()
        fake_resp = type("R", (), {
            "json": lambda self: payload,
            "raise_for_status": lambda self: None,
        })()
        compose_hash = hashlib.sha256(json.loads(payload["model_attestations"][0]["info"]["tcb_info"])["app_compose"].encode()).hexdigest()
        cm = payload["model_attestations"][0]["compose_manager_attestation"]
        with _p.object(att_mod.requests, "get", return_value=fake_resp), \
             _p.object(att_mod, "check_tdx_quote",
                       _mock_check_tdx_quote_for(compose_hash, cm_actions_hash=cm["actions_hash"], cm_nonce=cm["nonce"])), \
             _p.object(att_mod, "check_report_data", _mock_check_report_data), \
             _p.object(att_mod, "check_gpu", _mock_check_gpu), \
             _p.object(att_mod, "verify_domain_attestation", _mock_verify_domain), \
             _p.object(att_mod, "_extract_cm_td_measurements", lambda _q: ("99" * 48, _FIXTURE_RTMR3)), \
             _p.object(att_mod, "secrets", new_secrets_with(cm["nonce"])):
            report = att_mod._verify_near_ai_attestation(
                {"api_key": "x", "base_url": "https://example.test", "model": _GLM},
                {},
            )
        self.assertFalse(report.valid)
        self.assertIn("mr_td", report.error)
        self.assertIn("different TD images", report.error)

    def test_anchor_missing_inner_yaml_fails(self):
        # Anchor without inner_yaml means we can't verify Block C — refuse.
        from unittest.mock import patch as _p
        synthetic = self.synthetic_hash
        anchor_no_inner = _override_anchor(synthetic, with_inner_yaml=False)
        with _p.object(att_mod, "_NEARAI_ANCHOR", anchor_no_inner):
            payload = self._payload()
            report = _patched_run(payload)
        self.assertFalse(report.valid)
        self.assertIn("inner_yaml", report.error)


class TestBlockCPositive(_AnchorTestBase):
    """Block C path passes when actions[] latest compose_up matches anchored
    (commit, file_sha256), MRTD matches, RTMR3 matches, report_data binding holds."""

    def test_block_c_pass_records_inner_yaml(self):
        report = _patched_run(self._payload())
        self.assertTrue(report.valid, f"expected valid; got error={report.error}")
        inner = report.details["models"][0].get("inner_yaml")
        self.assertIsNotNone(inner)
        self.assertEqual(inner["file"], _FIXTURE_INNER_FILE)
        self.assertEqual(inner["commit"], _FIXTURE_INNER_COMMIT)
        self.assertEqual(inner["file_sha256"], _FIXTURE_INNER_SHA)


if __name__ == "__main__":
    unittest.main()
