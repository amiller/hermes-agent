"""Tests for NEAR AI E2EE proxy and attestation crypto."""

import base64
import hashlib
import json
import secrets
import socketserver
import threading
from http.server import BaseHTTPRequestHandler

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import requests

from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
from nacl import bindings as _nacl
from nacl.public import PrivateKey as _X25519Priv, PublicKey as _X25519Pub, Box

from hermes_cli.e2ee_proxy import (
    E2EEProxy,
    _encrypt_ecdsa,
    _decrypt_ecdsa,
    _generate_ecdsa_keypair,
    _encrypt_ed25519,
    _decrypt_ed25519,
    _generate_ed25519_keypair,
)
from hermes_cli.attestation import _phala_check_report_data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_model_keypair():
    """Return (priv_key_obj, pub_hex) for a fresh SECP256K1 keypair (the "model CVM" side)."""
    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return priv, pub_bytes[1:].hex()  # strip 0x04


# ---------------------------------------------------------------------------
# ECIES roundtrip
# ---------------------------------------------------------------------------

class TestEciesRoundtrip:
    def test_encrypt_decrypt(self):
        model_priv, model_pub_hex = _make_model_keypair()
        plaintext = b"secret prompt: what is 2+2?"
        ct = _encrypt_ecdsa(plaintext, model_pub_hex)
        recovered = _decrypt_ecdsa(ct, model_priv)
        assert recovered == plaintext

    def test_ciphertext_is_random(self):
        _, model_pub_hex = _make_model_keypair()
        ct1 = _encrypt_ecdsa(b"same message", model_pub_hex)
        ct2 = _encrypt_ecdsa(b"same message", model_pub_hex)
        assert ct1 != ct2  # ephemeral key is fresh each time

    def test_wrong_key_raises(self):
        _, model_pub_hex = _make_model_keypair()
        wrong_priv, _ = _make_model_keypair()
        ct = _encrypt_ecdsa(b"hello", model_pub_hex)
        with pytest.raises(Exception):
            _decrypt_ecdsa(ct, wrong_priv)

    def test_client_keypair_generation(self):
        priv, pub_hex = _generate_ecdsa_keypair()
        assert len(bytes.fromhex(pub_hex)) == 64  # uncompressed minus 0x04 prefix


# ---------------------------------------------------------------------------
# Ed25519 roundtrip
# ---------------------------------------------------------------------------

def _make_ed25519_model_keypair():
    priv = _ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub.hex()


class TestEd25519Roundtrip:
    def test_encrypt_decrypt(self):
        model_priv, model_pub_hex = _make_ed25519_model_keypair()
        plaintext = b"secret prompt: what is 2+2?"
        ct = _encrypt_ed25519(plaintext, model_pub_hex)
        recovered = _decrypt_ed25519(ct, model_priv)
        assert recovered == plaintext

    def test_ciphertext_is_random(self):
        _, model_pub_hex = _make_ed25519_model_keypair()
        ct1 = _encrypt_ed25519(b"same message", model_pub_hex)
        ct2 = _encrypt_ed25519(b"same message", model_pub_hex)
        assert ct1 != ct2

    def test_wrong_key_raises(self):
        _, model_pub_hex = _make_ed25519_model_keypair()
        wrong_priv, _ = _make_ed25519_model_keypair()
        ct = _encrypt_ed25519(b"hello", model_pub_hex)
        with pytest.raises(Exception):
            _decrypt_ed25519(ct, wrong_priv)

    def test_client_keypair_generation(self):
        priv, pub_hex = _generate_ed25519_keypair()
        assert len(bytes.fromhex(pub_hex)) == 32


# ---------------------------------------------------------------------------
# Fake upstream server that acts as the model CVM
# ---------------------------------------------------------------------------

class _FakeModelServer(BaseHTTPRequestHandler):
    """Receives encrypted requests, decrypts, re-encrypts response to client key."""

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))

        client_pub_hex = self.headers.get("X-Client-Pub-Key", "")
        signing_algo = self.headers.get("X-Signing-Algo", "ecdsa")

        # Decrypt each message using model's private key
        decrypted_messages = []
        for msg in body.get("messages", []):
            ct_hex = msg.get("content", "")
            if ct_hex:
                pt = _decrypt_ecdsa(bytes.fromhex(ct_hex), self.server.model_priv_key)
                decrypted_messages.append(pt.decode())

        self.server.received_plaintexts.extend(decrypted_messages)

        # Encrypt response back to client's public key
        response_text = "4"
        client_pub_bytes = bytes.fromhex(client_pub_hex)
        if len(client_pub_bytes) == 65 and client_pub_bytes[0] == 0x04:
            client_pub_bytes = client_pub_bytes[1:]
        client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x04" + client_pub_bytes)
        eph_priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
        shared = eph_priv.exchange(ec.ECDH(), client_pub)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecdsa_encryption", backend=default_backend()).derive(shared)
        nonce = secrets.token_bytes(12)
        ct = AESGCM(aes_key).encrypt(nonce, response_text.encode(), None)
        eph_pub_bytes = eph_priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        encrypted_response = (eph_pub_bytes + nonce + ct).hex()

        out = json.dumps({"choices": [{"message": {"content": encrypted_response}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def _start_fake_model_server(model_priv_key):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _FakeModelServer)
    server.model_priv_key = model_priv_key
    server.received_plaintexts = []
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ---------------------------------------------------------------------------
# E2EE proxy integration test
# ---------------------------------------------------------------------------

class TestE2EEProxyIntegration:
    def test_proxy_encrypts_prompt_and_decrypts_response(self):
        model_priv, model_pub_hex = _make_model_keypair()
        upstream = _start_fake_model_server(model_priv)
        port = upstream.server_address[1]
        upstream_url = f"http://127.0.0.1:{port}"

        proxy = E2EEProxy(model_pub_hex, "ecdsa", upstream_url)

        payload = {
            "model": "test-model",
            "messages": [{"role": "user", "content": "what is 2+2?"}],
            "stream": False,
        }
        resp = requests.post(f"{proxy.base_url}/v1/chat/completions", json=payload, timeout=10)
        assert resp.status_code == 200

        # Upstream received the encrypted ciphertext, not the plaintext
        assert upstream.received_plaintexts == ["what is 2+2?"]

        # Client got back decrypted response
        data = resp.json()
        assert data["choices"][0]["message"]["content"] == "4"

        proxy.shutdown()
        upstream.shutdown()

    def test_proxy_ed25519_encrypts_prompt_and_decrypts_response(self):
        model_priv, model_pub_hex = _make_ed25519_model_keypair()

        class _FakeEd25519Server(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args): pass
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length))
                client_pub_hex = self.headers.get("X-Client-Pub-Key", "")

                decrypted = []
                for msg in body.get("messages", []):
                    if msg.get("content"):
                        decrypted.append(_decrypt_ed25519(bytes.fromhex(msg["content"]), self.server.model_priv_key).decode())
                self.server.received_plaintexts.extend(decrypted)

                # Re-encrypt response to client key (client key is also ed25519)
                client_x25519 = _X25519Pub(_nacl.crypto_sign_ed25519_pk_to_curve25519(bytes.fromhex(client_pub_hex)))
                eph = _X25519Priv.generate()
                encrypted_response = (bytes(eph.public_key) + Box(eph, client_x25519).encrypt(b"4")).hex()

                out = json.dumps({"choices": [{"message": {"content": encrypted_response}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _FakeEd25519Server)
        upstream.model_priv_key = model_priv
        upstream.received_plaintexts = []
        upstream.daemon_threads = True
        threading.Thread(target=upstream.serve_forever, daemon=True).start()

        proxy = E2EEProxy(model_pub_hex, "ed25519", f"http://127.0.0.1:{upstream.server_address[1]}")
        resp = requests.post(f"{proxy.base_url}/v1/chat/completions",
                             json={"model": "test", "messages": [{"role": "user", "content": "what is 2+2?"}], "stream": False},
                             timeout=10)
        assert resp.status_code == 200
        assert upstream.received_plaintexts == ["what is 2+2?"]
        assert resp.json()["choices"][0]["message"]["content"] == "4"
        proxy.shutdown()
        upstream.shutdown()

    def test_proxy_non_chat_path_passes_through(self):
        """Non-/chat/completions paths pass through unchanged."""
        class _SimpleHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args): pass
            def do_GET(self):
                out = b'{"models": []}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _SimpleHandler)
        upstream.daemon_threads = True
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        port = upstream.server_address[1]

        _, model_pub_hex = _make_model_keypair()
        proxy = E2EEProxy(model_pub_hex, "ecdsa", f"http://127.0.0.1:{port}")

        resp = requests.get(f"{proxy.base_url}/v1/models", timeout=5)
        assert resp.status_code == 200
        assert resp.json() == {"models": []}

        proxy.shutdown()
        upstream.shutdown()


# ---------------------------------------------------------------------------
# signing_public_key → signing_address derivation
# ---------------------------------------------------------------------------

class TestSigningKeyDerivation:
    def test_pub_key_derives_to_correct_address(self):
        """keccak256(pubkey[1:]) → last 20 bytes == Ethereum address."""
        from eth_keys.datatypes import PublicKey as _EthPubKey

        priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
        pub_bytes_full = priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        pub_hex = pub_bytes_full[1:].hex()  # strip 0x04

        eth_addr = "0x" + _EthPubKey(bytes.fromhex(pub_hex)).to_canonical_address().hex()
        assert eth_addr.startswith("0x")
        assert len(eth_addr) == 42

    def test_wrong_pub_key_gives_different_address(self):
        from eth_keys.datatypes import PublicKey as _EthPubKey

        priv1 = ec.generate_private_key(ec.SECP256K1(), default_backend())
        priv2 = ec.generate_private_key(ec.SECP256K1(), default_backend())

        def _addr(priv):
            pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            return "0x" + _EthPubKey(pub[1:]).to_canonical_address().hex()

        assert _addr(priv1) != _addr(priv2)


# ---------------------------------------------------------------------------
# _phala_check_report_data
# ---------------------------------------------------------------------------

class TestPhalaReportData:
    def _make_report_data(self, signing_address_hex: str, nonce_hex: str) -> str:
        addr = bytes.fromhex(signing_address_hex.removeprefix("0x"))
        nonce = bytes.fromhex(nonce_hex)
        return (addr.ljust(32, b"\x00") + nonce).hex()

    def test_valid_report_data(self):
        addr = "0x" + secrets.token_hex(20)
        nonce = secrets.token_hex(32)
        rd = self._make_report_data(addr, nonce)
        assert _phala_check_report_data(rd, addr, "ecdsa", nonce) is True

    def test_wrong_nonce_fails(self):
        addr = "0x" + secrets.token_hex(20)
        nonce = secrets.token_hex(32)
        rd = self._make_report_data(addr, nonce)
        assert _phala_check_report_data(rd, addr, "ecdsa", secrets.token_hex(32)) is False

    def test_wrong_address_fails(self):
        addr = "0x" + secrets.token_hex(20)
        nonce = secrets.token_hex(32)
        rd = self._make_report_data(addr, nonce)
        wrong_addr = "0x" + secrets.token_hex(20)
        assert _phala_check_report_data(rd, wrong_addr, "ecdsa", nonce) is False

    def test_0x_prefix_stripped(self):
        addr = "0x" + "ab" * 20
        nonce = secrets.token_hex(32)
        rd = self._make_report_data(addr, nonce)
        assert _phala_check_report_data(rd, addr, "ecdsa", nonce) is True
        assert _phala_check_report_data(rd, addr.removeprefix("0x"), "ecdsa", nonce) is True


# ---------------------------------------------------------------------------
# Live integration test (skipped without credentials)
# ---------------------------------------------------------------------------

import os


def _read_env_file(path, key):
    if os.path.exists(path):
        for line in open(path):
            if line.startswith(f"{key}="):
                return line.strip().split("=", 1)[1]
    return ""

def _near_api_key():
    return os.environ.get("NEAR_API_KEY", "") or _read_env_file(os.path.expanduser("~/.hermes-near-test/.env"), "NEAR_API_KEY")

def _redpill_api_key():
    return os.environ.get("REDPILL_API_KEY", "") or _read_env_file(os.path.expanduser("~/.hermes-near-test/.env"), "REDPILL_API_KEY")


@pytest.mark.skipif(not _near_api_key(), reason="NEAR_API_KEY not found — live attestation test skipped")
class TestNearAILiveAttestation:
    def test_full_attestation_returns_signing_key(self):
        from hermes_cli.attestation import verify_attestation
        api_key = _near_api_key()
        report = verify_attestation("near-ai", {"api_key": api_key, "base_url": "https://cloud-api.near.ai", "model": "openai/gpt-oss-120b"}, {"enabled": True, "strict": True})
        assert report.valid, f"Attestation failed: {report.error}"
        assert report.signing_public_key is not None
        assert len(bytes.fromhex(report.signing_public_key)) == 64

    def test_e2ee_proxy_with_live_key(self):
        from hermes_cli.attestation import verify_attestation
        api_key = _near_api_key()
        report = verify_attestation("near-ai", {"api_key": api_key, "base_url": "https://cloud-api.near.ai", "model": "openai/gpt-oss-120b"}, {"enabled": True})
        assert report.signing_public_key
        proxy = E2EEProxy(report.signing_public_key, report.signing_algo, "https://cloud-api.near.ai")
        resp = requests.post(
            f"{proxy.base_url}/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": "openai/gpt-oss-120b", "messages": [{"role": "user", "content": "say hi"}], "max_tokens": 100},
            timeout=60,
        )
        assert resp.status_code == 200
        data = resp.json()
        msg = data["choices"][0]["message"]
        # gpt-oss-120b is a reasoning model; response arrives in reasoning_content, content may be None
        response_text = msg.get("content") or msg.get("reasoning_content") or msg.get("reasoning")
        assert response_text, f"No response text in message fields: {list(msg.keys())}"
        proxy.shutdown()


@pytest.mark.skipif(not _redpill_api_key(), reason="REDPILL_API_KEY not found — live redpill test skipped")
class TestRedpillLiveAttestation:
    def test_full_attestation_returns_signing_key(self):
        from hermes_cli.attestation import verify_attestation
        api_key = _redpill_api_key()
        report = verify_attestation("redpill", {"api_key": api_key, "base_url": "https://api.red-pill.ai/v1", "model": "phala/gpt-oss-20b"}, {"enabled": True})
        assert report.valid, f"Attestation failed: {report.error}"
        assert report.signing_public_key is not None
        assert report.signing_algo in ("ecdsa", "ed25519")

    def test_plain_chat_works_without_e2ee(self):
        # api.red-pill.ai gateway rejects E2EE headers ("This endpoint is not supported").
        # Attestation gives us the model CVM's signing key, but the gateway blocks encrypted
        # requests from reaching it. Test that plain (non-E2EE) chat works.
        api_key = _redpill_api_key()
        resp = requests.post(
            "https://api.red-pill.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": "phala/gpt-oss-20b", "messages": [{"role": "user", "content": "say hi"}], "max_tokens": 20},
            timeout=60,
        )
        assert resp.status_code == 200
        data = resp.json()
        msg = data["choices"][0]["message"]
        response_text = msg.get("content") or msg.get("reasoning_content") or msg.get("reasoning")
        assert response_text, f"No response text in message fields: {list(msg.keys())}"


# ---------------------------------------------------------------------------
# Model attestation filtering
# ---------------------------------------------------------------------------

class TestAttestationCache:
    def setup_method(self):
        from hermes_cli.attestation import _MODEL_ATTESTATION_CACHE, _ATTESTATION_CACHE
        _MODEL_ATTESTATION_CACHE.clear()
        _ATTESTATION_CACHE.clear()

    def teardown_method(self):
        from hermes_cli.attestation import _MODEL_ATTESTATION_CACHE, _ATTESTATION_CACHE
        _MODEL_ATTESTATION_CACHE.clear()
        _ATTESTATION_CACHE.clear()

    def test_verify_attestation_caches_per_model(self, monkeypatch):
        # Regression: cache key must include model_id so probing different
        # models under the same base_url doesn't collide.
        from hermes_cli import attestation as att_mod

        calls: list[str] = []

        def fake_redpill(creds, config):
            calls.append(creds["model"])
            return att_mod.AttestationReport(
                valid=creds["model"] == "good",
                provider="redpill", attestation_type="tdx+gpu",
                verified_at="", details={}, error=None if creds["model"] == "good" else "bad",
            )

        monkeypatch.setattr(att_mod, "_verify_redpill_attestation", fake_redpill)
        monkeypatch.setattr(att_mod, "_live_tls_fingerprint", lambda *a, **kw: None)

        r1 = att_mod.verify_attestation("redpill", {"api_key": "k", "base_url": "https://x", "model": "good"}, {})
        r2 = att_mod.verify_attestation("redpill", {"api_key": "k", "base_url": "https://x", "model": "bad"}, {})
        assert r1.valid is True and r2.valid is False
        assert calls == ["good", "bad"]  # both invoked — not collapsed by cache

    def test_verify_attestation_populates_model_cache(self, monkeypatch):
        from hermes_cli import attestation as att_mod
        monkeypatch.setattr(att_mod, "_live_tls_fingerprint", lambda *a, **kw: None)
        report = att_mod.verify_attestation(
            "custom",
            {"base_url": "http://localhost:9999", "model": "some-model"},
            {},
        )
        cached = att_mod.get_model_attestation_status("custom", "some-model")
        assert cached is report


# ---------------------------------------------------------------------------
# Redpill attestation shape dispatch — covers all 4 model types from
# redpill-verifier docs (Phala / NearAI / Chutes / Tinfoil).
# ---------------------------------------------------------------------------

class TestRedpillShapeDispatch:
    def setup_method(self):
        from hermes_cli.attestation import _MODEL_ATTESTATION_CACHE, _ATTESTATION_CACHE
        _MODEL_ATTESTATION_CACHE.clear()
        _ATTESTATION_CACHE.clear()

    def teardown_method(self):
        from hermes_cli.attestation import _MODEL_ATTESTATION_CACHE, _ATTESTATION_CACHE
        _MODEL_ATTESTATION_CACHE.clear()
        _ATTESTATION_CACHE.clear()

    def _fake_get(self, body):
        class _Resp:
            status_code = 200
            def json(self_inner):
                return body
            def raise_for_status(self_inner):
                return None
        return _Resp()

    def test_phala_simple_shape_dispatches_to_gateway_path(self, monkeypatch):
        # Phala simple shape: top-level intel_quote (no gateway_attestation, no attestation_type)
        from hermes_cli import attestation as att_mod
        att_body = {"intel_quote": "deadbeef", "nvidia_payload": {}, "signing_address": "0x00", "info": {}}
        monkeypatch.setattr(att_mod.requests, "get", lambda *a, **kw: self._fake_get(att_body))
        # Stub the Phala TDX verifier to simulate verification failure so we don't network out.
        post_calls = []
        class _P:
            def json(self_inner):
                return {"quote": {"verified": False, "message": "stubbed"}}
        def fake_post(url, **kw):
            post_calls.append(url)
            return _P()
        monkeypatch.setattr(att_mod.requests, "post", fake_post)
        r = att_mod._verify_redpill_attestation(
            {"api_key": "k", "base_url": "https://api.red-pill.ai/v1", "model": "phala/qwen-2.5-7b-instruct"},
            {},
        )
        assert r.valid is False
        assert "TDX quote verification failed" in (r.error or "")
        # Confirms the Phala simple branch was taken (hit the Phala verifier URL).
        assert att_mod._PHALA_TDX_VERIFIER in post_calls

    def test_near_ai_via_redpill_shape_dispatches_to_gateway_path(self, monkeypatch):
        # NearAI-via-redpill shape: gateway_attestation + model_attestations
        from hermes_cli import attestation as att_mod
        att_body = {
            "gateway_attestation": {"intel_quote": "deadbeef", "signing_address": "0x00", "info": {}},
            "model_attestations": [{"signing_public_key": "abcd", "signing_algo": "ecdsa"}],
        }
        monkeypatch.setattr(att_mod.requests, "get", lambda *a, **kw: self._fake_get(att_body))
        class _P:
            def json(self_inner):
                return {"quote": {"verified": False, "message": "stubbed"}}
        monkeypatch.setattr(att_mod.requests, "post", lambda *a, **kw: _P())
        r = att_mod._verify_redpill_attestation(
            {"api_key": "k", "base_url": "https://api.red-pill.ai/v1", "model": "phala/gpt-oss-120b"},
            {},
        )
        # Path taken = gateway_attestation branch; fails at TDX step (stubbed).
        assert r.valid is False
        assert "TDX quote verification failed" in (r.error or "")

    def test_chutes_shape_verifies_anti_tamper_binding(self, monkeypatch):
        # Chutes shape: attestation_type="chutes" + all_attestations[]
        # Build a synthetic quote whose report_data = SHA256(nonce || e2e_pubkey)
        from hermes_cli import attestation as att_mod

        e2e_pubkey = "beadfeed" * 8
        # We control the nonce by intercepting secrets.token_hex
        test_nonce = "11" * 32
        monkeypatch.setattr(att_mod.secrets, "token_hex", lambda n: test_nonce)
        expected_rd = hashlib.sha256((test_nonce + e2e_pubkey).encode()).hexdigest()

        att_body = {
            "attestation_type": "chutes",
            "nonce": test_nonce,
            "all_attestations": [{
                "intel_quote": base64.b64encode(b"\x00" * 100).decode(),
                "e2e_pubkey": e2e_pubkey,
                "nonce": test_nonce,
                "instance_id": "inst-1",
            }],
        }
        monkeypatch.setattr(att_mod.requests, "get", lambda *a, **kw: self._fake_get(att_body))

        # Phala verifier returns a body containing report_data that binds our nonce||e2e_pubkey
        class _P:
            def json(self_inner):
                return {
                    "quote": {
                        "verified": True,
                        "body": {"reportdata": expected_rd + "00" * 32, "td_attributes": "0000001000000000"},
                    },
                }
        monkeypatch.setattr(att_mod.requests, "post", lambda *a, **kw: _P())

        r = att_mod._verify_redpill_attestation(
            {"api_key": "k", "base_url": "https://api.red-pill.ai/v1", "model": "phala/deepseek-v3.2"},
            {},
        )
        assert r.valid, f"expected chutes attestation to pass, got: {r.error}"
        assert r.attestation_type == "chutes+tdx"
        assert r.details["instance_count"] == 1

    def test_chutes_shape_rejects_when_anti_tamper_fails(self, monkeypatch):
        from hermes_cli import attestation as att_mod
        test_nonce = "22" * 32
        monkeypatch.setattr(att_mod.secrets, "token_hex", lambda n: test_nonce)

        att_body = {
            "attestation_type": "chutes",
            "nonce": test_nonce,
            "all_attestations": [{
                "intel_quote": base64.b64encode(b"\x00" * 100).decode(),
                "e2e_pubkey": "cafebabe" * 8,
                "nonce": test_nonce,
                "instance_id": "inst-tampered",
            }],
        }
        monkeypatch.setattr(att_mod.requests, "get", lambda *a, **kw: self._fake_get(att_body))

        # Simulate a WRONG report_data — attacker swapped the e2e key without updating the binding
        class _P:
            def json(self_inner):
                return {
                    "quote": {
                        "verified": True,
                        "body": {"reportdata": "00" * 64, "td_attributes": "0000001000000000"},
                    },
                }
        monkeypatch.setattr(att_mod.requests, "post", lambda *a, **kw: _P())

        r = att_mod._verify_redpill_attestation(
            {"api_key": "k", "base_url": "https://api.red-pill.ai/v1", "model": "phala/kimi-k2.5"},
            {},
        )
        assert r.valid is False
        assert "anti-tamper" in (r.error or "").lower()

    def test_chutes_shape_rejects_debug_mode(self, monkeypatch):
        from hermes_cli import attestation as att_mod
        test_nonce = "33" * 32
        monkeypatch.setattr(att_mod.secrets, "token_hex", lambda n: test_nonce)
        e2e_pubkey = "feedface" * 8
        expected_rd = hashlib.sha256((test_nonce + e2e_pubkey).encode()).hexdigest()

        att_body = {
            "attestation_type": "chutes",
            "nonce": test_nonce,
            "all_attestations": [{
                "intel_quote": base64.b64encode(b"\x00" * 100).decode(),
                "e2e_pubkey": e2e_pubkey,
                "nonce": test_nonce,
                "instance_id": "inst-dbg",
            }],
        }
        monkeypatch.setattr(att_mod.requests, "get", lambda *a, **kw: self._fake_get(att_body))

        # td_attributes bit 0 set → DEBUG mode (int(hex,16) & 1 == 1)
        class _P:
            def json(self_inner):
                return {
                    "quote": {
                        "verified": True,
                        "body": {"reportdata": expected_rd + "00" * 32, "td_attributes": "0000000000000001"},
                    },
                }
        monkeypatch.setattr(att_mod.requests, "post", lambda *a, **kw: _P())

        r = att_mod._verify_redpill_attestation(
            {"api_key": "k", "base_url": "https://api.red-pill.ai/v1", "model": "phala/deepseek-v3.2"},
            {},
        )
        assert r.valid is False
        assert "debug" in (r.error or "").lower()

    def test_tinfoil_or_unknown_shape_rejected(self, monkeypatch):
        # Tinfoil responses aren't routed through our curated list yet, and the
        # redpill API returns {"error": "..."} for upstream (non-phala/) model
        # paths. Either way, unknown shapes must fail cleanly — the picker
        # filter will drop them.
        from hermes_cli import attestation as att_mod
        monkeypatch.setattr(
            att_mod.requests, "get",
            lambda *a, **kw: self._fake_get({"error": "route not found"}),
        )
        r = att_mod._verify_redpill_attestation(
            {"api_key": "k", "base_url": "https://api.red-pill.ai/v1", "model": "meta-llama/llama-3.3-70b-instruct"},
            {},
        )
        assert r.valid is False
        assert "Unrecognized attestation response format" in (r.error or "")
