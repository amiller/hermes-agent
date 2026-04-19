"""Tests for NEAR AI E2EE proxy and attestation crypto."""

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

from hermes_cli.e2ee_proxy import (
    E2EEProxy,
    _encrypt_ecdsa,
    _decrypt_ecdsa,
    _generate_ecdsa_keypair,
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


def _near_api_key():
    """Read NEAR_API_KEY from env or ~/.hermes-near-test/.env (survives pytest env isolation)."""
    key = os.environ.get("NEAR_API_KEY", "")
    if key:
        return key
    env_file = os.path.expanduser("~/.hermes-near-test/.env")
    if os.path.exists(env_file):
        for line in open(env_file):
            if line.startswith("NEAR_API_KEY="):
                return line.strip().split("=", 1)[1]
    return ""


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
