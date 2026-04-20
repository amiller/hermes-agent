"""Local E2EE proxy — transparently encrypts chat content with attested model key."""
import json
import logging
import secrets
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings as _nacl
from nacl.public import Box, PrivateKey as _X25519Priv, PublicKey as _X25519Pub

logger = logging.getLogger(__name__)


def _generate_ecdsa_keypair():
    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return priv, pub_bytes[1:].hex()  # strip 0x04 prefix


def _generate_ed25519_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub_bytes.hex()


def _encrypt_ecdsa(data: bytes, pub_hex: str) -> bytes:
    pub_bytes = bytes.fromhex(pub_hex)
    if len(pub_bytes) == 65 and pub_bytes[0] == 0x04:
        pub_bytes = pub_bytes[1:]
    pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x04" + pub_bytes)
    eph_priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    shared = eph_priv.exchange(ec.ECDH(), pub_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"ecdsa_encryption", backend=default_backend(),
    ).derive(shared)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(aes_key).encrypt(nonce, data, None)
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return eph_pub + nonce + ct


def _decrypt_ecdsa(data: bytes, priv_key) -> bytes:
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), data[:65])
    shared = priv_key.exchange(ec.ECDH(), eph_pub)
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"ecdsa_encryption", backend=default_backend(),
    ).derive(shared)
    return AESGCM(aes_key).decrypt(data[65:77], data[77:], None)


def _encrypt_ed25519(data: bytes, pub_hex: str) -> bytes:
    # Ed25519 pubkey → X25519 via NaCl, then NaCl Box (X25519 + ChaCha20-Poly1305)
    pub_bytes = bytes.fromhex(pub_hex)
    x25519_pub = _X25519Pub(_nacl.crypto_sign_ed25519_pk_to_curve25519(pub_bytes))
    eph_priv = _X25519Priv.generate()
    box = Box(eph_priv, x25519_pub)
    encrypted = box.encrypt(data)  # includes 24-byte nonce prepended by NaCl
    return bytes(eph_priv.public_key) + encrypted


def _decrypt_ed25519(data: bytes, priv_key) -> bytes:
    seed = priv_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = priv_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x25519_priv = _X25519Priv(_nacl.crypto_sign_ed25519_sk_to_curve25519(seed + pub))
    eph_pub = _X25519Pub(data[:32])
    return Box(x25519_priv, eph_pub).decrypt(data[32:])


def _generate_keypair(algo: str):
    if algo == "ecdsa":
        return _generate_ecdsa_keypair()
    if algo == "ed25519":
        return _generate_ed25519_keypair()
    raise ValueError(f"Unsupported signing algo: {algo}")


def _encrypt_content(text: str, pub_hex: str, algo: str) -> str:
    if algo == "ecdsa":
        return _encrypt_ecdsa(text.encode(), pub_hex).hex()
    if algo == "ed25519":
        return _encrypt_ed25519(text.encode(), pub_hex).hex()
    raise ValueError(f"Unsupported signing algo: {algo}")


def _decrypt_content(hex_data: str, priv_key, algo: str) -> str:
    if algo == "ecdsa":
        return _decrypt_ecdsa(bytes.fromhex(hex_data), priv_key).decode()
    if algo == "ed25519":
        return _decrypt_ed25519(bytes.fromhex(hex_data), priv_key).decode()
    raise ValueError(f"Unsupported signing algo: {algo}")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.debug("e2ee_proxy: " + fmt, *args)

    def do_POST(self):
        if self.path.split("?")[0].endswith("/chat/completions"):
            self._handle_chat()
        else:
            self._proxy("POST")

    def do_GET(self):
        self._proxy("GET")

    def _handle_chat(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length))

        priv_key, client_pub_hex = _generate_keypair(self.server.signing_algo)

        for msg in payload.get("messages", []):
            if isinstance(msg.get("content"), str) and msg["content"]:
                msg["content"] = _encrypt_content(
                    msg["content"], self.server.signing_public_key, self.server.signing_algo
                )

        fwd_headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
        fwd_headers.update({
            "X-Signing-Algo": self.server.signing_algo,
            "X-Client-Pub-Key": client_pub_hex,
            "X-Model-Pub-Key": self.server.signing_public_key,
        })
        new_body = json.dumps(payload).encode()
        fwd_headers["Content-Length"] = str(len(new_body))

        is_stream = payload.get("stream", False)
        upstream_url = self.server.upstream_base_url.rstrip("/") + self.path
        # For streaming, use no timeout — let the caller's connection govern it.
        # For non-streaming, 120s is plenty.
        upstream_timeout = None if is_stream else 120
        resp = requests.post(upstream_url, headers=fwd_headers, data=new_body, stream=is_stream, timeout=upstream_timeout)

        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() in ("content-length", "transfer-encoding"):
                continue
            self.send_header(k, v)

        if is_stream:
            # BaseHTTPRequestHandler doesn't auto-wrap writes in chunked-transfer
            # framing; emitting the header without framing breaks the client.
            # Use connection-close to delimit the stream instead.
            self.send_header("Connection", "close")
            self.end_headers()
            pending = b""
            for chunk in resp.iter_content(chunk_size=4096):
                pending += chunk
                while b"\n" in pending:
                    raw, pending = pending.split(b"\n", 1)
                    line = raw.decode("utf-8", errors="replace")
                    if line.startswith("data: {"):
                        data = json.loads(line[6:])
                        for choice in data.get("choices", []):
                            delta = choice.get("delta", {})
                            for field in ("content", "reasoning_content", "reasoning"):
                                if delta.get(field):
                                    delta[field] = _decrypt_content(
                                        delta[field], priv_key, self.server.signing_algo
                                    )
                        line = "data: " + json.dumps(data)
                    self.wfile.write((line + "\n").encode())
                    self.wfile.flush()
            if pending:
                self.wfile.write(pending)
                self.wfile.flush()
        else:
            data = resp.json()
            for choice in data.get("choices", []):
                msg = choice.get("message", {})
                for field in ("content", "reasoning_content", "reasoning"):
                    if msg.get(field):
                        msg[field] = _decrypt_content(msg[field], priv_key, self.server.signing_algo)
            out = json.dumps(data).encode()
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            self.wfile.flush()

    def _proxy(self, method):
        fwd_headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else None
        upstream_url = self.server.upstream_base_url.rstrip("/") + self.path
        resp = requests.request(method, upstream_url, headers=fwd_headers, data=body, timeout=30)
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.content)
        self.wfile.flush()


class E2EEProxy:
    """Local HTTP proxy that encrypts outgoing chat messages and decrypts responses."""

    def __init__(self, signing_public_key: str, signing_algo: str, upstream_base_url: str):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
        server.signing_public_key = signing_public_key
        server.signing_algo = signing_algo
        server.upstream_base_url = upstream_base_url
        server.daemon_threads = True
        self._port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self._server = server
        logger.info("E2EE proxy started on port %d → %s", self._port, upstream_base_url)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    def shutdown(self):
        self._server.shutdown()
