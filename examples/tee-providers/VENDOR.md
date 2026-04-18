# Vendored Dependencies

## nearai-cloud-verifier

**Repository:** https://github.com/nearai/nearai-cloud-verifier

**Commit SHA:** `ec3040175af96f14d6be63aa44981daa6e7ad6aa`

**Vendored Date:** 2026-04-14

**Purpose:** TEE attestation verification for NEAR AI Cloud endpoints

**Components Used:**
- `py/chat_verifier.py` - Chat completion signature verification
- `py/domain_verifier.py` - Domain/TLS attestation verification
- `py/model_verifier.py` - Model attestation and TDX quote validation
- `py/encrypted_chat_verifier.py` - Encrypted chat verification (not used in current implementation)
- `py/tls_verifier.py` - TLS certificate verification (imported by domain_verifier)

**License:** See vendor/nearai-cloud-verifier/LICENSE

**Modifications:** None - vendored as-is for integration purposes

**Rationale:** The nearai-cloud-verifier provides battle-tested TEE attestation logic including:
- Intel TDX quote validation via dcap-qvl
- Gateway TLS certificate binding
- NVIDIA GPU attestation via NRAS
- ECDSA signature verification for signed responses

Rather than reimplementing this complex cryptographic verification, we compose these verifiers into a Hermes Agent provider wrapper.
