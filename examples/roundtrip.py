#!/usr/bin/env python3
"""End-to-end roundtrip demonstration of post-quantum hybrid JWS and JWE."""

import json
from pqblocks_jose import Policy, generate_keypair, encode_jws, decode_jws, encrypt_jwe, decrypt_jwe


def main():
    policy = Policy(
        version=1,
        kem="X25519+MLKEM768",
        sig="MLDSA65+Ed25519",
        kdf="HKDF-SHA256",
        max_token_bytes=8192,
    )

    # 1. Sign and verify JWS
    sig_keys = generate_keypair("ML-DSA-65-Ed25519")
    payload = {"sub": "service-worker-42", "scope": "read:records", "iat": 1710000000}
    jws = encode_jws(payload, policy, private_key=sig_keys.private_key)
    verified = decode_jws(jws.compact_serialization, policy, public_key=sig_keys.public_key)
    assert verified.signature_verified is True
    claims = json.loads(verified.payload) if isinstance(verified.payload, str) else verified.payload
    assert claims["sub"] == "service-worker-42"
    print("JWS Roundtrip: Verified successfully.")

    # 2. Encrypt and decrypt JWE
    enc_keys = generate_keypair("X25519+MLKEM768")
    secret_data = b"confidential-telemetry-payload"
    jwe = encrypt_jwe(secret_data, policy, public_key=enc_keys.public_key)
    decrypted = decrypt_jwe(jwe.compact_serialization, policy, private_key=enc_keys.private_key)
    assert decrypted.plaintext == secret_data
    print("JWE Roundtrip: Decrypted successfully.")


if __name__ == "__main__":
    main()
