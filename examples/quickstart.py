# 1. Import the library
from pqblocks_jose import Policy, generate_keypair, encode_jws, decode_jws, encrypt_jwe, decrypt_jwe

# 2. Create a versioned policy (CI/CD enforceable)
policy = Policy(
    version=1,
    kem="X25519+MLKEM768",           # Hybrid KEM for JWE
    sig="MLDSA65+Ed25519",           # Hybrid signature for JWS
    kdf="HKDF-SHA256",               # Mandatory KDF enforcement
    max_token_bytes=8192,            # library default; a hybrid ML-DSA-65 JWS is ~4.6 KB, so 3500 rejects it
                                     # (check your proxy's header limit: 8 KB is common)
    kdf_info="JOSE_PostQuantum_Traditional_Hybrid X25519MLKEM768",
    sig_alg_std="ML-DSA-65-Ed25519"  # Standards-track identifier
)

# 3. Generate deterministic hybrid keypairs (for reproducibility)
sign_keypair = generate_keypair("ML-DSA-65-Ed25519", seed=12345)
enc_keypair = generate_keypair("X25519+MLKEM768", seed=12345)

# 4. SIGN & VERIFY a JWS token
payload = {"sub": "alice@example.com", "iat": 1700000000, "aud": "api.internal"}
jws_result = encode_jws(payload, policy, private_key=sign_keypair.private_key)

# Verify with the matching public key (asymmetric API)
verification = decode_jws(
    token=jws_result.compact_serialization,
    policy=policy,
    public_key=sign_keypair.public_key  # REQUIRED: prevents seed=42 forgery
)

print(f"JWS signature verified: {verification.signature_verified}")
print(f"Token size: {len(jws_result.compact_serialization)} bytes")
print(f"Algorithm: {jws_result.algorithm}")

# 5. ENCRYPT & DECRYPT a JWE token
plaintext = b"session_key:random123nonce"
jwe_result = encrypt_jwe(plaintext, policy, public_key=enc_keypair.public_key)

# Decrypt with the recipient's PRIVATE key (a public key cannot decrypt)
decryption = decrypt_jwe(
    token=jwe_result.compact_serialization,
    policy=policy,
    private_key=enc_keypair.private_key
)

print(f"JWE plaintext match: {decryption.plaintext == plaintext}")
print(f"JWE encryption: {jwe_result.enc}")
print(f"Encapsulated key size: {len(jwe_result.encrypted_key)} bytes")

# 6. ERROR HANDLING - try to decode with wrong public key
try:
    decode_jws(
        token=jws_result.compact_serialization,
        policy=policy,
        public_key=b"wrong_key_" + sign_keypair.public_key[10:]  # Tampered key
    )
except Exception as e:
    print(f"Expected error with wrong key: {type(e).__name__}")

print("\n✅ All operations completed successfully!")
