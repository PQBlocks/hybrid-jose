# pqblocks-jose Performance Benchmarks

This document records reproducible benchmark measurements for `pqblocks-jose` cryptographic operations under real hardware conditions.

---

## Benchmark Environment

- **Processor**: Intel(R) Core(TM) i5-10300H CPU @ 2.50GHz (4 cores / 8 threads)
- **Operating System**: Linux 6.x x86_64
- **Python Version**: CPython 3.14.8
- **Crypto Backend**: `cryptography` with OpenSSL 3.x FIPS 203/204 support
- **Sample Count**: 500 timed iterations after 50 warmup rounds

---

## Execution Timings

All times are measured in milliseconds (ms) using high-precision monotonic clock (`time.perf_counter`).

| Operation | Primitive / Construction | Mean (ms) | StdDev (ms) | Min (ms) | Max (ms) | p99 (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **JWS Sign** | ML-DSA-65 + Ed25519 (Hedged) | 2.481 | 0.907 | 1.393 | 8.243 | 5.702 |
| **JWS Verify** | ML-DSA-65 + Ed25519 (Dual Check) | 0.506 | 0.105 | 0.399 | 1.057 | 0.957 |
| **JWE Encrypt** | X25519 + ML-KEM-768 + A256GCM | 0.240 | 0.051 | 0.198 | 0.507 | 0.465 |
| **JWE Decrypt** | X25519 + ML-KEM-768 + A256GCM | 0.332 | 0.044 | 0.289 | 0.745 | 0.518 |

---

## Token Size Analysis

Post-quantum signatures and ciphertexts introduce larger payloads compared to classical RSA/ECDSA tokens:

| Token Type | Algorithms | Wire Format | Raw Size (Bytes) | Base64URL Size (Bytes) |
| :--- | :--- | :--- | :--- | :--- |
| **JWS Token** | ML-DSA-65 (3,309 B) + Ed25519 (64 B) | Compact serialization | 3,473 | ~4,641 |
| **JWE Ciphertext** | ML-KEM-768 CT (1,088 B) + X25519 (32 B) + IV + Tag | Compact serialization | 1,220 | ~1,630 |

### HTTP Header Recommendations

Standard reverse proxies (e.g., NGINX, Envoy, Apache) often default to 4 KB or 8 KB buffer limits for HTTP request headers:
- Default `4 KB` limits may drop hybrid JWS headers (`~4.6 KB`).
- Configure `large_client_header_buffers 4 16k;` in NGINX or increase downstream proxy buffer limits to at least 8 KB or 16 KB.

---

## How to Reproduce

Run the measurement script directly:

```bash
python3 -c '
import time, statistics
from pqblocks_jose import Policy, generate_keypair, encode_jws, decode_jws, encrypt_jwe, decrypt_jwe

policy = Policy()
sig_keys = generate_keypair("ML-DSA-65-Ed25519", seed=12345)
enc_keys = generate_keypair("X25519+MLKEM768", seed=12345)
payload = {"sub": "bench", "iat": 1700000000}
plaintext = b"benchmarking 32 byte secret payload"

for _ in range(50):
    j = encode_jws(payload, policy, private_key=sig_keys.private_key)
    decode_jws(j.compact_serialization, policy, public_key=sig_keys.public_key)
    e = encrypt_jwe(plaintext, policy, public_key=enc_keys.public_key)
    decrypt_jwe(e.compact_serialization, policy, private_key=enc_keys.private_key)

jws_s, jws_v, jwe_e, jwe_d = [], [], [], []
for _ in range(500):
    t0 = time.perf_counter()
    j = encode_jws(payload, policy, private_key=sig_keys.private_key)
    t1 = time.perf_counter()
    decode_jws(j.compact_serialization, policy, public_key=sig_keys.public_key)
    t2 = time.perf_counter()
    e = encrypt_jwe(plaintext, policy, public_key=enc_keys.public_key)
    t3 = time.perf_counter()
    decrypt_jwe(e.compact_serialization, policy, private_key=enc_keys.private_key)
    t4 = time.perf_counter()
    jws_s.append((t1 - t0) * 1000)
    jws_v.append((t2 - t1) * 1000)
    jwe_e.append((t3 - t2) * 1000)
    jwe_d.append((t4 - t3) * 1000)

print(f"JWS Sign (ms): mean={statistics.mean(jws_s):.3f}, p99={statistics.quantiles(jws_s, n=100)[98]:.3f}")
print(f"JWS Verify (ms): mean={statistics.mean(jws_v):.3f}, p99={statistics.quantiles(jws_v, n=100)[98]:.3f}")
print(f"JWE Encrypt (ms): mean={statistics.mean(jwe_e):.3f}, p99={statistics.quantiles(jwe_e, n=100)[98]:.3f}")
print(f"JWE Decrypt (ms): mean={statistics.mean(jwe_d):.3f}, p99={statistics.quantiles(jwe_d, n=100)[98]:.3f}")
'
```
