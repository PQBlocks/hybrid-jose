"""pqblocks-jose CLI - Command-line interface for hybrid JWT/JOSE operations.

Usage:
    pqblocks-jose --version
    pqblocks-jose --help
    pqblocks-jose encode jws --payload '{"sub":"test","iat":1700000000}'
    pqblocks-jose decode jws --token <TOKEN>
    pqblocks-jose encrypt jwe --plaintext <BASE64>
    pqblocks-jose decrypt jwe --token <TOKEN>
    pqblocks-jose generate keypair --algorithm "ML-DSA-65-Ed25519"
"""

import argparse
import base64
import json
import sys

from pqblocks_jose import (
    JWSResult,
    JWEResult,
    Policy,
    decode_jws,
    decrypt_jwe,
    encode_jws,
    encrypt_jwe,
    generate_keypair,
    __version__,
)


def encode_jws_cmd(args):
    """Encode a JWS token from a JSON payload."""
    policy = Policy()
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON payload: {e}", file=sys.stderr)
        return 1

    result = encode_jws(payload, policy, seed=args.seed, kid=args.kid)
    print(result.compact_serialization)
    return 0


def decode_jws_cmd(args):
    """Decode and verify a JWS token."""
    policy = Policy()
    try:
        keypair = generate_keypair("ML-DSA-65-Ed25519", seed=args.seed)
        result = decode_jws(args.token, policy, seed=args.seed, public_key=keypair.public_key)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    output = {
        "compact_serialization": result.compact_serialization,
        "protected_header": json.loads(result.protected_header) if isinstance(result.protected_header, str) else result.protected_header,
        "payload": json.loads(result.payload) if isinstance(result.payload, str) else result.payload,
        "algorithm": result.algorithm,
        "key_id": result.key_id,
        "signature_verified": result.signature_verified,
    }
    print(json.dumps(output, indent=2))
    return 0


def encrypt_jwe_cmd(args):
    """Encrypt data into a JWE token."""
    policy = Policy()
    try:
        if args.plaintext.startswith("b'") or args.plaintext.startswith('"'):
            plaintext = args.plaintext.encode('utf-8')
        else:
            plaintext = base64.b64decode(args.plaintext)
    except Exception as e:
        print(f"Error: Invalid base64 plaintext: {e}", file=sys.stderr)
        return 1

    result = encrypt_jwe(plaintext, policy, seed=args.seed)
    print(result.compact_serialization)
    return 0


def decrypt_jwe_cmd(args):
    """Decrypt a JWE token to recover plaintext."""
    policy = Policy()
    try:
        result = decrypt_jwe(args.token, policy, seed=args.seed)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    output = {
        "compact_serialization": result.compact_serialization,
        "protected_header": json.loads(result.protected_header) if isinstance(result.protected_header, str) else result.protected_header,
        "plaintext": base64.b64encode(result.plaintext).decode("ascii"),
        "algorithm": result.algorithm,
        "enc": result.enc,
        "key_id": result.key_id,
        "iv": base64.b64encode(result.iv).decode("ascii"),
        "encrypted_key": base64.b64encode(result.encrypted_key).decode("ascii"),
        "ciphertext": base64.b64encode(result.ciphertext).decode("ascii"),
        "tag": base64.b64encode(result.tag).decode("ascii"),
    }
    print(json.dumps(output, indent=2))
    return 0


def generate_keypair_cmd(args):
    """Generate a hybrid key pair."""
    algorithm = args.algorithm
    if algorithm not in ("ML-DSA-65-Ed25519", "X25519+MLKEM768"):
        print(f"Error: Unsupported algorithm {algorithm!r}", file=sys.stderr)
        print("Supported: ML-DSA-65-Ed25519, X25519+MLKEM768", file=sys.stderr)
        return 1

    keypair = generate_keypair(algorithm, seed=args.seed)

    output = {
        "algorithm": keypair.algorithm,
        "private_key": base64.b64encode(keypair.private_key).decode("ascii"),
        "public_key": base64.b64encode(keypair.public_key).decode("ascii"),
    }
    print(json.dumps(output, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pqblocks-jose",
        description="CLI for post-quantum hybrid JWT/JOSE operations",
    )
    parser.add_argument("--version", action="version", version=f"pqblocks-jose {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # encode command
    encode_parser = subparsers.add_parser("encode", help="Encode a token")
    encode_parser.add_argument("token_type", choices=["jws"], help="Token type to encode")
    encode_parser.add_argument("--payload", required=True, help="JSON payload string")
    encode_parser.add_argument("--seed", type=int, default=42, help="Deterministic seed")
    encode_parser.add_argument("--kid", help="Key identifier")
    encode_parser.set_defaults(func=encode_jws_cmd)

    # decode command
    decode_parser = subparsers.add_parser("decode", help="Decode a token")
    decode_parser.add_argument("token_type", choices=["jws"], help="Token type to decode")
    decode_parser.add_argument("--token", required=True, help="Token to decode")
    decode_parser.add_argument("--seed", type=int, default=42, help="Deterministic seed")
    decode_parser.set_defaults(func=decode_jws_cmd)

    # encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt data")
    encrypt_parser.add_argument("token_type", choices=["jwe"], help="Token type to encrypt")
    encrypt_parser.add_argument("--plaintext", required=True, help="Base64-encoded plaintext")
    encrypt_parser.add_argument("--seed", type=int, default=42, help="Deterministic seed")
    encrypt_parser.set_defaults(func=encrypt_jwe_cmd)

    # decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a token")
    decrypt_parser.add_argument("token_type", choices=["jwe"], help="Token type to decrypt")
    decrypt_parser.add_argument("--token", required=True, help="Token to decrypt")
    decrypt_parser.add_argument("--seed", type=int, default=42, help="Deterministic seed")
    decrypt_parser.set_defaults(func=decrypt_jwe_cmd)

    # generate command
    gen_parser = subparsers.add_parser("generate", help="Generate cryptographic material")
    gen_parser.add_argument("object_type", choices=["keypair"], help="Object to generate")
    gen_parser.add_argument("--algorithm", required=True, help="Algorithm identifier")
    gen_parser.add_argument("--seed", type=int, default=42, help="Deterministic seed")
    gen_parser.set_defaults(func=generate_keypair_cmd)

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
