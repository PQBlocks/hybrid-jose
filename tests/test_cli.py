"""Tests for S9: CLI + Integration Examples.

This test module covers:
- CLI command-line interface for pqblocks-jose
- Basic JWS/JWE operations via CLI
- Help and version output
- Error handling via CLI
"""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from pqblocks_jose import Policy, encode_jws, encrypt_jwe

# Path to the CLI executable
CLI_PATH = Path(sys.executable).parent / "pqblocks-jose"
if not CLI_PATH.exists():
    CLI_PATH = Path(__file__).parent.parent / "bin" / "pqblocks-jose"
if not CLI_PATH.exists():
    import shutil
    which = shutil.which("pqblocks-jose")
    if which:
        CLI_PATH = Path(which)


def test_cli_exists():
    """Test that the CLI executable exists."""
    assert CLI_PATH.exists(), f"CLI not found at {CLI_PATH}"
    assert CLI_PATH.is_file(), f"CLI path is not a file: {CLI_PATH}"


def test_cli_help():
    """Test CLI help output."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "pqblocks-jose" in result.stdout.lower()
    assert "usage:" in result.stdout.lower()


def test_cli_version():
    """Test CLI version output."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    # argparse prints the version to stdout; allow stdout or stderr
    assert "pqblocks-jose" in (result.stdout + result.stderr).lower()


def test_cli_encode_jws():
    """Test CLI JWS encoding."""
    payload = '{"sub":"test","iat":1700000000}'
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "encode",
            "jws",
            "--payload",
            payload,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"CLI failed: {result.stderr}"
    # Should output a compact JWS (3 parts separated by dots)
    token = result.stdout.strip()
    assert token.count(".") == 2
    # Verify it's a valid token by decoding (default seed=42 matches encode default)
    verify_result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "decode",
            "jws",
            "--token",
            token,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert verify_result.returncode == 0, f"decode failed: {verify_result.stderr}"
    decoded = json.loads(verify_result.stdout)
    assert decoded["payload"]["sub"] == "test"
    assert decoded["payload"]["iat"] == 1700000000


def test_cli_decode_jws():
    """Test CLI JWS decoding."""
    policy = Policy()
    payload = {"sub": "cli-test", "role": "implementer"}
    encoded = encode_jws(payload, policy, seed=12345)
    token = encoded.compact_serialization

    # Now decode via CLI
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "decode",
            "jws",
            "--token",
            token,
            "--seed",
            "12345",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    decoded = json.loads(result.stdout)
    assert decoded["payload"]["sub"] == "cli-test"
    assert decoded["payload"]["role"] == "implementer"
    assert decoded["signature_verified"] is True


def test_cli_encrypt_jwe():
    """Test CLI JWE encryption."""
    plaintext = b"Hello, post-quantum CLI!"
    # Pass as base64 for CLI simplicity
    import base64

    plaintext_b64 = base64.b64encode(plaintext).decode("ascii")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "encrypt",
            "jwe",
            "--plaintext",
            plaintext_b64,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    # Should output a compact JWE (5 parts separated by dots)
    token = result.stdout.strip()
    assert token.count(".") == 4
    # Verify it's a valid token by decrypting
    verify_result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "decrypt",
            "jwe",
            "--token",
            token,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert verify_result.returncode == 0
    decrypted = json.loads(verify_result.stdout)
    assert base64.b64decode(decrypted["plaintext"]) == plaintext


def test_cli_decrypt_jwe():
    """Test CLI JWE decryption."""
    # First create a token via the library
    from pqblocks_jose import encrypt_jwe, Policy

    plaintext = b"CLI decrypt test"
    policy = Policy()
    encrypted = encrypt_jwe(plaintext, policy, seed=54321)
    token = encrypted.compact_serialization

    # Now decrypt via CLI
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "decrypt",
            "jwe",
            "--token",
            token,
            "--seed",
            "54321",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    decrypted = json.loads(result.stdout)
    assert base64.b64decode(decrypted["plaintext"]) == plaintext


def test_cli_generate_keypair():
    """Test CLI keypair generation."""
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "generate",
            "keypair",
            "--algorithm",
            "ML-DSA-65-Ed25519",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    # Should output a JSON representation of the keypair
    keypair_data = json.loads(result.stdout)
    assert "algorithm" in keypair_data
    assert keypair_data["algorithm"] == "ML-DSA-65-Ed25519"
    assert "private_key" in keypair_data
    assert "public_key" in keypair_data
    assert isinstance(keypair_data["private_key"], str)  # base64 encoded
    assert isinstance(keypair_data["public_key"], str)  # base64 encoded


def test_cli_invalid_command():
    """Test CLI handling of invalid commands."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "invalid-command"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "invalid" in result.stdout.lower() or "invalid" in result.stderr.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])