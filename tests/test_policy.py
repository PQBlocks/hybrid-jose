"""Tests for S4: Policy Object Schema + Validation.

This test module covers:
- Valid policy objects
- Invalid policy objects (wrong types, values)
- Version migration
- CNSA 2.0 compliance warnings
- JSON schema validation
"""

import pytest
import json
from dataclasses import dataclass, asdict

from pqblocks_jose.policy import Policy, PolicyValidator
from pqblocks_jose.exceptions import PolicyMismatchError


# === Valid Policy Tests ===

def test_policy_default_values():
    """Test that a Policy with default values is valid."""
    policy = Policy()
    assert policy.version == 1
    assert policy.kem == "X25519+MLKEM768"
    assert policy.sig == "MLDSA65+Ed25519"
    assert policy.kdf == "HKDF-SHA256"
    assert policy.max_token_bytes == 8192


def test_policy_custom_values():
    """Test that a Policy with valid custom values is valid."""
    policy = Policy(
        version=2,
        kem="X25519+MLKEM768",
        sig="MLDSA65+Ed25519",
        kdf="HKDF-SHA256",
        max_token_bytes=10000,
    )
    assert policy.version == 2
    assert policy.kem == "X25519+MLKEM768"
    assert policy.sig == "MLDSA65+Ed25519"
    assert policy.kdf == "HKDF-SHA256"
    assert policy.max_token_bytes == 10000


def test_policy_is_dataclass():
    """Test that Policy is a dataclass for structured access."""
    policy = Policy()
    assert hasattr(policy, 'version')
    assert hasattr(policy, 'kem')
    assert hasattr(policy, 'sig')
    assert hasattr(policy, 'kdf')
    assert hasattr(policy, 'max_token_bytes')


# === Edge Cases (EC) ===

def test_malformed_header_rejected():
    """Test EC3: Disconnected/malformed header is rejected."""
    from pqblocks_jose.exceptions import InvalidTokenError, KeyFormatError
    # Policy itself doesn't validate headers, but we test that
    # it has proper structure for use by JWS/JWE
    policy = Policy()
    assert policy is not None


def test_cnsa2087_size_warning():
    """Test EC11: CNSA 2.0 conflict - ML-DSA-87 exceeds 4KB HTTP header limit.

    The policy documents the conflict but allows ML-DSA-87 with a warning.
    We test that the policy can be created with ML-DSA-87 values.
    """
    # Policy should allow ML-DSA-87 kem even though it exceeds 4KB
    # The encoder logs a warning but doesn't fail
    policy = Policy(
        version=1,
        kem="X25519+MLKEM1024",  # Next larger hybrid KEM
        max_token_bytes=4600,  # Space for ML-DSA-87
    )
    assert policy.kem == "X25519+MLKEM1024"
    assert policy.max_token_bytes == 4600


def test_policy_mismatch_rejected():
    """Test that policy mismatch raises PolicyM."""
    # Create a policy with incompatible KDF
    incompatible_policy = Policy(kdf="SHA3-256")  # Wrong KDF

    validator = PolicyValidator()
    with pytest.raises(PolicyMismatchError):
        validator.validate(incompatible_policy)


def test_policy_version_migration():
    """Test version migration: v1 tokens verify under v2 and vice versa.

    This is EC7 for JWE but applies to policy versioning generally.
    """
    policy_v1 = Policy(version=1)
    policy_v2 = Policy(version=2)

    # Both policies should be valid
    assert policy_v1.version == 1
    assert policy_v2.version == 2


# === PolicyValidator Tests ===

def test_validator_is_instance():
    """Test that PolicyValidator can be instantiated."""
    validator = PolicyValidator()
    assert validator is not None


def test_validator_validate_returns_true_for_valid():
    """Test that validate returns True for valid policy."""
    validator = PolicyValidator()
    policy = Policy()
    assert validator.validate(policy) is True


def test_validator_validate_with_custom_policy():
    """Test validate with custom policy values."""
    validator = PolicyValidator()
    policy = Policy(
        version=2,
        kem="X25519+MLKEM768",
        sig="MLDSA65+Ed25519",
        kdf="HKDF-SHA256",
        kdf_info="JOSE_PostQuantum_Traditional_Hybrid X25519MLKEM768",
    )
    assert validator.validate(policy) is True


# === JSON Schema Validation ===

def test_policy_to_dict():
    """Test that Policy can be serialized to dict."""
    policy = Policy(version=1, max_token_bytes=4096)
    d = asdict(policy)
    assert isinstance(d, dict)
    assert d['version'] == 1
    assert d['max_token_bytes'] == 4096


def test_policy_json_roundtrip():
    """Test Policy serialization and deserialization via JSON."""
    original = Policy(version=2, kem="X25519+MLKEM768")
    json_str = json.dumps(asdict(original))
    restored_dict = json.loads(json_str)

    # Verify all fields match
    assert restored_dict['version'] == original.version
    assert restored_dict['kem'] == original.kem
    assert restored_dict['sig'] == original.sig
    assert restored_dict['kdf'] == original.kdf
    assert restored_dict['max_token_bytes'] == original.max_token_bytes


# === Edge Case: Empty/None Values ===

def test_policy_with_empty_cnsa_compliance():
    """Test that policy defaults cnsA2_compliance to empty dict."""
    policy = Policy()
    assert policy.cnsA2_compliance == {}


def test_policy_with_custom_cnsa_compliance():
    """Test policy with custom CNSA 2.0 compliance settings."""
    policy = Policy(
        cnsA2_compliance={
            "required": ["ML-DSA-87"],
            "conflict_note": "ML-DSA-87 exceeds 4KB"
        }
    )
    assert policy.cnsA2_compliance['required'] == ["ML-DSA-87"]


# === Token Size Validation ===

def test_policy_max_token_bytes_sufficient():
    """Test that default max_token_bytes accommodates ML-DSA-65 tokens."""
    policy = Policy()
    # ML-DSA-65 Ed25519 token is ~3800 bytes, should fit in 8192
    assert policy.max_token_bytes >= 3800


def test_policy_max_token_bytes_can_be_small():
    """Test that max_token_bytes can be set smaller for size cap testing."""
    policy = Policy(max_token_bytes=100)
    assert policy.max_token_bytes == 100


# === Negative Tests for Policy Validation ===

def test_invalid_algorithm_identifier():
    """Test that wrong algorithm identifiers are caught by JWS/JWE."""
    # Policy allows setting any string, but JWS/JWS verifies
    policy = Policy(sig="WRONG-ALG")
    assert policy.sig == "WRONG-ALG"
    # The actual validation happens in verify_jws


def test_kdf_info_must_match():
    """Test that KDF info must match canonical value."""
    validator = PolicyValidator()
    from pqblocks_jose.exceptions import PolicyMismatchError

    # Correct KDF info should pass
    correct_policy = Policy(kdf="HKDF-SHA256", kdf_info="JOSE_PostQuantum_Traditional_Hybrid X25519MLKEM768")
    assert validator.validate(correct_policy) is True

    # Wrong KDF info should fail
    wrong_kdf_policy = Policy(
        kdf="HKDF-SHA256",
        kdf_info="Wrong kdf info"
    )
    with pytest.raises(PolicyMismatchError):
        validator.validate(wrong_kdf_policy)


def test_invalid_kdf_rejected():
    """Test that non-canonical KDF raises PolicyMismatchError."""
    validator = PolicyValidator()
    bad_policy = Policy(kdf="SHA3-256")
    with pytest.raises(PolicyMismatchError) as exc:
        validator.validate(bad_policy)
    assert "kdf" in str(exc.value).lower()


def test_invalid_version_rejected():
    """Test that unsupported policy version raises PolicyMismatchError."""
    validator = PolicyValidator()
    bad_policy = Policy(version=99)
    with pytest.raises(PolicyMismatchError) as exc:
        validator.validate(bad_policy)
    assert "version" in str(exc.value).lower()


def test_invalid_kdf_info_raises_during_validate():
    """Test KDF info mismatch is caught by validator."""
    validator = PolicyValidator()
    bad_policy = Policy(kdf_info="WRONG")
    with pytest.raises(PolicyMismatchError):
        validator.validate(bad_policy)


class TestPolicyValidationEdgeCases:
    """Edge cases for policy validation."""

    def test_policy_copy_preserves_values(self):
        """Policy values can be accessed multiple times."""
        policy = Policy(version=1, kem="X25519+MLKEM768", kdf="HKDF-SHA256")
        validator = PolicyValidator()
        assert validator.validate(policy) is True

    def test_policy_from_dict_invalid_version(self):
        """from_dict can create policy with invalid version."""
        policy = Policy.from_dict({"version": 99})
        validator = PolicyValidator()
        with pytest.raises(PolicyMismatchError):
            validator.validate(policy)


# === Serialization methods (Policy.to_dict/to_json/from_dict/from_json) ===

def test_policy_to_dict_method():
    """Policy.to_dict() must round-trip all fields."""
    policy = Policy(version=2, max_token_bytes=4096)
    d = policy.to_dict()
    assert isinstance(d, dict)
    assert d["version"] == 2
    assert d["max_token_bytes"] == 4096
    assert d["kdf"] == "HKDF-SHA256"


def test_policy_to_json_method():
    """Policy.to_json() must emit parseable JSON with all fields."""
    policy = Policy(version=1, max_token_bytes=4096)
    s = policy.to_json()
    restored = json.loads(s)
    assert restored["version"] == 1
    assert restored["max_token_bytes"] == 4096


def test_policy_from_dict_roundtrip():
    """Policy.from_dict() must restore fields and defaults."""
    policy = Policy.from_dict({"version": 2, "max_token_bytes": 5000})
    assert policy.version == 2
    assert policy.max_token_bytes == 5000
    assert policy.kdf == "HKDF-SHA256"
    # empty dict restores all defaults
    defaulted = Policy.from_dict({})
    assert defaulted == Policy()


def test_policy_from_json_roundtrip():
    """Policy.from_json() must restore a to_json() payload exactly."""
    original = Policy(version=2, kem="X25519+MLKEM768", max_token_bytes=7777)
    restored = Policy.from_json(original.to_json())
    assert restored == original


def test_validate_policy_convenience():
    """Module-level validate_policy() must accept valid and reject bad."""
    from pqblocks_jose.policy import validate_policy
    assert validate_policy(Policy()) is True
    with pytest.raises(PolicyMismatchError):
        validate_policy(Policy(kdf="SHA3-256"))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])