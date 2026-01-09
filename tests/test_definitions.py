from datetime import datetime, timedelta
from typing import Any

import pytest
from superjwt.definitions import Alg, JWTClaims, Key
from superjwt.exceptions import (
    AlgorithmNotSupportedError,
    InvalidAlgorithmError,
    InvalidKeyError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from superjwt.keys import NoneKey, OctKey

from .conftest import (
    CRYPTOGRAPHY_AVAILABLE,
    JWTCustomClaims,
    check_claims_instance,
    requires_cryptography,
)


if CRYPTOGRAPHY_AVAILABLE:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from superjwt.keys import RSAKey


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


class TestTimeIntegrityValidation:
    """Test suite for the validate_time_integrity model validator."""

    def test_all_none_claims(self):
        """Test that claims with no time fields pass validation."""
        claims = JWTClaims()
        assert claims.iat is None
        assert claims.nbf is None
        assert claims.exp is None

    def test_exp_in_future_valid(self):
        """Test that exp in the future is valid."""
        now = datetime.now(UTC)
        claims = JWTClaims(exp=now + timedelta(hours=1))
        assert claims.exp == now + timedelta(hours=1)

    def test_exp_in_past_raises_error(self):
        """Test that exp in the past raises TokenExpiredError."""
        now = datetime.now(UTC)
        with pytest.raises(TokenExpiredError):
            JWTClaims(exp=now - timedelta(hours=1))

    def test_exp_equal_to_now_valid(self):
        """Test that exp equal to now is valid (within default leeway of 5s)."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        claims = JWTClaims.model_construct(exp=fixed_time)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.exp == fixed_time

    def test_exp_with_leeway(self):
        """Test that exp validation respects leeway."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        # exp is 4.9 seconds in the past, within 5 second leeway (should pass)
        exp_time = fixed_time - timedelta(seconds=4.9)
        claims = JWTClaims.model_construct(exp=exp_time)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.exp == exp_time

        # exp is exactly at leeway boundary (should fail, >= check)
        exp_at_leeway = fixed_time - timedelta(seconds=5)
        claims2 = JWTClaims.model_construct(exp=exp_at_leeway)
        claims2.spoof_time(fixed_time)
        with pytest.raises(TokenExpiredError):
            claims2.revalidate()

        # exp is beyond leeway boundary (should fail)
        exp_beyond_leeway = fixed_time - timedelta(seconds=6)
        claims3 = JWTClaims.model_construct(exp=exp_beyond_leeway)
        claims3.spoof_time(fixed_time)
        with pytest.raises(TokenExpiredError):
            claims3.revalidate()

    def test_nbf_in_past_valid(self):
        """Test that nbf in the past is valid."""
        now = datetime.now(UTC)
        claims = JWTClaims(nbf=now - timedelta(hours=1))
        assert claims.nbf == now - timedelta(hours=1)

    def test_nbf_in_future_raises_error(self):
        """Test that nbf in the future raises TokenNotYetValidError."""
        now = datetime.now(UTC)
        with pytest.raises(TokenNotYetValidError):
            JWTClaims(nbf=now + timedelta(hours=1))

    def test_nbf_equal_to_now_valid(self):
        """Test that nbf equal to now is valid (within leeway)."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        claims = JWTClaims.model_construct(nbf=fixed_time)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.nbf == fixed_time

    def test_nbf_with_leeway(self):
        """Test that nbf validation respects leeway."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        # nbf is 3 seconds in the future, but leeway is 5 seconds (default)
        nbf_time = fixed_time + timedelta(seconds=3)
        claims = JWTClaims.model_construct(nbf=nbf_time)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.nbf == nbf_time

        # nbf is exactly at leeway boundary (should pass, > check)
        nbf_at_leeway = fixed_time + timedelta(seconds=5)
        claims2 = JWTClaims.model_construct(nbf=nbf_at_leeway)
        claims2.spoof_time(fixed_time)
        claims2.revalidate()
        assert claims2.nbf == nbf_at_leeway

        # nbf is beyond leeway boundary (should fail)
        nbf_beyond_leeway = fixed_time + timedelta(seconds=6)
        claims3 = JWTClaims.model_construct(nbf=nbf_beyond_leeway)
        claims3.spoof_time(fixed_time)
        with pytest.raises(TokenNotYetValidError):
            claims3.revalidate()

    def test_iat_in_past_valid(self):
        """Test that iat in the past is valid."""
        now = datetime.now(UTC)
        claims = JWTClaims(iat=now - timedelta(hours=1))
        assert claims.iat == now - timedelta(hours=1)

    def test_iat_equal_to_now_valid(self):
        """Test that iat equal to now is valid."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        claims = JWTClaims.model_construct(iat=fixed_time)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.iat == fixed_time

    def test_iat_in_future_raises_error(self):
        """Test that iat in the future raises ValueError when check_consistent_iat is True."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        iat_future = fixed_time + timedelta(hours=1)
        claims = JWTClaims.model_construct(iat=iat_future)
        claims.spoof_time(fixed_time)
        with pytest.raises(ValueError, match="'iat' claim must not be in the future"):
            claims.revalidate()

    def test_iat_in_future_allowed_when_check_disabled(self):
        """Test that iat in the future is allowed when disable_iat_consistency_check()."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        iat_future = fixed_time + timedelta(hours=1)
        claims = JWTClaims.model_construct(iat=iat_future)
        claims.allow_future_iat()
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.iat == iat_future
        claims.disallow_future_iat()
        with pytest.raises(ValueError, match="'iat' claim must not be in the future"):
            claims.revalidate()

    def test_iat_with_leeway(self):
        """Test that iat validation respects leeway."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        # iat is 3 seconds in the future, but leeway is 5 seconds (default)
        iat_time = fixed_time + timedelta(seconds=3)
        claims = JWTClaims.model_construct(iat=iat_time)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.iat == iat_time

        # iat is exactly at leeway boundary (should pass, > check)
        iat_at_leeway = fixed_time + timedelta(seconds=5)
        claims2 = JWTClaims.model_construct(iat=iat_at_leeway)
        claims2.spoof_time(fixed_time)
        claims2.revalidate()
        assert claims2.iat == iat_at_leeway

        # iat is beyond leeway boundary (should fail)
        iat_beyond_leeway = fixed_time + timedelta(seconds=6)
        claims3 = JWTClaims.model_construct(iat=iat_beyond_leeway)
        claims3.spoof_time(fixed_time)
        with pytest.raises(ValueError, match="'iat' claim must not be in the future"):
            claims3.revalidate()

    def test_nbf_iat_relationship_valid(self):
        """Test that nbf >= iat is valid."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        iat_time = fixed_time - timedelta(days=2)
        nbf_time = fixed_time - timedelta(days=1)

        claims = JWTClaims.model_construct(iat=iat_time, nbf=nbf_time)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.iat == iat_time
        assert claims.nbf == nbf_time

    def test_nbf_equal_to_iat_valid(self):
        """Test that nbf equal to iat is valid."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        time_value = fixed_time - timedelta(days=1)

        claims = JWTClaims.model_construct(iat=time_value, nbf=time_value)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.iat == time_value
        assert claims.nbf == time_value

    def test_nbf_less_than_iat_raises_error(self):
        """Test that nbf < iat raises ValueError."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        iat_time = fixed_time - timedelta(days=1)
        nbf_time = fixed_time - timedelta(days=2)  # nbf before iat

        claims = JWTClaims.model_construct(iat=iat_time, nbf=nbf_time)
        claims.spoof_time(fixed_time)
        with pytest.raises(
            ValueError, match="'nbf' claim must be greater than or equal to 'iat' claim"
        ):
            claims.revalidate()

    def test_all_three_claims_valid(self):
        """Test valid configuration with iat, nbf, and exp."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        iat_time = fixed_time - timedelta(days=2)
        nbf_time = fixed_time - timedelta(days=1)
        exp_time = fixed_time + timedelta(days=1)

        claims = JWTClaims.model_construct(iat=iat_time, nbf=nbf_time, exp=exp_time)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.iat == iat_time
        assert claims.nbf == nbf_time
        assert claims.exp == exp_time

    def test_complex_scenario_with_timestamps(self):
        """Test complex scenario with int timestamps."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        iat_ts = int((fixed_time - timedelta(days=1)).timestamp())
        nbf_ts = int((fixed_time - timedelta(hours=1)).timestamp())
        exp_ts = int((fixed_time + timedelta(days=1)).timestamp())

        claims = JWTClaims.model_construct(iat=iat_ts, nbf=nbf_ts, exp=exp_ts)  # type: ignore
        claims.spoof_time(fixed_time)
        claims.revalidate()

        assert claims.iat is not None
        assert claims.nbf is not None
        assert claims.exp is not None

    def test_custom_leeway(self):
        """Test that custom leeway values work correctly."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        # Set custom leeway to 10 seconds, exp is 8 seconds in past (within leeway)
        exp_time = fixed_time - timedelta(seconds=8)
        claims = JWTClaims.model_construct(exp=exp_time, internal__leeway=10.0)
        claims.spoof_time(fixed_time)
        claims.revalidate()
        assert claims.exp == exp_time

        # exp is at the custom leeway boundary (should fail)
        exp_time2 = fixed_time - timedelta(seconds=10)
        claims2 = JWTClaims.model_construct(exp=exp_time2, internal__leeway=10.0)
        claims2.spoof_time(fixed_time)
        with pytest.raises(TokenExpiredError):
            claims2.revalidate()

        # exp is beyond custom leeway (should fail)
        exp_time3 = fixed_time - timedelta(seconds=11)
        claims3 = JWTClaims.model_construct(exp=exp_time3, internal__leeway=10.0)
        claims3.spoof_time(fixed_time)
        with pytest.raises(TokenExpiredError):
            claims3.revalidate()

    def test_set_leeway_method(self):
        """Test the set_leeway() method."""
        claims = JWTClaims()

        # Test setting valid positive leeway
        claims.set_leeway(10.5)
        assert claims.internal__leeway == 10.5

        # Test setting leeway to zero (should be valid)
        claims.set_leeway(0)
        assert claims.internal__leeway == 0

        # Test that negative leeway raises ValueError
        with pytest.raises(ValueError, match="Leeway must be a non-negative float"):
            claims.set_leeway(-1)


# ============================================================================
# JWTClaims Expiration / IssuedAt Method Tests
# ============================================================================


def test_with_issued_at_basic():
    """Test with_issued_at() method sets iat to current time."""
    fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

    claims = JWTClaims()
    claims.spoof_time(fixed_time)
    updated = claims.with_issued_at()

    assert updated.iat == fixed_time


def test_with_issued_at_preserves_exp_delta():
    """Test that with_issued_at() preserves the delta between iat and exp."""
    fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

    # Create claims with iat 2 days ago and exp 2 days in future (4 day delta)
    old_iat = fixed_time - timedelta(days=2)
    old_exp = fixed_time + timedelta(days=2)

    claims = JWTClaims.model_construct(iat=old_iat, exp=old_exp)
    claims.spoof_time(fixed_time)
    claims.revalidate()

    updated = claims.with_issued_at()

    # iat should now be fixed_time
    assert updated.iat == fixed_time
    # exp should be fixed_time + 4 days
    assert updated.exp == fixed_time + timedelta(days=4)


def test_with_expiration_basic():
    """Test with_expiration() method sets exp relative to now."""
    fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

    claims = JWTClaims()
    claims.spoof_time(fixed_time)
    updated = claims.with_expiration(hours=2)

    assert updated.exp == fixed_time + timedelta(hours=2)
    assert updated.iat is None  # iat not set when it wasn't already


def test_with_expiration_updates_iat():
    """Test that with_expiration() updates iat when it was already set."""
    fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
    old_iat = fixed_time - timedelta(days=1)

    claims = JWTClaims.model_construct(iat=old_iat)
    claims.spoof_time(fixed_time)
    claims.revalidate()

    updated = claims.with_expiration(days=1)

    # iat should be updated to current time
    assert updated.iat == fixed_time
    # exp should be fixed_time + 1 day
    assert updated.exp == fixed_time + timedelta(days=1)


def test_with_expiration_negative_raises_error():
    """Test that with_expiration() raises error for negative values."""
    claims = JWTClaims()

    with pytest.raises(ValueError, match="positive numbers"):
        claims.with_expiration(hours=-1)

    with pytest.raises(ValueError, match="positive numbers"):
        claims.with_expiration(days=-1)

    with pytest.raises(ValueError, match="positive numbers"):
        claims.with_expiration(minutes=-1)


def test_with_expiration_invalid_type_raises_error():
    """Test that with_expiration() raises TypeError for invalid types."""
    claims = JWTClaims()

    with pytest.raises(TypeError, match="must be valid numbers"):
        claims.with_expiration(hours="not a number")  # type: ignore

    with pytest.raises(TypeError, match="must be valid numbers"):
        claims.with_expiration(minutes=[1, 2, 3])  # type: ignore


# ============================================================================
# Spoof Time Tests
# ============================================================================


def test_spoof_time_method():
    """Test spoofing time with spoof_time() method."""
    fixed_time = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)

    claims = JWTClaims()
    claims.spoof_time(fixed_time)
    assert claims.now == fixed_time
    assert claims.internal__now == fixed_time


def test_spoof_time_with_validation():
    """Test that validation uses spoofed time."""
    fixed_time = datetime(2025, 3, 10, 15, 0, 0, tzinfo=UTC)

    # Test exp validation with spoofed time
    future_exp = fixed_time + timedelta(days=30)
    claims = JWTClaims.model_construct(exp=future_exp)
    claims.spoof_time(fixed_time)
    claims.revalidate()
    assert claims.exp == future_exp

    # Test expired token relative to spoofed time
    past_exp = fixed_time - timedelta(days=1)
    past_claims = JWTClaims.model_construct(exp=past_exp)
    past_claims.spoof_time(fixed_time)
    with pytest.raises(TokenExpiredError):
        past_claims.revalidate()


def test_spoof_time_revert():
    """Test reverting from spoofed time back to normal."""
    fixed_time = datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)

    claims = JWTClaims()
    claims.spoof_time(fixed_time)
    assert claims.now == fixed_time

    # Revert
    claims.spoof_time(None)
    current_actual_time = datetime.now(UTC)
    time_diff = abs((claims.now - current_actual_time).total_seconds())
    assert time_diff < 2  # Within 2 seconds tolerance


# ============================================================================
# Timestamp Serialization Tests
# ============================================================================


def test_default_int_serialization(jwt, secret_key):
    """Test that default serialization uses int (microseconds truncated)."""
    now = datetime.now(UTC)
    claims = JWTClaims(iat=now, exp=now + timedelta(hours=1))

    # Verify default is int
    assert claims.internal__jwtdatetime_force_int is True

    # Encode and decode
    token = jwt.encode(claims, secret_key, Alg.HS256)
    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)

    # Check payload has int timestamps
    assert isinstance(decoded.payload["iat"], int)
    assert isinstance(decoded.payload["exp"], int)

    # Verify microseconds were truncated
    assert decoded.payload["iat"] == int(now.timestamp())
    assert decoded.payload["exp"] == int((now + timedelta(hours=1)).timestamp())


def test_float_serialization_preserves_microseconds(jwt, secret_key):
    """Test that float serialization preserves microseconds."""
    now = datetime.now(UTC)
    claims = JWTClaims(iat=now, exp=now + timedelta(hours=1))

    # Switch to float mode
    claims.force_jwtdatetime_to_float()

    # Encode and decode
    token = jwt.encode(claims, secret_key, Alg.HS256)
    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)

    # Check payload has float timestamps
    assert isinstance(decoded.payload["iat"], float)
    assert isinstance(decoded.payload["exp"], float)

    # Verify microseconds were preserved
    assert decoded.payload["iat"] == now.timestamp()
    assert decoded.payload["exp"] == (now + timedelta(hours=1)).timestamp()

    # Verify exact microsecond match
    assert abs(decoded.payload["iat"] - now.timestamp()) < 1e-6
    assert abs(decoded.payload["exp"] - (now + timedelta(hours=1)).timestamp()) < 1e-6


def test_custom_claims_int_mode(jwt, secret_key):
    """Test custom claims with int serialization mode."""
    now = datetime.now(UTC)
    claims_before = JWTCustomClaims(
        iss="issuer",
        sub="user123",
        user_id="value",
        iat=now,
        exp=now + timedelta(days=1),
        past_date=now - timedelta(days=1),
        future_date=now + timedelta(days=2),
    )

    # Default int mode
    assert claims_before.internal__jwtdatetime_force_int is True

    # Encode and decode
    token = jwt.encode(claims_before, secret_key, Alg.HS256)
    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)
    claims_after = JWTCustomClaims(**decoded.payload)

    # Check with int precision
    check_claims_instance(claims_before, claims_after, jwtdatetime_force_int=True)


def test_custom_claims_float_mode(jwt, secret_key):
    """Test custom claims with float serialization mode."""
    now = datetime.now(UTC)
    claims_before = JWTCustomClaims(
        iss="issuer",
        sub="user123",
        user_id="value",
        iat=now,
        exp=now + timedelta(days=1),
        past_date=now - timedelta(days=1),
        future_date=now + timedelta(days=2),
    )

    # Switch to float mode
    claims_before.force_jwtdatetime_to_float()

    # Encode and decode
    token = jwt.encode(claims_before, secret_key, Alg.HS256)
    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)
    claims_after = JWTCustomClaims(**decoded.payload)

    # Check with float precision - should preserve microseconds
    check_claims_instance(claims_before, claims_after, jwtdatetime_force_int=False)


def test_microseconds_actually_preserved_in_float_mode(jwt, secret_key):
    """Explicitly verify microseconds are preserved in float mode."""
    # Create datetime with specific microseconds
    dt_with_microseconds = datetime(2026, 1, 3, 12, 30, 45, 123456, tzinfo=UTC)

    claims = JWTClaims(iat=dt_with_microseconds)
    claims.force_jwtdatetime_to_float()

    # Encode and decode
    token = jwt.encode(claims, secret_key, Alg.HS256)
    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)

    # Reconstruct datetime from float timestamp
    decoded_dt = datetime.fromtimestamp(decoded.payload["iat"], tz=UTC)

    # Verify microseconds match
    assert decoded_dt.microsecond == 123456
    assert decoded_dt == dt_with_microseconds


def test_microseconds_truncated_in_int_mode(jwt, secret_key):
    """Explicitly verify microseconds are truncated in int mode."""
    # Create datetime with specific microseconds
    dt_with_microseconds = datetime(2026, 1, 3, 12, 30, 45, 123456, tzinfo=UTC)

    claims = JWTClaims(iat=dt_with_microseconds)
    # Default int mode

    # Encode and decode
    token = jwt.encode(claims, secret_key, Alg.HS256)
    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)

    # Reconstruct datetime from int timestamp
    decoded_dt = datetime.fromtimestamp(decoded.payload["iat"], tz=UTC)

    # Verify microseconds were lost
    assert decoded_dt.microsecond == 0
    assert decoded_dt != dt_with_microseconds
    # But should match at second level
    assert int(decoded_dt.timestamp()) == int(dt_with_microseconds.timestamp())


def test_unserialized_datetime(claims_dict: dict[str, Any]):
    """Test datetime serialization in to_dict()."""
    claims = JWTClaims.model_construct(**claims_dict)

    assert int(claims.exp) == int(claims_dict["exp"])  # type: ignore

    claims.force_jwtdatetime_to_float()
    claims_dict_float = claims.to_dict()
    assert abs(claims.exp - claims_dict_float["exp"]) < 1e-6


class TestAlgEnum:
    """Test suite for the Alg enum methods."""

    def test_get_instance_not_implemented(self):
        """Test that get_instance() raises AlgorithmNotSupportedError for unimplemented algorithms."""
        # EdDSA is defined but not yet implemented (ALG_INSTANCES[RS256] = None)
        with pytest.raises(
            AlgorithmNotSupportedError, match=r"EdDSA.*not yet implemented"
        ):
            Alg.EdDSA.get_instance()

    def test_get_instance_by_name_invalid_algorithm(self):
        """Test that get_instance_by_name() raises InvalidAlgorithmError for invalid algorithm names."""
        with pytest.raises(
            InvalidAlgorithmError, match=r"INVALID.*not a valid JWS algorithm"
        ):
            Alg.get_instance_by_name("INVALID")

    def test_get_instance_by_name_not_implemented(self):
        """Test that get_instance_by_name() raises AlgorithmNotSupportedError for unimplemented algorithms."""
        # EdDSA is defined but not yet implemented (ALG_INSTANCES[PS256] = None)
        with pytest.raises(
            AlgorithmNotSupportedError, match=r"EdDSA.*not yet implemented"
        ):
            Alg.get_instance_by_name("EdDSA")

    def test_get_instance_success(self):
        """Test that get_instance() successfully returns an algorithm instance for implemented algorithms."""
        instance = Alg.HS256.get_instance()
        assert instance is not None
        assert instance.__class__.__name__ == "HS256Algorithm"

    def test_get_instance_by_name_success(self):
        """Test that get_instance_by_name() successfully returns an algorithm instance for implemented algorithms."""
        instance = Alg.get_instance_by_name("HS256")
        assert instance is not None
        assert instance.__class__.__name__ == "HS256Algorithm"


class TestKeyEnum:
    """Test suite for the Key enum static methods."""

    def test_make_key_with_symmetric_algorithm(self):
        """Test Key.make_key() with symmetric algorithm (HMAC)."""
        key = Key.make_key("HS256", private_key=b"secret", public_key=None)
        assert isinstance(key, OctKey)
        assert key.private_key == b"secret"
        assert key.public_key == b""

    def test_make_key_with_none_algorithm(self):
        """Test Key.make_key() with 'none' algorithm."""
        key = Key.make_key("none", private_key=None, public_key=None)
        assert isinstance(key, NoneKey)
        assert key.private_key == b""
        assert key.public_key == b""

    def test_make_signing_key_with_symmetric_algorithm(self):
        """Test Key.make_signing_key() with symmetric algorithm (HMAC)."""
        key = Key.make_signing_key("HS256", b"secret")
        assert isinstance(key, OctKey)
        assert key.private_key == b"secret"
        assert key.public_key == b""

    def test_make_signing_key_with_none_algorithm(self):
        """Test Key.make_signing_key() with 'none' algorithm."""
        key = Key.make_signing_key("none", b"")
        assert isinstance(key, NoneKey)
        assert key.private_key == b""
        assert key.public_key == b""

    def test_make_verifying_key_with_symmetric_algorithm(self):
        """Test Key.make_verifying_key() with symmetric algorithm (HMAC)."""
        key = Key.make_verifying_key("HS256", b"secret")
        assert isinstance(key, OctKey)
        assert key.private_key == b"secret"
        assert key.public_key == b""

    def test_make_verifying_key_with_none_algorithm(self):
        """Test Key.make_verifying_key() with 'none' algorithm."""
        key = Key.make_verifying_key("none", b"")
        assert isinstance(key, NoneKey)
        assert key.private_key == b""
        assert key.public_key == b""

    def test_make_key_with_symmetric_algorithm_and_public_key_raises_error(self):
        """Test Key.make_key() with symmetric algorithm and public_key raises InvalidKeyError."""
        with pytest.raises(
            InvalidKeyError, match=r"Symmetric key should not have a public key component"
        ):
            Key.make_key("HS256", private_key=b"secret", public_key=b"invalid")

    @requires_cryptography
    def test_make_key_with_rsa_algorithm(self):
        """Test Key.make_key() with RSA algorithm (RS256)."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Test with RS256
        key = Key.make_key("RS256", private_key=private_pem, public_key=public_pem)
        assert isinstance(key, RSAKey)
        assert key.private_key == private_pem
        assert key.public_key == public_pem

    @requires_cryptography
    def test_make_key_with_ps256_algorithm(self):
        """Test Key.make_key() with PS256 algorithm."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Test with PS256
        key = Key.make_key("PS256", private_key=private_pem, public_key=public_pem)
        assert isinstance(key, RSAKey)
        assert key.private_key == private_pem
        assert key.public_key == public_pem

    @requires_cryptography
    def test_make_key_with_ps384_algorithm(self):
        """Test Key.make_key() with PS384 algorithm."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Test with PS384
        key = Key.make_key("PS384", private_key=private_pem, public_key=public_pem)
        assert isinstance(key, RSAKey)
        assert key.private_key == private_pem
        assert key.public_key == public_pem

    @requires_cryptography
    def test_make_key_with_ps512_algorithm(self):
        """Test Key.make_key() with PS512 algorithm."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Test with PS512
        key = Key.make_key("PS512", private_key=private_pem, public_key=public_pem)
        assert isinstance(key, RSAKey)
        assert key.private_key == private_pem
        assert key.public_key == public_pem

    @requires_cryptography
    def test_make_signing_key_with_rsa_algorithm(self):
        """Test Key.make_signing_key() with RSA algorithm (RS256)."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Test with RS256
        key = Key.make_signing_key("RS256", private_pem)
        assert isinstance(key, RSAKey)
        assert key.private_key == private_pem
        assert key.public_key != b""  # Public key derived from private

    @requires_cryptography
    def test_make_signing_key_with_ps_algorithms(self):
        """Test Key.make_signing_key() with PS algorithms."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Test with PS256, PS384, PS512
        for alg in ["PS256", "PS384", "PS512"]:
            key = Key.make_signing_key(alg, private_pem)
            assert isinstance(key, RSAKey)
            assert key.private_key == private_pem
            assert key.public_key != b""  # Public key derived from private

    @requires_cryptography
    def test_make_verifying_key_with_rsa_algorithm(self):
        """Test Key.make_verifying_key() with RSA algorithm (RS256)."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Test with RS256
        key = Key.make_verifying_key("RS256", public_pem)
        assert isinstance(key, RSAKey)
        assert key.private_key == b""
        assert key.public_key == public_pem

    @requires_cryptography
    def test_make_verifying_key_with_ps_algorithms(self):
        """Test Key.make_verifying_key() with PS algorithms."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Test with PS256, PS384, PS512
        for alg in ["PS256", "PS384", "PS512"]:
            key = Key.make_verifying_key(alg, public_pem)
            assert isinstance(key, RSAKey)
            assert key.private_key == b""
            assert key.public_key == public_pem
