from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import Field
from superjwt.exceptions import TokenExpiredError, TokenNotYetValidError
from superjwt.jwt import decode, encode
from superjwt.shared import Alg
from superjwt.validations import (
    DEFAULT_ALLOW_FUTURE_IAT,
    DEFAULT_LEEWAY_SECONDS,
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    JWTDatetimeFloat,
    JWTDatetimeInt,
    Operation,
    Validation,
    ValidationConfig,
)


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


# ============================================================================
# Test Fixtures
# ============================================================================


class ModelA(JWTClaims):
    """First pydantic model for testing - requires field_a."""

    field_a: str  # Required field


class ModelB(JWTClaims):
    """Second pydantic model for testing - requires field_b."""

    field_b: str  # Required field


class CustomModel(JWTClaims):
    """Custom model with additional field for testing."""

    custom_field: int


# ============================================================================
# Test Time Integrity
# ============================================================================


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
        """Test that nbf in the future raises TokenNotYetValidError during decode."""
        now = datetime.now(UTC)
        # nbf validation only happens during decode operation
        with pytest.raises(TokenNotYetValidError):
            JWTClaims.model_validate(
                {"nbf": now + timedelta(hours=1)}, context={"operation": Operation.DECODE}
            )

        # Without decode context, nbf in the future should be allowed (no error)
        claims = JWTClaims.model_construct(nbf=now + timedelta(hours=1))
        claims.spoof_time(now)
        claims.revalidate()  # Should NOT raise - no decode context
        assert claims.nbf == now + timedelta(hours=1)

        # But with decode context, it should raise
        with pytest.raises(TokenNotYetValidError):
            claims.revalidate(context={"operation": Operation.DECODE})

    def test_nbf_equal_to_now_valid(self):
        """Test that nbf equal to now is valid (within leeway) during decode."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        claims = JWTClaims.model_construct(nbf=fixed_time)
        claims.spoof_time(fixed_time)
        # nbf validation only happens during decode
        claims.revalidate(context={"operation": Operation.DECODE})
        assert claims.nbf == fixed_time

    def test_nbf_with_leeway(self):
        """Test that nbf validation respects leeway during decode."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        # nbf is 3 seconds in the future, but leeway is 5 seconds (default)
        # nbf validation only happens during decode
        nbf_time = fixed_time + timedelta(seconds=3)
        claims = JWTClaims.model_construct(nbf=nbf_time)
        claims.spoof_time(fixed_time)
        claims.revalidate(context={"operation": Operation.DECODE})
        assert claims.nbf == nbf_time

        # nbf is exactly at leeway boundary (should pass, > check)
        nbf_at_leeway = fixed_time + timedelta(seconds=5)
        claims2 = JWTClaims.model_construct(nbf=nbf_at_leeway)
        claims2.spoof_time(fixed_time)
        claims2.revalidate(context={"operation": Operation.DECODE})
        assert claims2.nbf == nbf_at_leeway

        # nbf is beyond leeway boundary (should fail)
        nbf_beyond_leeway = fixed_time + timedelta(seconds=6)
        claims3 = JWTClaims.model_construct(nbf=nbf_beyond_leeway)
        claims3.spoof_time(fixed_time)
        with pytest.raises(TokenNotYetValidError):
            claims3.revalidate(context={"operation": Operation.DECODE})

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

    # JWTClaims Expiration / IssuedAt Method Tests

    def test_with_issued_at_basic(self):
        """Test with_issued_at() method sets iat to current time."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        claims = JWTClaims()
        claims.spoof_time(fixed_time)
        updated = claims.with_issued_at()

        assert updated.iat == fixed_time

    def test_with_issued_at_preserves_exp_delta(self):
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

    def test_with_expiration_basic(self):
        """Test with_expiration() method sets exp relative to now."""
        fixed_time = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        claims = JWTClaims()
        claims.spoof_time(fixed_time)
        updated = claims.with_expiration(hours=2)

        assert updated.exp == fixed_time + timedelta(hours=2)
        assert updated.iat is None  # iat not set when it wasn't already

    def test_with_expiration_updates_iat(self):
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

    def test_with_expiration_negative_raises_error(self):
        """Test that with_expiration() raises error for negative values."""
        claims = JWTClaims()

        with pytest.raises(ValueError, match="positive numbers"):
            claims.with_expiration(hours=-1)

        with pytest.raises(ValueError, match="positive numbers"):
            claims.with_expiration(days=-1)

        with pytest.raises(ValueError, match="positive numbers"):
            claims.with_expiration(minutes=-1)

    def test_with_expiration_invalid_type_raises_error(self):
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


def test_default_int_serialization(secret_key):
    """Test that default JWTClaims uses JWTDatetimeInt (microseconds truncated)."""
    now = datetime.now(UTC)
    claims = JWTClaims(iat=now, exp=now + timedelta(hours=1))

    # Encode and decode
    token = encode(claims, secret_key, Alg.HS256)
    decoded = decode(token, secret_key, Alg.HS256)
    decoded_dict = decoded.to_dict()

    # Check payload has int timestamps
    assert isinstance(decoded_dict["iat"], int)
    assert isinstance(decoded_dict["exp"], int)

    # Verify microseconds were truncated
    assert decoded_dict["iat"] == int(now.timestamp())
    assert decoded_dict["exp"] == int((now + timedelta(hours=1)).timestamp())


def test_float_serialization_with_custom_model(secret_key):
    """Test that JWTDatetimeFloat custom fields preserve microseconds."""

    class CustomFloatClaims(JWTClaims):
        # Override exp as JWTDatetimeFloat to preserve microseconds
        exp: JWTDatetimeFloat = Field(default=...)  # type: ignore
        # Add custom float timestamp field
        custom_time: JWTDatetimeFloat | None = None

    now = datetime.now(UTC)
    exp_time = now + timedelta(hours=1)
    custom_time = datetime(2026, 1, 15, 12, 30, 45, 123456, tzinfo=UTC)

    claims = CustomFloatClaims(iat=now, exp=exp_time, custom_time=custom_time)

    # Encode and decode
    token = encode(claims, secret_key, Alg.HS256)
    decoded = decode(token, secret_key, Alg.HS256, validation=CustomFloatClaims)
    decoded_dict = decoded.to_dict()

    # iat should still be int (JWTDatetimeInt in base JWTClaims)
    assert isinstance(decoded_dict["iat"], int)
    assert decoded_dict["iat"] == int(now.timestamp())

    # exp should be float (overridden as JWTDatetimeFloat)
    assert isinstance(decoded_dict["exp"], float)
    assert abs(decoded_dict["exp"] - exp_time.timestamp()) < 1e-6

    # custom_time should be float (JWTDatetimeFloat)
    assert isinstance(decoded_dict["custom_time"], float)
    assert abs(decoded_dict["custom_time"] - custom_time.timestamp()) < 1e-6


def test_mixed_datetime_serialization_types(secret_key):
    """Test custom claims with mixed JWTDatetimeInt and JWTDatetimeFloat."""

    class MixedClaims(JWTClaims):
        # exp overridden as JWTDatetimeFloat
        exp: JWTDatetimeFloat = Field(default=...)  # type: ignore

        # nbf overridden as required JWTDatetimeInt
        nbf: JWTDatetimeInt = Field(default=...)  # type: ignore

        # Custom field with JWTDatetimeFloat
        custom_float_time: JWTDatetimeFloat | None = None

        # Custom field with JWTDatetimeInt
        custom_int_time: JWTDatetimeInt | None = None

    now = datetime.now(UTC)
    iat_time = now - timedelta(days=1)
    exp_time = now + timedelta(hours=10, minutes=30, seconds=15, microseconds=123456)
    nbf_time = now - timedelta(minutes=5, microseconds=789012)
    custom_float = datetime(2026, 3, 15, 8, 45, 22, 987654, tzinfo=UTC)
    custom_int = datetime(2026, 6, 20, 14, 10, 30, 456789, tzinfo=UTC)

    claims = MixedClaims.model_construct(
        iat=iat_time,
        exp=exp_time,
        nbf=nbf_time,
        custom_float_time=custom_float,
        custom_int_time=custom_int,
    )

    # Encode and decode
    token = encode(claims, secret_key, Alg.HS256)
    decoded = decode(token, secret_key, Alg.HS256, validation=MixedClaims)
    decoded_dict = decoded.to_dict()

    # iat should be int (default JWTDatetimeInt)
    assert isinstance(decoded_dict["iat"], int)
    assert decoded_dict["iat"] == int(iat_time.timestamp())

    # exp should be float (overridden as JWTDatetimeFloat)
    assert isinstance(decoded_dict["exp"], float)
    assert abs(decoded_dict["exp"] - exp_time.timestamp()) < 1e-6

    # nbf should be int (overridden as JWTDatetimeInt)
    assert isinstance(decoded_dict["nbf"], int)
    assert decoded_dict["nbf"] == int(nbf_time.timestamp())

    # custom_float_time should be float with microseconds preserved
    assert isinstance(decoded_dict["custom_float_time"], float)
    assert abs(decoded_dict["custom_float_time"] - custom_float.timestamp()) < 1e-6

    # custom_int_time should be int with microseconds truncated
    assert isinstance(decoded_dict["custom_int_time"], int)
    assert decoded_dict["custom_int_time"] == int(custom_int.timestamp())


def test_microseconds_preserved_in_float_type(secret_key):
    """Verify microseconds are preserved with JWTDatetimeFloat."""

    class FloatTimeClaims(JWTClaims):
        iat: JWTDatetimeFloat = Field(default=...)  # type: ignore

    # Create datetime with specific microseconds
    dt_with_microseconds = datetime(2016, 1, 15, 12, 30, 45, 123456, tzinfo=UTC)
    claims = FloatTimeClaims(iat=dt_with_microseconds)

    # Encode and decode
    token = encode(claims, secret_key, Alg.HS256)
    decoded = decode(token, secret_key, Alg.HS256, validation=FloatTimeClaims)
    decoded_dict = decoded.to_dict()

    # Reconstruct datetime from float timestamp
    decoded_dt = datetime.fromtimestamp(decoded_dict["iat"], tz=UTC)

    # Verify microseconds match
    assert decoded_dt.microsecond == 123456
    assert decoded_dt == dt_with_microseconds


def test_microseconds_truncated_in_int_type(secret_key):
    """Verify microseconds are truncated with JWTDatetimeInt (default)."""

    # Create datetime with specific microseconds
    dt_with_microseconds = datetime(2016, 1, 15, 12, 30, 45, 123456, tzinfo=UTC)
    claims = JWTClaims(iat=dt_with_microseconds)

    # Encode and decode
    token = encode(claims, secret_key, Alg.HS256)
    decoded = decode(token, secret_key, Alg.HS256)
    decoded_dict = decoded.to_dict()

    # Reconstruct datetime from int timestamp
    decoded_dt = datetime.fromtimestamp(decoded_dict["iat"], tz=UTC)

    # Verify microseconds were lost
    assert decoded_dt.microsecond == 0
    assert decoded_dt != dt_with_microseconds
    # But should match at second level
    assert int(decoded_dt.timestamp()) == int(dt_with_microseconds.timestamp())


def test_to_dict_serialization(claims_dict: dict[str, Any]):
    """Test datetime serialization in to_dict()."""

    claims = JWTClaims.model_construct(**claims_dict)
    claims_serialized = claims.to_dict()

    # iat and exp are JWTDatetimeInt by default, should be int
    assert isinstance(claims_serialized["iat"], int)
    assert isinstance(claims_serialized["exp"], int)
    assert claims_serialized["iat"] == int(claims_dict["iat"])
    assert claims_serialized["exp"] == int(claims_dict["exp"])

    # Now test with custom model using float
    class FloatClaims(JWTClaims):
        iat: JWTDatetimeFloat | None = None  # type: ignore

    float_claims = FloatClaims.model_construct(**claims_dict)
    float_serialized = float_claims.to_dict()

    # iat should now be float
    assert isinstance(float_serialized["iat"], float)
    assert abs(float_serialized["iat"] - claims_dict["iat"]) < 1e-6


# ============================================================================
# ValidationConfig Class Tests
# ============================================================================


def test_validation_config_default_initialization():
    """Test ValidationConfig with default initialization."""
    validation = ValidationConfig()

    assert validation.enabled is True
    assert validation.model is JWTBaseModel
    assert validation.forward_pydantic_model is True
    assert validation.leeway is None
    assert validation.allow_future_iat is None
    assert validation.now is None


def test_validation_config_custom_initialization():
    """Test ValidationConfig with custom parameters."""
    now = datetime.now(UTC)
    validation = ValidationConfig(
        enabled=False,
        model=JWTClaims,
        forward_pydantic_model=False,
        leeway=10.0,
        allow_future_iat=True,
        now=now,
    )

    assert validation.enabled is False
    assert validation.model == JWTClaims
    assert validation.forward_pydantic_model is False
    assert validation.leeway == 10.0
    assert validation.allow_future_iat is True
    assert validation.now == now


def test_validation_applies_defaults_for_jwtclaims_models():
    """Test get_validation fills defaults for JWTClaims-derived validation models."""
    validation_cfg = ValidationConfig(
        model=JWTClaims,
        leeway=None,
        allow_future_iat=None,
        now=None,
    )

    validation = Validation.get({"sub": "test"}, validation_cfg, JWTClaims)

    assert validation.leeway == DEFAULT_LEEWAY_SECONDS
    assert validation.allow_future_iat == DEFAULT_ALLOW_FUTURE_IAT
    assert validation.now is None


def test_validation_inherits_from_model():
    """Test get_validation inherits None values from pydantic model."""
    # Create model with custom internal values
    model = JWTClaims()
    model.set_leeway(20.0)
    model.allow_future_iat()
    custom_now = datetime.now(UTC)
    model.spoof_time(custom_now)

    # Validation with all None values should inherit
    validation_cfg = ValidationConfig(
        model=JWTClaims,
        leeway=None,
        allow_future_iat=None,
        now=None,
    )

    validation = Validation.get(model, validation_cfg, JWTClaims)

    assert validation.leeway == 20.0
    assert validation.allow_future_iat is True
    assert validation.now == custom_now


def test_validation_does_not_override():
    """Test get_validation does not override set values."""
    # Create model with custom internal values
    model = JWTClaims()
    model.set_leeway(100.0)
    model.allow_future_iat()
    model_now = datetime.now(UTC)
    model.spoof_time(model_now)

    # Validation with set values should NOT be overridden
    config_now = model_now + timedelta(hours=1)
    validation_cfg = ValidationConfig(
        model=JWTClaims,
        leeway=7.0,
        allow_future_iat=False,
        now=config_now,
    )

    validation = Validation.get(model, validation_cfg, JWTClaims)

    assert validation.leeway == 7.0  # NOT 100.0
    assert validation.allow_future_iat is False  # NOT True
    assert validation.now == config_now  # NOT model_now


def test_validation_mixed():
    """Test get_validation with mix of None and set values."""
    model = JWTClaims()
    model.set_leeway(50.0)
    model.allow_future_iat()
    model_now = datetime.now(UTC)
    model.spoof_time(model_now)

    validation_cfg = ValidationConfig(
        model=JWTClaims,
        leeway=10.0,  # Set - should NOT be overridden
        allow_future_iat=None,  # None - should inherit True
        now=None,  # None - should inherit model_now
    )

    validation = Validation.get(model, validation_cfg, JWTClaims)

    assert validation.leeway == 10.0  # Used validation's value
    assert validation.allow_future_iat is True  # Inherited from model
    assert validation.now == model_now  # Inherited from model


def test_validation_run_rejects_invalid_data_type():
    """Test Validation.run() rejects unsupported data types."""
    validation = Validation(enabled=True, model=JWTClaims)

    with pytest.raises(
        TypeError, match="Wrong type during data preparation and validation"
    ):
        validation.run(123)  # type: ignore[arg-type]


def test_validation_run_with_dict_data():
    """Test Validation.run() with dict data."""
    validation = Validation(
        enabled=True,
        model=JWTClaims,
    )

    now = datetime.now(UTC)
    data = {
        "sub": "user123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    _, result_dict, _ = validation.run(data, dump_dict=True)

    # Should return dict with validated data
    assert isinstance(result_dict, dict)
    assert result_dict["sub"] == "user123"


def test_validation_run_with_pydantic_data():
    """Test Validation.run() with pydantic data."""
    validation = Validation(
        enabled=True,
        model=JWTClaims,
    )

    data = JWTClaims(sub="user123")
    _, result_dict, _ = validation.run(data, dump_dict=True)

    # Should return dict
    assert isinstance(result_dict, dict)
    assert result_dict["sub"] == "user123"


def test_validation_run_disabled():
    """Test Validation.run() with validation disabled."""
    validation = Validation(
        enabled=False,
        model=JWTClaims,
    )

    # Test with dict
    data_dict = {"sub": "user123"}
    _, result_dict, _ = validation.run(data_dict, dump_dict=True)
    assert result_dict == data_dict

    # Test with pydantic model
    data_pydantic = JWTClaims(sub="user123")
    _, result_dict, _ = validation.run(data_pydantic, dump_dict=True)
    assert isinstance(result_dict, dict)
    assert result_dict["sub"] == "user123"


# ============================================================================
# Test JOSEHeader Validation
# ============================================================================


class TestJOSEHeaderValidation:
    """Test suite for JOSEHeader model validation."""

    def test_validate_crit_none(self):
        """Test that crit=None is valid."""
        header = JOSEHeader(alg="HS256", crit=None)
        assert header.crit is None

    def test_validate_crit_empty_list_raises_error(self):
        """Test that empty crit list raises ValueError."""
        with pytest.raises(
            ValueError, match="'crit' header must be a non-empty list of strings"
        ):
            JOSEHeader(alg="HS256", crit=[])

    def test_validate_crit_missing_header_raises_error(self):
        """Test that crit referencing missing header raises ValueError."""
        with pytest.raises(ValueError, match="'crit' header missing 'missing_header'"):
            JOSEHeader(alg="HS256", crit=["missing_header"])

    def test_validate_crit_valid(self):
        """Test that valid crit list passes validation."""
        header = JOSEHeader(alg="HS256", kid="key-123", crit=["kid"])
        assert header.crit == ["kid"]

    def test_validate_crit_multiple_headers(self):
        """Test crit validation with multiple headers."""
        header = JOSEHeader(alg="HS256", kid="key-123", typ="JWT", crit=["kid", "typ"])
        assert header.crit == ["kid", "typ"]


# ============================================================================
# Validation.get() Tests - DISABLE Cases
# ============================================================================


def test_get_validation_disable_with_validation_none_uses_default_fallback():
    """Test get_validation_config with validation=None disables validation and uses fallback model."""
    data = {"sub": "user123"}

    result = Validation.get(
        data=data,
        validation=None,
        default_validation=JWTClaims,
    )

    assert result.enabled is False
    assert result.model is JWTBaseModel


def test_get_validation_disable_with_custom_fallback_model():
    """Test disabled validation can select a custom fallback model."""
    data = {"sub": "user123"}

    result = Validation.get(
        data=data,
        validation=None,
        default_validation=JWTClaims,
        fallback_model=JWTClaims,
    )

    assert result.enabled is False
    assert result.model is JWTClaims


def test_get_validation_disable_with_validation_disable_uses_fallback():
    """Test get_validation_config with validation=Validation.DISABLE disables validation."""
    data = ModelA(field_a="test")

    result = Validation.get(
        data=data,
        validation=Validation.DISABLE,
        default_validation=JWTClaims,
    )

    assert result.enabled is False
    assert result.model is JWTBaseModel


def test_get_validation_disable_with_enabled_false_uses_fallback():
    """Test get_validation_config treats ValidationConfig(enabled=False) as disabled."""
    data = {"sub": "user123"}
    custom_validation = ValidationConfig(enabled=False, model=JWTClaims)

    result = Validation.get(
        data=data,
        validation=custom_validation,
        default_validation=JWTClaims,
    )

    assert result.enabled is False
    assert result.model is JWTBaseModel


# ============================================================================
# Validation.get() Tests - DEFAULT Cases
# ============================================================================


def test_get_validation_default_with_pydantic_data_forwards_data_model():
    """Test DEFAULT validation forwards the input pydantic model type."""
    data = ModelA(field_a="test")

    result = Validation.get(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=JWTClaims,
    )

    assert result.enabled is True
    assert result.model is ModelA


def test_get_validation_default_with_dict_data_uses_default_validation_model():
    """Test DEFAULT validation for dict data uses default_validation model."""
    data = {"sub": "user123"}

    result = Validation.get(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=JWTClaims,
    )

    assert result.enabled is True
    assert result.model is JWTClaims


def test_get_validation_default_inherits_internal_config():
    """Test DEFAULT validation inherits internal config from pydantic model."""
    data = ModelA(field_a="test")
    data.set_leeway(20.0)
    data.allow_future_iat()

    result = Validation.get(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=JWTClaims,
    )

    assert result.leeway == 20.0
    assert result.allow_future_iat is True


# ============================================================================
# Validation.get() Tests - CUSTOM ValidationConfig Cases
# ============================================================================


def test_get_validation_custom_validation_config_pydantic_forward_true_overrides_model():
    """If forward_pydantic_model=True and data is pydantic, it forwards to data's type."""
    data = ModelA(field_a="test")
    custom_validation = ValidationConfig(model=ModelB, forward_pydantic_model=True)

    result = Validation.get(
        data=data,
        validation=custom_validation,
        default_validation=JWTClaims,
    )

    assert result.enabled is True
    assert result.model is ModelA


def test_get_validation_custom_validation_config_pydantic_forward_false_keeps_model():
    """If forward_pydantic_model=False, the explicit model is kept."""
    data = ModelA(field_a="test")
    custom_validation = ValidationConfig(model=ModelB, forward_pydantic_model=False)

    result = Validation.get(
        data=data,
        validation=custom_validation,
        default_validation=JWTClaims,
    )

    assert result.enabled is True
    assert result.model is ModelB


def test_get_validation_custom_validation_config_with_dict_data():
    """Test custom ValidationConfig with dict data and explicit model."""
    data = {"sub": "user123"}
    custom_validation = ValidationConfig(
        model=JWTClaims,
        leeway=15.0,
    )
    result = Validation.get(
        data=data,
        validation=custom_validation,
        default_validation=JWTClaims,
    )

    assert result.model == JWTClaims
    assert result.leeway == 15.0
    assert result.enabled is True


def test_get_validation_custom_validation_config_forwards_model():
    """Test that ValidationConfig with forward_pydantic_model=True forwards the data model type."""
    data = ModelA(field_a="test")
    custom_validation = ValidationConfig(model=JWTClaims, forward_pydantic_model=True)

    result = Validation.get(
        data=data,
        validation=custom_validation,
        default_validation=JWTClaims,
    )

    # The resulting Validation instance should have the forwarded model
    assert isinstance(result, Validation)
    assert result.model is ModelA
    # The original ValidationConfig should remain unchanged
    assert custom_validation.model is JWTClaims


def test_get_validation_custom_validation_config_inherits_from_model():
    """Test custom ValidationConfig inherits internal config from pydantic model."""
    data = CustomModel(custom_field=42)
    data.set_leeway(30.0)

    custom_validation = ValidationConfig(
        model=JWTClaims,
        forward_pydantic_model=True,
        leeway=None,  # Should inherit from data
    )

    result = Validation.get(
        data=data,
        validation=custom_validation,
        default_validation=JWTClaims,
    )

    assert result.leeway == 30.0


def test_get_validation_custom_model_class_inherits_from_model():
    """Test custom model class inherits internal config from pydantic data."""
    data = CustomModel(custom_field=42)
    data.set_leeway(30.0)

    result = Validation.get(
        data=data,
        validation=JWTClaims,  # Model class directly
        default_validation=JWTClaims,
    )

    assert result.leeway == 30.0


# ============================================================================
# Validation.get() Tests - CUSTOM Model Class Cases
# ============================================================================


def test_get_validation_custom_model_class():
    """Test get_validation_config with model class as validation parameter."""
    data = {"sub": "user123"}
    result = Validation.get(
        data=data,
        validation=JWTClaims,  # Model class
        default_validation=JWTClaims,
    )

    assert result.model == JWTClaims
    assert result.enabled is True


def test_get_validation_custom_model_class_with_pydantic_data():
    """Test get_validation_config with model class and pydantic data."""
    data = ModelA(field_a="test")
    result = Validation.get(
        data=data,
        validation=ModelB,  # Different model class
        default_validation=JWTClaims,
    )

    assert result.model == ModelB  # NOT ModelA
    assert result.enabled is True


# ============================================================================
# Validation.get() Tests - Internal Config Application
# ============================================================================


def test_get_validation_applies_defaults_for_dict_data():
    """Test get_validation_config applies defaults for dict data."""
    data = {"sub": "user123"}
    custom_validation = ValidationConfig(
        model=JWTClaims,
        leeway=None,
        allow_future_iat=None,
    )
    result = Validation.get(
        data=data,
        validation=custom_validation,
        default_validation=JWTClaims,
    )

    # Should have default values applied
    assert result.leeway == DEFAULT_LEEWAY_SECONDS
    assert result.allow_future_iat == DEFAULT_ALLOW_FUTURE_IAT


def test_get_validation_does_not_override_explicit_values():
    """Test get_validation_config does not override explicit internal config."""
    data = ModelA(field_a="test")
    data.set_leeway(50.0)

    custom_validation = ValidationConfig(
        model=JWTClaims,
        forward_pydantic_model=True,
        leeway=10.0,  # Explicit - should NOT be overridden
    )
    result = Validation.get(
        data=data,
        validation=custom_validation,
        default_validation=JWTClaims,
    )

    assert result.leeway == 10.0  # NOT 50.0 from data


# ============================================================================
# Validation.get() Tests - Comprehensive Scenarios
# ============================================================================


def test_get_validation_all_combinations():
    """Test get_validation_config with all parameter combinations.

    This is a comprehensive test covering the 8 main scenarios:
    1. Pydantic data + forward=True + validation_model=None → forwards data type
    2. Pydantic data + forward=True + validation_model=Set → uses explicit model
    3. Pydantic data + forward=False + validation_model=None → no model
    4. Pydantic data + forward=False + validation_model=Set → uses explicit model
    5. Dict data + forward=True + validation_model=None → no model
    6. Dict data + forward=True + validation_model=Set → uses explicit model
    7. Dict data + forward=False + validation_model=None → no model
    8. Dict data + forward=False + validation_model=Set → uses explicit model
    """
    # Default validation model for this matrix
    default_validation_model = JWTClaims

    # Case 1: Pydantic + forward=True + model=JWTClaims -> forwards to data type
    data_1 = ModelA(field_a="test")
    validation_1 = ValidationConfig(model=JWTClaims, forward_pydantic_model=True)
    result_1 = Validation.get(data_1, validation_1, default_validation_model)
    assert result_1.model is ModelA

    # Case 2: Pydantic + forward=True + model=ModelB -> still forwards to data type
    data_2 = ModelA(field_a="test")
    validation_2 = ValidationConfig(model=ModelB, forward_pydantic_model=True)
    result_2 = Validation.get(data_2, validation_2, default_validation_model)
    assert result_2.model is ModelA

    # Case 3: Pydantic + forward=False + model=JWTClaims -> keeps JWTClaims
    data_3 = ModelA(field_a="test")
    validation_3 = ValidationConfig(model=JWTClaims, forward_pydantic_model=False)
    result_3 = Validation.get(data_3, validation_3, default_validation_model)
    assert result_3.model is JWTClaims

    # Case 4: Pydantic + forward=False + model=ModelB -> keeps ModelB
    data_4 = ModelA(field_a="test")
    validation_4 = ValidationConfig(model=ModelB, forward_pydantic_model=False)
    result_4 = Validation.get(data_4, validation_4, default_validation_model)
    assert result_4.model is ModelB

    # Case 5: Dict + forward=True + model=JWTBaseModel -> stays JWTBaseModel
    data_5 = {"sub": "user123"}
    validation_5 = ValidationConfig(model=JWTBaseModel, forward_pydantic_model=True)
    result_5 = Validation.get(data_5, validation_5, default_validation_model)
    assert result_5.model is JWTBaseModel

    # Case 6: Dict + forward=True + model=JWTClaims -> stays JWTClaims
    data_6 = {"sub": "user123"}
    validation_6 = ValidationConfig(model=JWTClaims, forward_pydantic_model=True)
    result_6 = Validation.get(data_6, validation_6, default_validation_model)
    assert result_6.model is JWTClaims

    # Case 7: Dict + forward=False + model=JWTBaseModel -> stays JWTBaseModel
    data_7 = {"sub": "user123"}
    validation_7 = ValidationConfig(model=JWTBaseModel, forward_pydantic_model=False)
    result_7 = Validation.get(data_7, validation_7, default_validation_model)
    assert result_7.model is JWTBaseModel

    # Case 8: Dict + forward=False + model=JWTClaims -> stays JWTClaims
    data_8 = {"sub": "user123"}
    validation_8 = ValidationConfig(model=JWTClaims, forward_pydantic_model=False)
    result_8 = Validation.get(data_8, validation_8, default_validation_model)
    assert result_8.model is JWTClaims


def test_get_validation_default_vs_custom():
    """Test key differences between Validation.DEFAULT and a custom ValidationConfig."""
    data_pydantic = ModelA(field_a="test")
    data_dict = {"sub": "user123"}

    # DEFAULT forwards pydantic type
    result_default_pydantic = Validation.get(data_pydantic, Validation.DEFAULT, JWTClaims)
    assert result_default_pydantic.model is ModelA

    # DEFAULT uses default_validation model for dict
    result_default_dict = Validation.get(data_dict, Validation.DEFAULT, JWTClaims)
    assert result_default_dict.model is JWTClaims

    # Custom config can disable forwarding
    custom_validation = ValidationConfig(model=JWTClaims, forward_pydantic_model=False)
    result_custom_pydantic = Validation.get(data_pydantic, custom_validation, JWTClaims)
    assert result_custom_pydantic.model is JWTClaims


def test_get_validation_invalid_validation_type():
    """Test get_validation_config raises error for invalid validation type."""
    data = {"sub": "user123"}
    with pytest.raises(TypeError, match="Wrong validation object type"):
        Validation.get(
            data=data,
            validation="invalid",  # type: ignore
            default_validation=JWTClaims,
        )
