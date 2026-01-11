"""Unit tests for JWTValidation configuration and get_validation_config().

These tests focus on:
- JWTValidation class: initialization, methods, parameter inheritance
- get_validation_config(): all validation modes and data type combinations

JWT encode/decode integration tests belong in test_jwt.py.
"""

from datetime import datetime, timedelta
from typing import Any

import pytest
from superjwt.algorithms import Alg
from superjwt.exceptions import TokenExpiredError, TokenNotYetValidError
from superjwt.validations import (
    DEFAULT_ALLOW_FUTURE_IAT,
    DEFAULT_LEEWAY_SECONDS,
    JWTBaseModel,
    JWTClaims,
    Validation,
    ValidationConfig,
    get_validation_config,
)

from .conftest import JWTCustomClaims, check_claims_instance


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


# ============================================================================
# JWTValidation Class Tests
# ============================================================================


def test_jwtvalidation_default_initialization():
    """Test JWTValidation with default initialization."""
    validation = ValidationConfig()

    assert validation.enabled is True
    assert validation.model is None
    assert validation.forward_pydantic_model is True
    assert validation.leeway is None
    assert validation.allow_future_iat is None
    assert validation.now is None


def test_jwtvalidation_custom_initialization():
    """Test JWTValidation with custom parameters."""
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


def test_jwtvalidation_apply_internal_cfg_with_none_model():
    """Test apply_internal_cfg uses defaults when model is None."""
    validation = ValidationConfig(
        leeway=None,
        allow_future_iat=None,
        now=None,
    )

    validation.apply_internal_cfg(model=None)

    assert validation.leeway == DEFAULT_LEEWAY_SECONDS
    assert validation.allow_future_iat == DEFAULT_ALLOW_FUTURE_IAT
    assert validation.now is None


def test_jwtvalidation_apply_internal_cfg_inherits_from_model():
    """Test apply_internal_cfg inherits None values from model."""
    # Create model with custom internal values
    model = JWTClaims()
    model.set_leeway(20.0)
    model.allow_future_iat()
    model.force_jwtdatetime_to_float()
    custom_now = datetime.now(UTC)
    model.spoof_time(custom_now)

    # Validation with all None values should inherit
    validation = ValidationConfig(
        leeway=None,
        allow_future_iat=None,
        now=None,
    )

    validation.apply_internal_cfg(model)

    assert validation.leeway == 20.0
    assert validation.allow_future_iat is True
    assert validation.now == custom_now


def test_jwtvalidation_apply_internal_cfg_does_not_override():
    """Test apply_internal_cfg does not override set values."""
    # Create model with custom internal values
    model = JWTClaims()
    model.set_leeway(100.0)
    model.allow_future_iat()
    model.force_jwtdatetime_to_float()
    model_now = datetime.now(UTC)
    model.spoof_time(model_now)

    # Validation with set values should NOT be overridden
    config_now = model_now + timedelta(hours=1)
    validation = ValidationConfig(
        leeway=7.0,
        allow_future_iat=False,
        now=config_now,
    )

    validation.apply_internal_cfg(model)

    assert validation.leeway == 7.0  # NOT 100.0
    assert validation.allow_future_iat is False  # NOT True
    assert validation.now == config_now  # NOT model_now


def test_jwtvalidation_apply_internal_cfg_mixed():
    """Test apply_internal_cfg with mix of None and set values."""
    model = JWTClaims()
    model.set_leeway(50.0)
    model.allow_future_iat()
    model.force_jwtdatetime_to_float()
    model_now = datetime.now(UTC)
    model.spoof_time(model_now)

    validation = ValidationConfig(
        leeway=10.0,  # Set - should NOT be overridden
        allow_future_iat=None,  # None - should inherit True
        now=None,  # None - should inherit model_now
    )

    validation.apply_internal_cfg(model)

    assert validation.leeway == 10.0  # Used validation's value
    assert validation.allow_future_iat is True  # Inherited from model
    assert validation.now == model_now  # Inherited from model


def test_jwtvalidation_model_copy():
    """Test JWTValidation.model_copy creates independent copy."""
    now = datetime.now(UTC)
    original = ValidationConfig(
        model=JWTClaims,
        leeway=10.0,
        allow_future_iat=True,
        now=now,
    )

    copy = original.model_copy(deep=True)

    # Verify values match
    assert copy.model == original.model
    assert copy.leeway == original.leeway
    assert copy.allow_future_iat == original.allow_future_iat
    assert copy.now == original.now

    # Modify copy - should not affect original
    copy.leeway = 20.0
    copy.allow_future_iat = False

    assert original.leeway == 10.0
    assert original.allow_future_iat is True


def test_jwtvalidation_forbids_extra_fields():
    """Test JWTValidation rejects extra fields due to extra='forbid' config."""
    import pydantic

    # Should raise ValidationError when trying to set an invalid field
    with pytest.raises(pydantic.ValidationError, match="Extra inputs are not permitted"):
        ValidationConfig(
            model=JWTClaims,
            invalid_field="some_value",  # type: ignore
        )


def test_jwtvalidation_run_with_no_validation_model():
    """Test JWTValidation.run() raises error when validation_model is None."""
    validation = ValidationConfig(
        model=None,
        enabled=True,
    )

    data = {"sub": "user123"}

    # Should raise error because validation_model is None but validation is enabled
    with pytest.raises(ValueError, match="Validation model is not set in JWTValidation"):
        validation.run(data)


def test_jwtvalidation_run_with_dict_data():
    """Test JWTValidation.run() with dict data."""
    validation = ValidationConfig(
        model=JWTClaims,
        enabled=True,
    )

    now = datetime.now(UTC)
    data = {
        "sub": "user123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    result = validation.run(data)

    # Should return dict with validated data
    assert isinstance(result, dict)
    assert result["sub"] == "user123"


def test_jwtvalidation_run_with_pydantic_data():
    """Test JWTValidation.run() with pydantic data."""
    validation = ValidationConfig(
        model=JWTClaims,
        enabled=True,
    )

    data = JWTClaims(sub="user123")
    result = validation.run(data)

    # Should return dict
    assert isinstance(result, dict)
    assert result["sub"] == "user123"


def test_jwtvalidation_run_disabled():
    """Test JWTValidation.run() with validation disabled."""
    validation = ValidationConfig(
        model=None,
        enabled=False,
    )

    # Test with dict
    data_dict = {"sub": "user123"}
    result_dict = validation.run(data_dict)
    assert result_dict == data_dict

    # Test with pydantic model
    data_pydantic = JWTClaims(sub="user123")
    result_pydantic = validation.run(data_pydantic)
    assert isinstance(result_pydantic, dict)
    assert result_pydantic["sub"] == "user123"


# ============================================================================
# get_validation_config() Tests - DISABLE Cases
# ============================================================================


def test_get_validation_config_disable_with_validation_none():
    """Test get_validation_config with validation=None (DISABLE)."""
    data = {"sub": "user123"}
    default_validation = ValidationConfig(model=JWTClaims)

    result = get_validation_config(
        data=data,
        validation=None,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.enabled is False


def test_get_validation_config_disable_with_validation_disable():
    """Test get_validation_config with validation=Validation.DISABLE."""
    data = ModelA(field_a="test")
    default_validation = ValidationConfig(model=JWTClaims)

    result = get_validation_config(
        data=data,
        validation=Validation.DISABLE,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.enabled is False


def test_get_validation_config_disable_with_enabled_false():
    """Test get_validation_config with JWTValidation(enabled=False)."""
    data = {"sub": "user123"}
    custom_validation = ValidationConfig(enabled=False, model=JWTClaims)
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.enabled is False


# ============================================================================
# get_validation_config() Tests - DEFAULT Cases
# ============================================================================


def test_get_validation_config_default_with_pydantic_data_forward_true():
    """Test DEFAULT validation with pydantic data and forward=True.

    Expected: validation_model should be data's type (ModelA), not default's model.
    """
    data = ModelA(field_a="test")
    default_validation = ValidationConfig(
        model=JWTBaseModel,
        forward_pydantic_model=True,
    )

    result = get_validation_config(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model == ModelA
    assert result.enabled is True


def test_get_validation_config_default_with_pydantic_data_forward_false():
    """Test DEFAULT validation with pydantic data and forward=False.

    Expected: validation_model should be default's model (JWTBaseModel).
    """
    data = ModelA(field_a="test")
    default_validation = ValidationConfig(
        model=JWTBaseModel,
        forward_pydantic_model=False,
    )

    result = get_validation_config(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model == JWTBaseModel
    assert result.enabled is True


def test_get_validation_config_default_with_dict_data():
    """Test DEFAULT validation with dict data.

    Expected: validation_model should be default's model (no forwarding possible).
    """
    data = {"sub": "user123"}
    default_validation = ValidationConfig(
        model=JWTClaims,
        forward_pydantic_model=True,
    )

    result = get_validation_config(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model == JWTClaims
    assert result.enabled is True


def test_get_validation_config_default_inherits_internal_config():
    """Test DEFAULT validation inherits internal config from pydantic model."""
    data = ModelA(field_a="test")
    data.set_leeway(20.0)
    data.allow_future_iat()

    default_validation = ValidationConfig(
        model=JWTBaseModel,
        forward_pydantic_model=True,
        leeway=None,  # Should inherit from data
        allow_future_iat=None,  # Should inherit from data
    )

    result = get_validation_config(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.leeway == 20.0
    assert result.allow_future_iat is True


# ============================================================================
# get_validation_config() Tests - CUSTOM JWTValidation Cases
# ============================================================================


def test_get_validation_config_custom_jwtvalidation_with_pydantic_forward_true():
    """Test custom JWTValidation with pydantic data and forward=True.

    Expected: If validation_model is None, forward data's type.
    """
    data = ModelA(field_a="test")
    custom_validation = ValidationConfig(
        model=None,
        forward_pydantic_model=True,
    )
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model == ModelA
    assert result.enabled is True


def test_get_validation_config_custom_jwtvalidation_with_explicit_model():
    """Test custom JWTValidation with explicit validation_model.

    Expected: validation_model should NOT be overridden by forwarding.
    """
    data = ModelA(field_a="test")
    custom_validation = ValidationConfig(
        model=ModelB,  # Explicit model
        forward_pydantic_model=True,  # Should NOT override explicit model
    )
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model == ModelB  # NOT ModelA
    assert result.enabled is True


def test_get_validation_config_custom_jwtvalidation_forward_false_no_model():
    """Test custom JWTValidation with forward=False and validation_model=None.

    Expected: validation_model should be None (invalid configuration).
    """
    data = ModelA(field_a="test")
    custom_validation = ValidationConfig(
        model=None,
        forward_pydantic_model=False,
    )
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model is None
    assert result.enabled is True


def test_get_validation_config_custom_jwtvalidation_with_dict_data():
    """Test custom JWTValidation with dict data and explicit model."""
    data = {"sub": "user123"}
    custom_validation = ValidationConfig(
        model=JWTClaims,
        leeway=15.0,
    )
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model == JWTClaims
    assert result.leeway == 15.0
    assert result.enabled is True


def test_get_validation_config_custom_jwtvalidation_does_not_mutate():
    """Test that get_validation_config does not mutate input validation config."""
    custom_validation = ValidationConfig(
        model=JWTBaseModel,
        leeway=10.0,
        allow_future_iat=False,
    )
    data = {"sub": "user123"}
    default_validation = ValidationConfig(model=JWTClaims)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    # Modify result
    result.leeway = 20.0
    result.allow_future_iat = True

    # Original should be unchanged
    assert custom_validation.leeway == 10.0
    assert custom_validation.allow_future_iat is False


def test_get_validation_config_custom_jwtvalidation_inherits_from_model():
    """Test custom JWTValidation inherits internal config from pydantic model."""
    data = CustomModel(custom_field=42)
    data.set_leeway(30.0)
    data.force_jwtdatetime_to_float()

    custom_validation = ValidationConfig(
        model=None,
        forward_pydantic_model=True,
        leeway=None,  # Should inherit from data
    )
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.leeway == 30.0


# ============================================================================
# get_validation_config() Tests - CUSTOM Model Class Cases
# ============================================================================


def test_get_validation_config_custom_model_class():
    """Test get_validation_config with model class as validation parameter."""
    data = {"sub": "user123"}
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=JWTClaims,  # Model class
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model == JWTClaims
    assert result.enabled is True


def test_get_validation_config_custom_model_class_with_pydantic_data():
    """Test get_validation_config with model class and pydantic data."""
    data = ModelA(field_a="test")
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=ModelB,  # Different model class
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.model == ModelB  # NOT ModelA
    assert result.enabled is True


# ============================================================================
# get_validation_config() Tests - Internal Config Application
# ============================================================================


def test_get_validation_config_applies_defaults_for_dict_data():
    """Test get_validation_config applies defaults for dict data."""
    data = {"sub": "user123"}
    custom_validation = ValidationConfig(
        model=JWTClaims,
        leeway=None,
        allow_future_iat=None,
    )
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    # Should have default values applied
    assert result.leeway == DEFAULT_LEEWAY_SECONDS
    assert result.allow_future_iat == DEFAULT_ALLOW_FUTURE_IAT


def test_get_validation_config_does_not_override_explicit_values():
    """Test get_validation_config does not override explicit internal config."""
    data = ModelA(field_a="test")
    data.set_leeway(50.0)

    custom_validation = ValidationConfig(
        model=None,
        forward_pydantic_model=True,
        leeway=10.0,  # Explicit - should NOT be overridden
    )
    default_validation = ValidationConfig(model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.leeway == 10.0  # NOT 50.0 from data


# ============================================================================
# get_validation_config() Tests - Comprehensive Scenarios
# ============================================================================


def test_get_validation_config_all_combinations():
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
    default_validation = ValidationConfig(model=JWTBaseModel)

    # Case 1: Pydantic + forward=True + model=None
    data_1 = ModelA(field_a="test")
    validation_1 = ValidationConfig(model=None, forward_pydantic_model=True)
    result_1 = get_validation_config(
        data_1, validation_1, default_validation, JWTBaseModel
    )
    assert result_1.model == ModelA

    # Case 2: Pydantic + forward=True + model=Set
    data_2 = ModelA(field_a="test")
    validation_2 = ValidationConfig(model=ModelB, forward_pydantic_model=True)
    result_2 = get_validation_config(
        data_2, validation_2, default_validation, JWTBaseModel
    )
    assert result_2.model == ModelB

    # Case 3: Pydantic + forward=False + model=None
    data_3 = ModelA(field_a="test")
    validation_3 = ValidationConfig(model=None, forward_pydantic_model=False)
    result_3 = get_validation_config(
        data_3, validation_3, default_validation, JWTBaseModel
    )
    assert result_3.model is None

    # Case 4: Pydantic + forward=False + model=Set
    data_4 = ModelA(field_a="test")
    validation_4 = ValidationConfig(model=ModelB, forward_pydantic_model=False)
    result_4 = get_validation_config(
        data_4, validation_4, default_validation, JWTBaseModel
    )
    assert result_4.model == ModelB

    # Case 5: Dict + forward=True + model=None
    data_5 = {"sub": "user123"}
    validation_5 = ValidationConfig(model=None, forward_pydantic_model=True)
    result_5 = get_validation_config(
        data_5, validation_5, default_validation, JWTBaseModel
    )
    assert result_5.model is None

    # Case 6: Dict + forward=True + model=Set
    data_6 = {"sub": "user123"}
    validation_6 = ValidationConfig(model=JWTClaims, forward_pydantic_model=True)
    result_6 = get_validation_config(
        data_6, validation_6, default_validation, JWTBaseModel
    )
    assert result_6.model == JWTClaims

    # Case 7: Dict + forward=False + model=None
    data_7 = {"sub": "user123"}
    validation_7 = ValidationConfig(model=None, forward_pydantic_model=False)
    result_7 = get_validation_config(
        data_7, validation_7, default_validation, JWTBaseModel
    )
    assert result_7.model is None

    # Case 8: Dict + forward=False + model=Set
    data_8 = {"sub": "user123"}
    validation_8 = ValidationConfig(model=JWTClaims, forward_pydantic_model=False)
    result_8 = get_validation_config(
        data_8, validation_8, default_validation, JWTBaseModel
    )
    assert result_8.model == JWTClaims


def test_get_validation_config_default_vs_custom():
    """Test key differences between Validation.DEFAULT and custom JWTValidation.

    Key differences:
    1. DEFAULT with pydantic+forward=True → forwards data type
    2. CUSTOM with explicit model → uses explicit model only
    3. DEFAULT uses default_validation's config values
    4. CUSTOM uses its own config values
    """
    data_pydantic = ModelA(field_a="test")
    data_dict = {"sub": "user123"}

    default_validation = ValidationConfig(
        model=JWTBaseModel,
        forward_pydantic_model=True,
        leeway=10.0,
    )

    # Scenario 1: DEFAULT with pydantic data forwards model type
    result_default_pydantic = get_validation_config(
        data_pydantic, Validation.DEFAULT, default_validation, JWTBaseModel
    )
    assert result_default_pydantic.model == ModelA
    assert result_default_pydantic.leeway == 10.0

    # Scenario 2: CUSTOM with explicit model uses explicit model
    custom_validation = ValidationConfig(
        model=JWTClaims,
        forward_pydantic_model=True,
        leeway=7.0,
    )
    result_custom_pydantic = get_validation_config(
        data_pydantic, custom_validation, default_validation, JWTBaseModel
    )
    assert result_custom_pydantic.model == JWTClaims  # NOT ModelA
    assert result_custom_pydantic.leeway == 7.0  # NOT 10.0

    # Scenario 3: DEFAULT with dict data uses default's model
    result_default_dict = get_validation_config(
        data_dict, Validation.DEFAULT, default_validation, JWTBaseModel
    )
    assert result_default_dict.model == JWTBaseModel
    assert result_default_dict.leeway == 10.0

    # Scenario 4: CUSTOM with dict data uses custom model
    result_custom_dict = get_validation_config(
        data_dict, custom_validation, default_validation, JWTBaseModel
    )
    assert result_custom_dict.model == JWTClaims
    assert result_custom_dict.leeway == 7.0


# ============================================================================
# Edge Cases
# ============================================================================


def test_get_validation_config_invalid_validation_type():
    """Test get_validation_config raises error for invalid validation type."""
    data = {"sub": "user123"}
    default_validation = ValidationConfig(model=JWTBaseModel)

    with pytest.raises(TypeError, match="Wrong validation object type"):
        get_validation_config(
            data=data,
            validation="invalid",  # type: ignore
            default_validation=default_validation,
            fallback_data_model=JWTBaseModel,
        )


def test_get_validation_config_with_data_model_tracking():
    """Test get_validation_config properly tracks data_model."""
    data_pydantic = ModelA(field_a="test")
    data_dict = {"sub": "user123"}
    default_validation = ValidationConfig(model=JWTBaseModel)

    result_pydantic = get_validation_config(
        data_pydantic, Validation.DEFAULT, default_validation, JWTBaseModel
    )
    assert result_pydantic.data_model == ModelA

    result_dict = get_validation_config(
        data_dict, Validation.DEFAULT, default_validation, JWTBaseModel
    )
    assert result_dict.data_model == JWTBaseModel
