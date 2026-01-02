from datetime import datetime, timedelta

import pydantic
import pytest
from superjwt.definitions import (
    JWTClaims,
)
from superjwt.exceptions import (
    TokenExpiredError,
    TokenNotYetValidError,
)


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


def test_validate_exp_with_datetime_input():
    """Test validate_exp field validator with datetime input."""
    now = datetime.now(UTC).replace(microsecond=0)

    # exp=None
    claims_none = JWTClaims.model_validate({"exp": None})
    assert claims_none.exp is None

    # exp in future
    future_exp = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=1)
    claims = JWTClaims(exp=future_exp)
    assert claims.exp == future_exp

    # exp equal to now (expired)
    current_time = datetime.now(UTC).replace(microsecond=0)
    with pytest.raises(TokenExpiredError):
        JWTClaims(exp=current_time)

    # exp in past (expired)
    past_exp = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    with pytest.raises(TokenExpiredError):
        JWTClaims(exp=past_exp)

    # exp > iat
    iat_time = now - timedelta(days=1)
    exp_time = now + timedelta(hours=1)
    claims_with_iat = JWTClaims(iat=iat_time, exp=exp_time)
    assert claims_with_iat.exp == exp_time
    assert claims_with_iat.iat == iat_time

    # exp <= iat
    with pytest.raises(
        pydantic.ValidationError,
        match="'exp' claim must be strictly greater than 'iat' claim",
    ):
        JWTClaims(iat=now, exp=now)


def test_validate_exp_with_timestamp_input():
    """Test validate_exp field validator with int/float timestamp input."""
    now = datetime.now(UTC).replace(microsecond=0)

    # exp as int timestamp
    future_timestamp_int = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    claims = JWTClaims(exp=future_timestamp_int)  # type: ignore[arg-type]
    assert claims.exp == datetime.fromtimestamp(future_timestamp_int, tz=UTC).replace(
        microsecond=0
    )

    # exp as float timestamp
    future_timestamp_float = (datetime.now(UTC) + timedelta(hours=1)).timestamp()
    claims_float = JWTClaims(exp=future_timestamp_float)  # type: ignore[arg-type]
    assert claims_float.exp == datetime.fromtimestamp(
        future_timestamp_float, tz=UTC
    ).replace(microsecond=0)

    # exp in past
    past_timestamp = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
    with pytest.raises(TokenExpiredError):
        JWTClaims(exp=past_timestamp)  # type: ignore[arg-type]

    # exp > iat
    iat_time = now - timedelta(days=1)
    exp_timestamp_int = int((now + timedelta(hours=1)).timestamp())
    claims_with_iat = JWTClaims(iat=iat_time, exp=exp_timestamp_int)  # type: ignore[arg-type]
    assert claims_with_iat.exp == datetime.fromtimestamp(
        exp_timestamp_int, tz=UTC
    ).replace(microsecond=0)

    # exp <= iat
    iat_timestamp = now
    exp_equal_iat = int(now.timestamp())
    with pytest.raises(
        pydantic.ValidationError,
        match="'exp' claim must be strictly greater than 'iat' claim",
    ):
        JWTClaims(iat=iat_timestamp, exp=exp_equal_iat)  # type: ignore[arg-type]


def test_validate_nbf_with_datetime_input():
    """Test validate_nbf field validator with datetime input."""
    # nbf in past
    past_nbf = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    claims = JWTClaims(nbf=past_nbf)
    assert claims.nbf == past_nbf

    # nbf equal to now
    current_time = datetime.now(UTC).replace(microsecond=0)
    claims_now = JWTClaims(nbf=current_time)
    assert claims_now.nbf == current_time

    # nbf in future
    future_nbf = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=1)
    with pytest.raises(TokenNotYetValidError):
        JWTClaims(nbf=future_nbf)

    # nbf <= iat
    now = datetime.now(UTC).replace(microsecond=0)
    with pytest.raises(
        pydantic.ValidationError,
        match="'nbf' claim must be strictly greater than 'iat' claim",
    ):
        JWTClaims(iat=now, nbf=now)

    # Test with_issued_at() preserving exp delta (lines 305-306 in definitions.py)
    claims_with_both = JWTClaims(
        iat=now - timedelta(hours=2), exp=now + timedelta(hours=2)
    )
    updated = claims_with_both.with_issued_at()
    assert updated.iat is not None and updated.iat >= now  # New iat is current time
    assert updated.exp is not None
    assert (updated.exp - updated.iat) == timedelta(hours=4)  # Delta preserved


def test_validate_nbf_with_timestamp_input():
    """Test validate_nbf field validator with int/float timestamp input."""
    now = datetime.now(UTC).replace(microsecond=0)

    # nbf as int timestamp
    past_timestamp_int = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
    claims = JWTClaims(nbf=past_timestamp_int)  # type: ignore[arg-type]
    assert claims.nbf == datetime.fromtimestamp(past_timestamp_int, tz=UTC).replace(
        microsecond=0
    )

    # nbf as float timestamp
    past_timestamp_float = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
    claims_float = JWTClaims(nbf=past_timestamp_float)  # type: ignore[arg-type]
    assert claims_float.nbf == datetime.fromtimestamp(
        past_timestamp_float, tz=UTC
    ).replace(microsecond=0)

    # nbf in future
    future_timestamp = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    with pytest.raises(TokenNotYetValidError):
        JWTClaims(nbf=future_timestamp)  # type: ignore[arg-type]

    # nbf <= iat
    iat_timestamp = now
    nbf_equal_iat = int(now.timestamp())
    with pytest.raises(
        pydantic.ValidationError,
        match="'nbf' claim must be strictly greater than 'iat' claim",
    ):
        JWTClaims(iat=iat_timestamp, nbf=nbf_equal_iat)  # type: ignore[arg-type]


def test_check_exp_after_nbf_model_validator():
    """Test check_exp_after_nbf model validator ensures nbf < exp."""
    # nbf < exp
    nbf_ts = int((datetime.now(UTC) - timedelta(days=90)).timestamp())
    exp_ts = int((datetime.now(UTC) + timedelta(days=90)).timestamp())
    claims = JWTClaims(nbf=nbf_ts, exp=exp_ts)  # type: ignore[arg-type]
    assert claims.nbf is not None and claims.exp is not None
    assert claims.nbf < claims.exp

    # nbf >= exp with iat=None
    now = datetime.now(UTC).replace(microsecond=0)

    # Make both in future but inverted: nbf > exp
    future_nbf = now + timedelta(days=2)
    future_exp = now + timedelta(days=1)

    # This will fail on nbf field validator (nbf in future)
    with pytest.raises(TokenNotYetValidError):
        JWTClaims(nbf=future_nbf, exp=future_exp, iat=None)

    # Try both in past but inverted
    past_nbf = now - timedelta(days=1)
    past_exp = now - timedelta(days=2)

    # This will fail on exp field validator (exp in past)
    with pytest.raises(TokenExpiredError):
        JWTClaims(nbf=past_nbf, exp=past_exp, iat=None)


def test_spoof_time_with_method():
    """Test time spoofing using the spoof_time() method."""
    fixed_time = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)

    claims = JWTClaims()
    claims.spoof_time(fixed_time)
    assert claims.now == fixed_time
    assert claims.internal__now == fixed_time

    # Test that exp validation uses spoofed time
    claims_with_exp = JWTClaims.model_construct(exp=fixed_time + timedelta(hours=1))
    claims_with_exp.spoof_time(fixed_time)
    claims_with_exp.revalidate()
    assert claims_with_exp.exp == fixed_time + timedelta(hours=1)

    # Setting exp equal to fixed_time should raise TokenExpiredError
    expired_claims = JWTClaims.model_construct(exp=fixed_time)
    expired_claims.spoof_time(fixed_time)
    with pytest.raises(TokenExpiredError):
        expired_claims.revalidate()

    # Revert to normal time
    claims.spoof_time(None)
    assert claims.now != fixed_time  # Should be close to actual current time


def test_spoof_time_with_exp_validation():
    """Test exp validation with spoofed time."""
    fixed_time = datetime(2025, 3, 10, 15, 0, 0, tzinfo=UTC)

    # Test valid exp in the future (relative to spoofed time)
    future_exp = fixed_time + timedelta(days=30)
    claims = JWTClaims.model_construct(exp=future_exp)
    claims.spoof_time(fixed_time)
    claims.revalidate()
    assert claims.exp == future_exp

    # Test expired token (exp in the past relative to spoofed time)
    past_exp = fixed_time - timedelta(days=1)
    past_claims = JWTClaims.model_construct(exp=past_exp)
    past_claims.spoof_time(fixed_time)
    with pytest.raises(TokenExpiredError):
        past_claims.revalidate()


def test_spoof_time_with_nbf_validation():
    """Test nbf validation with spoofed time."""
    fixed_time = datetime(2025, 4, 20, 8, 0, 0, tzinfo=UTC)

    # Test valid nbf in the past (relative to spoofed time)
    past_nbf = fixed_time - timedelta(hours=2)
    claims = JWTClaims.model_construct(nbf=past_nbf)
    claims.spoof_time(fixed_time)
    claims.revalidate()
    assert claims.nbf == past_nbf

    # Test nbf equal to spoofed time
    claims_now = JWTClaims.model_construct(nbf=fixed_time)
    claims_now.spoof_time(fixed_time)
    claims_now.revalidate()
    assert claims_now.nbf == fixed_time

    # Test nbf in the future (relative to spoofed time)
    future_nbf = fixed_time + timedelta(hours=1)
    future_claims = JWTClaims.model_construct(nbf=future_nbf)
    future_claims.spoof_time(fixed_time)
    with pytest.raises(TokenNotYetValidError):
        future_claims.revalidate()


def test_spoof_time_with_iat_exp_relationship():
    """Test iat and exp relationship with spoofed time."""
    fixed_time = datetime(2025, 2, 14, 14, 0, 0, tzinfo=UTC)

    # Create claims with iat in past and exp in future (relative to spoofed time)
    iat_time = fixed_time - timedelta(days=1)
    exp_time = fixed_time + timedelta(days=1)

    claims = JWTClaims.model_construct(iat=iat_time, exp=exp_time)
    claims.spoof_time(fixed_time)
    claims.revalidate()

    assert claims.iat == iat_time
    assert claims.exp == exp_time

    # Test with_issued_at() uses spoofed time
    claims_with_iat = JWTClaims()
    claims_with_iat.spoof_time(fixed_time)
    updated_claims = claims_with_iat.with_issued_at()
    assert updated_claims.iat == fixed_time


def test_spoof_time_with_expiration_method():
    """Test with_expiration() method with spoofed time."""
    fixed_time = datetime(2025, 5, 1, 12, 0, 0, tzinfo=UTC)

    claims = JWTClaims()
    claims.spoof_time(fixed_time)

    # Add expiration relative to spoofed time
    claims_with_exp = claims.with_expiration(hours=2)
    expected_exp = fixed_time + timedelta(hours=2)

    assert claims_with_exp.exp == expected_exp
    # Note: with_expiration() only sets iat if it was already set
    # Since we started with empty claims, iat remains None
    assert claims_with_exp.iat is None

    # Test with iat already set
    claims_with_iat = JWTClaims(iat=fixed_time - timedelta(days=1))
    claims_with_iat.spoof_time(fixed_time)
    claims_with_both = claims_with_iat.with_expiration(hours=2)
    assert claims_with_both.exp == expected_exp
    assert claims_with_both.iat == fixed_time


def test_spoof_time_revert_to_normal():
    """Test reverting from spoofed time back to normal time."""
    fixed_time = datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)

    claims = JWTClaims()
    claims.spoof_time(fixed_time)
    assert claims.now == fixed_time

    # Revert
    claims.spoof_time(None)
    current_actual_time = datetime.now(UTC).replace(microsecond=0)
    time_diff = abs((claims.now - current_actual_time).total_seconds())
    assert time_diff < 2  # Within 2 seconds tolerance
