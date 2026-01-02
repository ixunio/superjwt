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
from superjwt.jwt import JWT


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


def test_check_exp_after_nbf_model_validator(jwt: JWT, secret_key: str):
    """Test check_exp_after_nbf model validator ensures nbf < exp."""
    # nbf < exp
    nbf_ts = int((datetime.now(UTC) - timedelta(days=90)).timestamp())
    exp_ts = int((datetime.now(UTC) + timedelta(days=90)).timestamp())
    claims = JWTClaims(nbf=nbf_ts, exp=exp_ts)  # type: ignore[arg-type]
    assert claims.nbf is not None and claims.exp is not None
    assert claims.nbf < claims.exp

    # nbf >= exp
    now = datetime.now(UTC).replace(microsecond=0)
    unvalidated_claims = JWTClaims.model_construct(
        nbf=now + timedelta(days=1),
        exp=now - timedelta(days=1),
    )
    with pytest.raises(
        ValueError, match="'nbf' claim must be strictly less than 'exp' claim"
    ):
        JWTClaims.model_validate(unvalidated_claims)

    # only exp set
    future_exp = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=1)
    claims_exp_only = JWTClaims(exp=future_exp)
    assert claims_exp_only.exp is not None
    assert claims_exp_only.nbf is None

    # only nbf set
    past_nbf = datetime.now(UTC).replace(microsecond=0) - timedelta(days=180)
    claims_nbf_only = JWTClaims(nbf=past_nbf)
    assert claims_nbf_only.nbf is not None
    assert claims_nbf_only.exp is None
