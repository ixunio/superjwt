import secrets
from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import Field
from superjwt.definitions import Alg, JWTClaims, JWTDatetime
from superjwt.jws import JWS
from superjwt.jwt import JWT


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


class JWTCustomClaims(JWTClaims):
    # override sub as a mandatory field
    # sub: str --> this syntax triggers a Pylance[reportGeneralTypeIssues] error
    sub: str = Field(default=...)

    # add new custom claims
    user_id: str
    optional_id: int | None = None
    past_date: JWTDatetime | None = None
    future_date: JWTDatetime | None = None


def check_claims_instance(
    claim_before: JWTCustomClaims,
    claim_after: JWTCustomClaims,
    jwtdatetime_force_int: bool,
) -> None:
    assert claim_after.iss == claim_before.iss
    assert claim_after.sub == claim_before.sub
    assert claim_after.aud is None

    # Compare timestamps based on serialization mode
    if jwtdatetime_force_int is False:
        # Float mode: microseconds must be preserved exactly
        if claim_after.iat is not None and claim_before.iat is not None:
            assert float(claim_after.iat.timestamp()) == float(
                claim_before.iat.timestamp()
            )
        if claim_after.nbf is not None and claim_before.nbf is not None:
            assert float(claim_after.nbf.timestamp()) == float(
                claim_before.nbf.timestamp()
            )
        if claim_after.exp is not None and claim_before.exp is not None:
            assert float(claim_after.exp.timestamp()) == float(
                claim_before.exp.timestamp()
            )
    else:
        # Int mode: compare at second-level precision (microseconds truncated)
        if claim_after.iat is not None and claim_before.iat is not None:
            assert int(claim_after.iat.timestamp()) == int(claim_before.iat.timestamp())
        if claim_after.nbf is not None and claim_before.nbf is not None:
            assert int(claim_after.nbf.timestamp()) == int(claim_before.nbf.timestamp())
        if claim_after.exp is not None and claim_before.exp is not None:
            assert int(claim_after.exp.timestamp()) == int(claim_before.exp.timestamp())

    assert claim_after.jti is None
    assert claim_after.user_id == claim_before.user_id
    assert claim_after.optional_id is None


@pytest.fixture
def jwt() -> JWT:
    return JWT()


@pytest.fixture
def jws_HS256() -> JWS:  # noqa: N802
    return JWS(algorithm=Alg.HS256)


@pytest.fixture
def secret_key_random() -> str:
    return secrets.token_hex(32)


@pytest.fixture
def secret_key() -> str:
    return "test-secret-key-32-bytes-long!!"


@pytest.fixture
def sub() -> str:
    return "user123"


@pytest.fixture
def iss() -> str:
    return "issuer"


@pytest.fixture
def iat() -> float:
    return datetime.now(UTC).timestamp()


@pytest.fixture
def nbf() -> None: ...


@pytest.fixture
def exp() -> float:
    return datetime.strptime(
        "2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z"
    ).timestamp()


@pytest.fixture
def claims_dict(sub: str, iss: str, iat: float, nbf: float, exp: float) -> dict[str, Any]:
    return {
        "iss": iss,
        "sub": sub,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "user_id": "value",
        "past_date": (datetime.fromtimestamp(iat) - timedelta(days=1)).timestamp(),
        "future_date": (datetime.fromtimestamp(exp) + timedelta(days=1)).timestamp(),
    }


@pytest.fixture
def claims(claims_dict) -> JWTCustomClaims:
    return JWTCustomClaims(**claims_dict)


@pytest.fixture
def claims_fixed_dt() -> JWTCustomClaims:
    return JWTCustomClaims(user_id="123", iss="myapp", sub="someone").with_expiration(
        minutes=30
    )
