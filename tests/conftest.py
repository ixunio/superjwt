import secrets
from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import Field
from superjwt.definitions import JWTClaims
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
    sub: str = Field(default=...)

    # add new custom claims
    user_id: str
    optional_id: int | None = None

    # sub: str
    # this triggers Pylance[reportGeneralTypeIssues] error:
    # "overrides a field of the same name but is missing a default value"


def check_claims_instance(
    claim_before: JWTCustomClaims, claim_after: JWTCustomClaims
) -> None:
    assert claim_after.iss == claim_before.iss
    assert claim_after.sub == claim_before.sub
    assert claim_after.aud is None
    assert claim_after.iat == claim_before.iat
    assert claim_after.nbf == claim_before.nbf
    assert claim_after.exp == claim_before.exp
    assert claim_after.jti is None
    assert claim_after.user_id == claim_before.user_id
    assert claim_after.optional_id is None


@pytest.fixture
def jwt() -> JWT:
    return JWT()


@pytest.fixture
def jws_HS256() -> JWS:  # noqa: N802
    return JWS(algorithm="HS256")


@pytest.fixture
def secret_key_random() -> str:
    return secrets.token_hex(32)


@pytest.fixture
def secret_key() -> str:
    return "5297323b3f8f10e11f884e8079416f858010af256e5cc9dd67994743fcc3417d"


@pytest.fixture
def sub() -> str:
    return "user123"


@pytest.fixture
def iss() -> str:
    return "issuer"


@pytest.fixture
def iat() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def nbf(iat: datetime) -> float:
    return (iat + timedelta(days=30)).timestamp()


@pytest.fixture
def exp() -> datetime:
    return datetime.strptime("2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z")


@pytest.fixture
def claims_dict(
    sub: str, iss: str, iat: datetime, nbf: float, exp: datetime
) -> dict[str, Any]:
    return {
        "iss": iss,
        "sub": sub,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "user_id": "value",
    }


@pytest.fixture
def claims(claims_dict) -> JWTCustomClaims:
    return JWTCustomClaims(**claims_dict)


@pytest.fixture
def claims_fixed_dt() -> JWTCustomClaims:
    return JWTCustomClaims(
        user_id="123", iat=datetime.fromtimestamp(1899123456), iss="myapp", sub="someone"
    ).with_expiration(minutes=30)
