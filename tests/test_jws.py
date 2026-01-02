import pytest
from superjwt.definitions import JOSEHeader, Validation
from superjwt.exceptions import (
    AlgorithmMismatchError,
    HeadersValidationError,
    InvalidHeadersError,
    SuperJWTError,
)
from superjwt.jws import JWS
from superjwt.keys import NoneKey, OctKey

from tests.conftest import JWTCustomClaims


def test_not_reset_jws_instance(
    jws_HS256: JWS, claims_fixed_dt: JWTCustomClaims, secret_key: str
):
    key = OctKey.import_key(secret_key)
    compact = jws_HS256.encode(
        headers=JOSEHeader(alg="HS256"),
        payload=claims_fixed_dt.to_dict(),
        key=key,
    ).compact

    # not reset JWS instance
    with pytest.raises(SuperJWTError):
        jws_HS256.encode(
            headers=JOSEHeader(alg="HS256"),
            payload=claims_fixed_dt.to_dict(),
            key=key,
        )
    with pytest.raises(SuperJWTError):
        jws_HS256.decode(compact=compact, key=key)

    jws_HS256.reset()
    decoded_claims_after_reset = jws_HS256.decode(compact=compact, key=key)
    assert decoded_claims_after_reset.payload == claims_fixed_dt.to_dict()


def test_wrong_header_algorithm(
    jws_HS256: JWS, claims_fixed_dt: JWTCustomClaims, secret_key: str
):
    key = OctKey.import_key(secret_key)
    headers = JOSEHeader(alg="HS256")
    headers.alg = "ABCDEF"  # wrong algorithm in header  # type: ignore

    with pytest.raises(HeadersValidationError):
        jws_HS256.encode(
            headers=headers,
            payload=claims_fixed_dt.to_dict(),
            key=key,
        )
    jws_HS256.reset()

    invalid_compact = jws_HS256.encode(
        headers=headers,
        payload=claims_fixed_dt.to_dict(),
        key=key,
        headers_validation=Validation.DISABLE,
    ).compact

    # not reset JWS instance
    with pytest.raises(SuperJWTError):
        jws_HS256.decode(
            compact=invalid_compact,
            key=key,
        )
    jws_HS256.reset()

    # header validation error, alg is not a valid algorithm
    with pytest.raises(InvalidHeadersError):
        jws_HS256.decode(compact=invalid_compact, key=key)
    jws_HS256.reset()

    # algorithm mismatch error
    with pytest.raises(AlgorithmMismatchError):
        jws_HS256.decode(
            compact=invalid_compact, key=key, headers_validation=Validation.DISABLE
        )
    jws_HS256.reset()


def test_none_algorithm_not_allowed(claims_fixed_dt: JWTCustomClaims):
    """Test that 'none' algorithm raises error when not explicitly allowed."""

    none_token = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
        "."
        "eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUifQ"
        "."
        "ZHVtbXk"
    )

    jws_none = JWS(algorithm="none")
    none_key = NoneKey()

    with pytest.raises(SuperJWTError, match="None algorithm is not allowed"):
        jws_none.decode(compact=none_token, key=none_key)

    jws_none._allow_none_algorithm = True
    jws_none.reset()
    jws_none.decode(compact=none_token, key=none_key)  # Should not raise
    assert jws_none.token.unsafe.headers == {"alg": "none", "typ": "JWT"}
    assert jws_none.token.unsafe.payload == {"iss": "myapp", "sub": "someone"}
