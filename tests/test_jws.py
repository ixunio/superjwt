import pytest
from superjwt.definitions import JOSEHeader, Validation
from superjwt.exceptions import (
    AlgorithmMismatchError,
    HeadersValidationError,
    InvalidHeadersError,
    SuperJWTError,
)
from superjwt.jws import JWS
from superjwt.keys import OctKey

from tests.conftest import JWTCustomClaims


def test_not_reset_jws_instance(
    jws_HS256: JWS, claims_fixed_dt: JWTCustomClaims, secret_key: str
):
    compact = (
        ""
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        "."
        "eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUiLCJpYXQiOjE4OTkxMjM0NTYsImV4cCI6MTg5OTEyNTI1NiwidXNlcl9pZCI6IjEyMyJ9"
        "."
        "7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )

    key = OctKey.import_key(secret_key)
    jws_HS256.encode(
        headers=JOSEHeader(alg="HS256"),
        payload=claims_fixed_dt.to_dict(),
        key=key,
    )

    # not reset JWS instance
    with pytest.raises(SuperJWTError):
        jws_HS256.decode(compact=compact, key=key)

    jws_HS256.reset()
    decoded_claims_after_reset = jws_HS256.decode(compact=compact, key=key)
    assert decoded_claims_after_reset.payload == claims_fixed_dt.to_dict()


def test_jws_hmac_decoding(jws_HS256: JWS, claims_fixed_dt, secret_key: str):
    compact = (
        ""
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        "."
        "eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUiLCJpYXQiOjE4OTkxMjM0NTYsImV4cCI6MTg5OTEyNTI1NiwidXNlcl9pZCI6IjEyMyJ9"
        "."
        "7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )

    key = OctKey.import_key(secret_key)
    decoded_claims = JWTCustomClaims(**jws_HS256.decode(compact=compact, key=key).payload)
    assert decoded_claims.to_dict() == claims_fixed_dt.to_dict()


def test_wrong_header_algorithm(
    jws_HS256: JWS, claims_fixed_dt: JWTCustomClaims, secret_key: str
):
    compact = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        "."
        "eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUiLCJpYXQiOjE4OTkxMjM0NTYsImV4cCI6MTg5OTEyNTI1NiwidXNlcl9pZCI6IjEyMyJ9"
        "."
        "7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )

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

    decoded_claims = JWTCustomClaims(**jws_HS256.decode(compact=compact, key=key).payload)
    assert decoded_claims.to_dict() == claims_fixed_dt.to_dict()
