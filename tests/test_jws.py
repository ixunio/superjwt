import pytest
from superjwt.definitions import DefaultHeadersValidationModel, JOSEHeader
from superjwt.exceptions import InvalidHeaderError, JWTError
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
        payload=claims_fixed_dt,
        key=key,
        headers_validation_model=DefaultHeadersValidationModel,
    )

    # not reset JWS instance
    with pytest.raises(JWTError):
        jws_HS256.decode(
            token=compact, key=key, headers_validation_model=DefaultHeadersValidationModel
        )

    jws_HS256.reset()
    decoded_claims_after_reset = jws_HS256.decode(
        token=compact, key=key, headers_validation_model=DefaultHeadersValidationModel
    )
    assert decoded_claims_after_reset.decoded.payload == claims_fixed_dt.to_dict()


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
    decoded_claims = JWTCustomClaims(
        **jws_HS256.decode(
            token=compact, key=key, headers_validation_model=DefaultHeadersValidationModel
        ).decoded.payload
    )
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
    invalid_compact = jws_HS256.encode(
        headers=headers, payload=claims_fixed_dt, key=key, headers_validation_model=None
    ).decode("utf-8")

    # not reset JWS instance
    with pytest.raises(JWTError):
        jws_HS256.decode(
            token=invalid_compact,
            key=key,
            headers_validation_model=DefaultHeadersValidationModel,
        )

    jws_HS256.reset()
    with pytest.raises(InvalidHeaderError):
        jws_HS256.decode(
            token=invalid_compact,
            key=key,
            headers_validation_model=DefaultHeadersValidationModel,
        )
    jws_HS256.reset()
    jws_token = jws_HS256.decode(
        token=invalid_compact, key=key, headers_validation_model=None
    )
    assert jws_token.decoded.headers["alg"] == headers.alg

    jws_HS256.reset()
    decoded_claims = JWTCustomClaims(
        **jws_HS256.decode(
            token=compact, key=key, headers_validation_model=DefaultHeadersValidationModel
        ).decoded.payload
    )
    assert decoded_claims.to_dict() == claims_fixed_dt.to_dict()
