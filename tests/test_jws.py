import pytest
from superjwt.definitions import JOSEHeader
from superjwt.exceptions import InvalidHeaderError
from superjwt.jws import JWS
from superjwt.keys import OctetKey

from tests.conftest import JWTCustomClaims


def test_jws_hmac_decoding(jws_HS256: JWS, claims_fixed_dt, secret_key: str):
    compact = (
        ""
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        "."
        "eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUiLCJpYXQiOjE4OTkxMjM0NTYsImV4cCI6MTg5OTEyNTI1NiwidXNlcl9pZCI6IjEyMyJ9"
        "."
        "7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )

    key = OctetKey.import_key(secret_key)
    decoded_claims = JWTCustomClaims(
        **jws_HS256.decode(token=compact, key=key).decoded.payload
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

    key = OctetKey.import_key(secret_key)
    headers = JOSEHeader(alg="HS256")
    headers.alg = "ABCDEF"  # wrong algorithm in header  # type: ignore
    invalid_compact = jws_HS256.encode(
        header=headers, payload=claims_fixed_dt, key=key
    ).decode("utf-8")

    with pytest.raises(InvalidHeaderError):
        jws_HS256.decode(token=invalid_compact, key=key)

    jws_token = jws_HS256.decode(
        token=invalid_compact, key=key, disable_headers_validation=True
    )
    assert jws_token.decoded.header["alg"] == headers.alg
    decoded_claims = JWTCustomClaims(
        **jws_HS256.decode(token=compact, key=key).decoded.payload
    )
    assert decoded_claims.to_dict() == claims_fixed_dt.to_dict()
