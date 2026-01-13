import pytest
from superjwt import inspect
from superjwt.algorithms import NoneAlgorithm
from superjwt.exceptions import (
    AlgorithmMismatchError,
    HeadersValidationError,
    InvalidAlgorithmError,
    SuperJWTError,
)
from superjwt.jws import JWS
from superjwt.keys import NoneKey, OctKey
from superjwt.validations import JOSEHeader, Validation

from .conftest import JWTCustomClaims


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


def test_encode_wrong_header_algorithm(
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

    # Even with validation disabled, we enforce consistency
    with pytest.raises(AlgorithmMismatchError):
        jws_HS256.encode(
            headers=headers,
            payload=claims_fixed_dt.to_dict(),
            key=key,
            headers_validation=Validation.DISABLE,
        )


def test_encode_algorithm_mismatch(
    jws_HS256: JWS, claims_fixed_dt: JWTCustomClaims, secret_key: str
):
    """Test that encoding with mismatched algorithm in headers raises error."""
    key = OctKey.import_key(secret_key)
    headers = {"alg": "HS512", "typ": "JWT"}

    with pytest.raises(AlgorithmMismatchError) as exc:
        jws_HS256.encode(
            headers=headers,
            payload=claims_fixed_dt.to_dict(),
            key=key,
        )
    assert "does not match" in str(exc.value)


def test_decode_algorithm_mismatch(jws_HS256: JWS, secret_key: str):
    """Test that decoding with mismatched algorithm in headers raises error."""
    compact = (
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
        "."
        "eyJpc3MiOiJ1c2VyLTEyMyJ9"
        "."
        "Mp0Pcwsz5VECK11Kf2ZZNF_SMKu5CgBeLN9ZOP04kZo"
    )
    assert inspect(compact).headers["alg"] == "HS512"
    with pytest.raises(AlgorithmMismatchError) as exc:
        jws_HS256.decode(compact, secret_key)
    assert "does not match" in str(exc.value)


def test_none_algorithm_not_allowed_decode():
    """Test that decoding with 'none' algorithm raises error when not explicitly allowed.

    Note: NoneAlgorithm is used internally for inspect() functionality but not exposed
    in the public Alg enum.
    """

    none_token = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
        "."
        "eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUifQ"
        "."
        "ZHVtbXk"
    )

    jws_none = JWS(algorithm=NoneAlgorithm())
    none_key = NoneKey()

    # Test decode with none algorithm not allowed
    with pytest.raises(InvalidAlgorithmError, match="None algorithm is not allowed"):
        jws_none.decode(compact=none_token, key=none_key)

    jws_none._allow_none_algorithm = True
    jws_none.reset()
    jws_none.decode(compact=none_token, key=none_key)  # Should not raise
    assert jws_none.token.unsafe.headers == {"alg": "none", "typ": "JWT"}
    assert jws_none.token.unsafe.payload == {"iss": "myapp", "sub": "someone"}


def test_none_algorithm_not_allowed_encode(claims_fixed_dt: JWTCustomClaims):
    """Test that encoding with 'none' algorithm raises error when not explicitly allowed.

    Note: NoneAlgorithm is used internally for inspect() functionality but not exposed
    in the public Alg enum.
    """
    jws_none = JWS(algorithm=NoneAlgorithm())
    none_key = NoneKey()

    # Test encode with none algorithm not allowed
    with pytest.raises(InvalidAlgorithmError, match="None algorithm is not allowed"):
        jws_none.encode(
            headers=JOSEHeader(alg="none"),
            payload=claims_fixed_dt.to_dict(),
            key=none_key,
        )

    # Test that it works when allowed
    jws_none._allow_none_algorithm = True
    jws_none.reset()
    token = jws_none.encode(
        headers=JOSEHeader(alg="none"),
        payload=claims_fixed_dt.to_dict(),
        key=none_key,
    )
    assert token.headers == {"alg": "none", "typ": "JWT"}
    assert token.payload == claims_fixed_dt.to_dict()
