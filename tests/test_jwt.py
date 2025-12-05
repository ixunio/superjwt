from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pydantic
import pytest
from superjwt import decode, encode
from superjwt.exceptions import (
    ClaimsValidationError,
    SignatureVerificationFailedError,
)
from superjwt.jwt import JWT

from tests.conftest import JWTCustomClaims, check_claims_instance


if TYPE_CHECKING:
    from superjwt.definitions import Algorithm


def test_encode_decode_default_claims(secret_key):
    token = encode(claims=None, key=secret_key)
    decoded_claims = decode(token=token, key=secret_key)
    assert decoded_claims == {}


def test_encode_decode_dict_claims(claims_dict, secret_key):
    token = encode(claims=claims_dict, key=secret_key)
    decoded_claims_dict = decode(token=token, key=secret_key)

    assert decoded_claims_dict["iss"] == claims_dict["iss"]
    assert decoded_claims_dict["sub"] == claims_dict["sub"]
    assert decoded_claims_dict.get("aud") is None
    assert decoded_claims_dict["iat"] == int(claims_dict["iat"].timestamp())
    assert decoded_claims_dict["nbf"] == int(claims_dict["nbf"])
    assert decoded_claims_dict["exp"] == int(claims_dict["exp"].timestamp())
    assert decoded_claims_dict.get("jti") is None
    assert decoded_claims_dict["user_id"] == claims_dict["user_id"]
    assert decoded_claims_dict.get("optional_id") is None


def test_encode_decode_pydantic_claims(
    jwt: JWT, claims_dict: dict[str, Any], secret_key: str
):
    claims = JWTCustomClaims(**claims_dict)

    token = jwt.encode(claims=claims, key=secret_key)
    decoded_claims = JWTCustomClaims(**jwt.decode(token=token, key=secret_key))

    check_claims_instance(claims, decoded_claims)


def test_decode_invalid_signature(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    wrong_key = "wrongkey_but_long_enough"
    token = jwt.encode(claims=claims, key=secret_key)

    with pytest.raises(SignatureVerificationFailedError):
        jwt.decode(token=token, key=wrong_key)


def test_hmac_algorithms(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    hmac_algorithms: list[Algorithm] = ["HS256", "HS384", "HS512"]

    for alg in hmac_algorithms:
        token = jwt.encode(claims=claims, key=secret_key, algorithm=alg)
        decoded_claims = JWTCustomClaims(
            **jwt.decode(token=token, key=secret_key, algorithm=alg)
        )

        check_claims_instance(claims, decoded_claims)


def test_encode_decode_claims_validation_disabled(
    jwt: JWT, claims: JWTCustomClaims, secret_key_random: str
):
    # prepare an invalid claims pydantic instance
    unvalidated_claims = JWTCustomClaims.model_construct(
        **claims.to_dict()
    )  # zero validation (even for datetime)
    unvalidated_claims.sub = 1  # invalid type for sub  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims=unvalidated_claims, key=secret_key_random)
    encoded = jwt.encode(
        unvalidated_claims, secret_key_random, disable_claims_validation=True
    )
    with pytest.raises(ClaimsValidationError):
        jwt.decode(token=encoded, key=secret_key_random)
    decoded = jwt.decode(
        token=encoded, key=secret_key_random, disable_claims_validation=True
    )
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims.sub  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime
    check_claims_instance(claims, decoded_claims)


def test_encode_decode_claims_dict_validation_disabled(
    jwt: JWT, claims_dict: dict[str, Any], secret_key_random: str
):
    # prepare an invalid claims dict
    unvalidated_claims_dict = claims_dict.copy()
    unvalidated_claims_dict["sub"] = 1  # invalid type for sub
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims=unvalidated_claims_dict, key=secret_key_random)
    # run encoding again with validation disabled, does not raise error
    encoded = jwt.encode(
        unvalidated_claims_dict, secret_key_random, disable_claims_validation=True
    )
    with pytest.raises(ClaimsValidationError):
        jwt.decode(token=encoded, key=secret_key_random)
    # run decoding again with validation disabled, does not raise error
    decoded = jwt.decode(
        token=encoded, key=secret_key_random, disable_claims_validation=True
    )
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims_dict["sub"]  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime
    claims = JWTCustomClaims(**claims_dict)  # the original claims data
    check_claims_instance(claims, decoded_claims)


def test_required_field_missing(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    claims.sub = None  # remove required field 'sub'  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims=claims, key=secret_key)
    encoded = jwt.encode(claims, secret_key, disable_claims_validation=True)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(token=encoded, key=secret_key)
    decoded = jwt.decode(token=encoded, key=secret_key, disable_claims_validation=True)
    with pytest.raises(pydantic.ValidationError):
        JWTCustomClaims(**decoded)


def test_invalid_claims_future_dates(jwt: JWT, secret_key: str):
    now = datetime.now(UTC)

    # exp <= iat is invalid
    claims_dict = {"sub": "user123", "iat": now, "exp": now - timedelta(minutes=5)}
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims=claims_dict, key=secret_key)

    # nbf <= iat is invalid
    claims_dict = {"sub": "user123", "iat": now, "nbf": now - timedelta(minutes=5)}
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims=claims_dict, key=secret_key)

    # nbf >= exp is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now,
        "nbf": now + timedelta(days=5),
        "exp": now + timedelta(minutes=5),
    }
    with pytest.raises(ClaimsValidationError):
        encode(claims=claims_dict, key=secret_key)


def test_claims_type_error(jwt: JWT, secret_key: str):
    with pytest.raises(TypeError):
        jwt.encode(claims="not_a_dict_or_jwtclaims", key=secret_key)  # type: ignore


def test_unsafe_inspect(jwt: JWT, claims_fixed_dt, secret_key: str):
    forged_claims = claims_fixed_dt.model_copy()
    forged_claims.sub = "someone-else"

    # original valid token
    compact = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b"."
        b"eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUiLCJpYXQiOjE4OTkxMjM0NTYsImV4cCI6MTg5OTEyNTI1NiwidXNlcl9pZCI6IjEyMyJ9"
        b"."
        b"7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )

    # forged token with sub = "someone-else"
    forged_compact = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b"."
        b"eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUtZWxzZSIsImlhdCI6MTg5OTEyMzQ1NiwiZXhwIjoxODk5MTI1MjU2LCJ1c2VyX2lkIjoiMTIzIn0"
        b"."
        b"7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )

    encoded_token = jwt.encode(claims=claims_fixed_dt, key=secret_key)
    assert encoded_token.rsplit(b".", 1)[0] == compact.rsplit(b".", 1)[0]

    decoded_claims = jwt.decode(token=compact, key=secret_key)
    assert decoded_claims["sub"] == claims_fixed_dt.sub

    # check the JWT was tampered with
    with pytest.raises(SignatureVerificationFailedError):
        jwt.decode(token=forged_compact, key=secret_key)

    # decode with no signature verification
    unsafe_token = jwt.inspect(token=forged_compact)
    assert unsafe_token.decoded.payload["sub"] == forged_claims.sub


def test_detached_payload(jwt: JWT, claims_fixed_dt, secret_key):
    encoded_token = jwt.encode(claims=claims_fixed_dt, key=secret_key)
    encoded_token_detached = jwt.detach_payload()

    full_compact = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b"."
        b"eyJpc3MiOiJteWFwcCIsInN1YiI6InNvbWVvbmUiLCJpYXQiOjE4OTkxMjM0NTYsImV4cCI6MTg5OTEyNTI1NiwidXNlcl9pZCI6IjEyMyJ9"
        b"."
        b"7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )

    detached_compact = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b"."
        b"."
        b"7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )

    assert full_compact == encoded_token
    assert detached_compact == encoded_token_detached

    decoded = jwt.decode(
        detached_compact, secret_key, with_detached_payload=claims_fixed_dt
    )
    assert decoded == claims_fixed_dt.to_dict()

    decoded = jwt.decode(
        detached_compact, secret_key, with_detached_payload=claims_fixed_dt.to_dict()
    )
    assert decoded == claims_fixed_dt.to_dict()
    # todo: change to to_dict() everywhere
