import json
from datetime import datetime, timedelta
from typing import Any

import pydantic
import pytest
from superjwt import decode, encode, inspect
from superjwt.definitions import (
    Alg,
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    JWTDatetime,
    JWTDatetimeFloat,
    JWTDatetimeInt,
    JWTValidation,
    Validation,
)
from superjwt.exceptions import (
    ClaimsValidationError,
    HeadersValidationError,
    InvalidHeadersError,
    InvalidPayloadError,
    InvalidTokenError,
    SignatureVerificationFailedError,
    SizeExceededError,
    SuperJWTError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from superjwt.jwt import JWT
from superjwt.utils import urlsafe_b64encode

from tests.conftest import JWTCustomClaims, check_claims_instance


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


def test_encode_decode_default_claims(secret_key):
    # Test with string for backward compatibility
    compact = encode(None, secret_key, "HS256")
    decoded_claims = decode(compact, secret_key, "HS256")
    assert decoded_claims == {}


def test_encode_decode_dict_claims(claims_dict, secret_key):
    compact = encode(claims_dict, secret_key, Alg.HS256)
    decoded_claims_dict = decode(compact, secret_key, Alg.HS256)

    # standard claims
    assert decoded_claims_dict["iss"] == claims_dict["iss"]
    assert decoded_claims_dict["sub"] == claims_dict["sub"]
    assert decoded_claims_dict.get("aud") is None
    assert decoded_claims_dict.get("jti") is None

    # standard claims (datetime data with various input types)
    # they will be serialized uniformly as int (timestamp) thanks to JWTClaims validation
    assert decoded_claims_dict["iat"] == claims_dict["iat"]
    assert decoded_claims_dict["nbf"] == claims_dict["nbf"]
    assert decoded_claims_dict["exp"] == claims_dict["exp"]

    # custom claims
    # won't be any type conversion here, nor validation
    assert decoded_claims_dict["user_id"] == claims_dict["user_id"]
    assert decoded_claims_dict.get("optional_id") is None


def test_encode_decode_dict_custom_datetime_claim(secret_key):
    # custom datetime claim from dict cannot be validated without pydantic
    # it MUST be serializable
    # it SHOULD be an int timestamp
    custom_dt_unserializable = {
        "custom_date": datetime.strptime(
            "2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z"
        ),
    }
    custom_dt_serializable_str = {"custom_date": "2042-04-02T:00:42:42.123456+0000"}
    custom_dt_correct = {
        "custom_date": int(
            datetime.strptime(
                "2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z"
            ).timestamp()
        ),
    }

    # cannot encode unserializable datetime
    with pytest.raises(TypeError):
        encode({"custom_date": custom_dt_unserializable}, secret_key, Alg.HS256)

    # can encode serializable datetime string, this will not be serialized as a timestamp
    # unlike the standard datetime claims (iat, nbf, exp)
    compact = encode({"custom_date": custom_dt_serializable_str}, secret_key, Alg.HS256)
    decoded = decode(compact, secret_key, Alg.HS256)
    assert decoded["custom_date"] == custom_dt_serializable_str

    # can encode integer timestamp
    compact = encode({"custom_date": custom_dt_correct}, secret_key, Alg.HS256)
    decoded = decode(compact, secret_key, Alg.HS256)
    assert decoded["custom_date"] == custom_dt_correct


def test_add_iat_add_exp(secret_key):
    # custom datetime claim set to None should be handled correctly
    claims = JWTClaims().with_issued_at().with_expiration(minutes=30)
    compact = encode(claims, secret_key, Alg.HS256)
    decoded = decode(compact, secret_key, Alg.HS256)
    assert "iat" in decoded
    assert "exp" in decoded


def test_empty_iat_with_exp(secret_key):
    # custom datetime claim set to None should be handled correctly
    claims = JWTClaims(
        iat=None,
        exp=datetime.strptime(
            "2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z"
        ),
    )
    compact = encode(claims, secret_key, Alg.HS256)
    decoded = decode(compact, secret_key, Alg.HS256)
    assert "iat" not in decoded


def test_with_expiration_negative():
    # custom datetime claim set to invalid type should be handled correctly
    with pytest.raises(ValueError):
        JWTClaims().with_expiration(minutes=-15)


def test_rewrite_incorrect_exp_type():
    class JWTIncorrectExpClaim(JWTClaims):
        exp: JWTDatetime  # type: ignore

    with pytest.raises(pydantic.ValidationError):
        JWTIncorrectExpClaim(exp=True)  # type: ignore


def test_encode_decode_pydantic_claims(
    jwt: JWT, claims_dict: dict[str, Any], secret_key: str
):
    claims = JWTCustomClaims(**claims_dict)

    compact = jwt.encode(claims, secret_key, Alg.HS256).compact
    decoded_claims = JWTCustomClaims(**jwt.decode(compact, secret_key, Alg.HS256).payload)

    check_claims_instance(claims, decoded_claims, jwtdatetime_force_int=True)

    # test non compliant claims
    claims = JWTCustomClaims(**claims_dict)
    claims.aud = 123  # invalid type for aud  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256)

    # test custom claims model validation
    claims = JWTCustomClaims(**claims_dict)
    # encoding valid
    jws_token = jwt.encode(claims, secret_key, Alg.HS256)
    jws_token2 = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=JWTCustomClaims
    )
    assert jws_token.compact == jws_token2.compact
    # decoding
    claims.user_id = None  # invalid type for user_id  # type: ignore
    compact = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact
    # passes (validation with default JWTClaims)
    jwt.decode(compact, secret_key, Alg.HS256)
    # fails (validation with JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(compact, secret_key, Alg.HS256, claims_validation=JWTCustomClaims)


def test_decode_invalid_signature(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    wrong_key = "wrongkey_but_long_enough"
    compact = jwt.encode(claims, secret_key, Alg.HS256).compact

    with pytest.raises(SignatureVerificationFailedError):
        jwt.decode(compact, wrong_key, Alg.HS256)


def test_hmac_algorithms(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    hmac_algorithms = [Alg.HS256, Alg.HS384, Alg.HS512]

    for alg in hmac_algorithms:
        token = jwt.encode(claims, secret_key, alg).compact
        decoded_claims = JWTCustomClaims(**jwt.decode(token, secret_key, alg).payload)

        check_claims_instance(claims, decoded_claims, jwtdatetime_force_int=True)


def test_encode_decode_claims_validation_disabled(
    jwt: JWT, claims: JWTCustomClaims, secret_key_random: str
):
    # prepare an invalid claims pydantic instance
    unvalidated_claims = JWTCustomClaims.model_construct(
        **claims.to_dict()
    )  # zero validation (even for datetime)
    unvalidated_claims.sub = 1  # invalid type for sub  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(unvalidated_claims, secret_key_random, Alg.HS256)
    compact = jwt.encode(
        unvalidated_claims,
        secret_key_random,
        Alg.HS256,
        claims_validation=Validation.DISABLE,
    ).compact

    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact, secret_key_random, Alg.HS256, claims_validation=JWTCustomClaims
        )
    jwt.decode(compact, secret_key_random, Alg.HS256)  # passes (no validation)
    decoded = jwt.decode(
        compact, secret_key_random, Alg.HS256, claims_validation=Validation.DISABLE
    ).payload
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims.sub  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime
    check_claims_instance(claims, decoded_claims, jwtdatetime_force_int=True)


def test_encode_decode_claims_dict_validation_disabled(
    jwt: JWT, claims_dict: dict[str, Any], exp: float, secret_key_random: str
):
    # prepare an invalid claims dict
    unvalidated_claims_dict = claims_dict.copy()
    unvalidated_claims_dict["sub"] = 1  # invalid type for sub
    jwt.encode(
        unvalidated_claims_dict, secret_key_random, Alg.HS256
    )  # passes (no encode validation as dict)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            unvalidated_claims_dict,
            secret_key_random,
            Alg.HS256,
            claims_validation=JWTClaims,
        )
    # run encoding again with validation disabled, does not raise error
    compact = jwt.encode(
        unvalidated_claims_dict,
        secret_key_random,
        Alg.HS256,
        claims_validation=Validation.DISABLE,
    ).compact
    jwt.decode(
        compact, secret_key_random, Alg.HS256
    )  # passes (no decode validation as dict)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(compact, secret_key_random, Alg.HS256, claims_validation=JWTClaims)
    # run decoding again with validation disabled, does not raise error
    decoded = jwt.decode(
        compact, secret_key_random, Alg.HS256, claims_validation=Validation.DISABLE
    ).payload
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims_dict["sub"]  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime as int timestamp
    claims = JWTCustomClaims(**claims_dict)  # the original claims data
    check_claims_instance(claims, decoded_claims, jwtdatetime_force_int=True)


def test_custom_claims_validation(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    # test with a wrong object type for claims_validation
    with pytest.raises(TypeError):
        jwt.encode(claims, secret_key, Alg.HS256, claims_validation="not_a_model")  # type: ignore

    claims.sub = None  # remove required field 'sub'  # type: ignore

    jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=JWTClaims
    )  # passes because compliant with JWTClaims
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256, claims_validation=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims, secret_key, Alg.HS256
        )  # same as claims_validation=JWTCustomClaims (pydantic object is validated by default)

    claims.aud = 123  # invalid registered claim  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims, secret_key, Alg.HS256, claims_validation=JWTClaims
        )  # no more compliant with JWTClaims (aud should be str | list[str] | None)

    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256, claims_validation=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims, secret_key, Alg.HS256
        )  # same as claims_validation=JWTCustomClaims

    compact = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact  # create token anyway
    jwt.decode(compact, secret_key, Alg.HS256)  # passes (no validation)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact, secret_key, Alg.HS256, claims_validation=JWTClaims
        )  # fails JWTClaims validation (aud wrong type)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(compact, secret_key, Alg.HS256, claims_validation=JWTCustomClaims)
    decoded_claims = jwt.decode(
        compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).payload
    with pytest.raises(pydantic.ValidationError):
        JWTCustomClaims(**decoded_claims)

    # test detached payload
    jwt.encode(claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE)
    compact_detached = jwt.detach_payload().compact  # switch to detached mode
    jwt.decode(
        compact_detached, secret_key, Alg.HS256, with_detached_payload=claims.to_dict()
    )  # passes (no validation)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact_detached,
            secret_key,
            Alg.HS256,
            claims_validation=JWTClaims,
            with_detached_payload=claims.to_dict(),
        )
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact_detached,
            secret_key,
            Alg.HS256,
            claims_validation=JWTCustomClaims,
            with_detached_payload=claims.to_dict(),
        )


def test_unsupported_b64_header(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    # 'b64' header parameter is not supported
    with pytest.raises(InvalidHeadersError):
        jwt.encode(claims, secret_key, Alg.HS256, headers={"alg": "HS256", "b64": False})


def test_invalid_claims_future_dates(jwt: JWT, secret_key: str):
    now = datetime.now(UTC)

    # exp <= iat is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "exp": (now - timedelta(minutes=5)).timestamp(),
    }

    jwt.encode(claims_dict, secret_key, Alg.HS256)  # no validation
    jwt.encode(
        claims_dict, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )  # no validation
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, Alg.HS256, claims_validation=JWTClaims)

    # nbf <= iat is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "nbf": (now - timedelta(minutes=5)).timestamp(),
    }
    jwt.encode(claims_dict, secret_key, Alg.HS256)  # no validation
    jwt.encode(
        claims_dict, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )  # no validation
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, Alg.HS256, claims_validation=JWTClaims)

    # nbf >= exp is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "nbf": (now + timedelta(days=5)).timestamp(),
        "exp": (now + timedelta(minutes=5)).timestamp(),
    }
    jwt.encode(claims_dict, secret_key, Alg.HS256)  # no validation
    jwt.encode(
        claims_dict, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )  # no validation
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, Alg.HS256, claims_validation=JWTClaims)


def test_claims_type_error(jwt: JWT, secret_key: str):
    with pytest.raises(TypeError):
        jwt.encode("not_a_dict_or_jwtclaims", secret_key, Alg.HS256)  # type: ignore


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

    compact = jwt.encode(claims_fixed_dt, secret_key, Alg.HS256).compact
    assert compact.rsplit(b".", 1)[0] == compact.rsplit(b".", 1)[0]

    decoded_claims = jwt.decode(compact, secret_key, Alg.HS256).payload
    assert decoded_claims["sub"] == claims_fixed_dt.sub

    # check the JWT was tampered with
    with pytest.raises(SignatureVerificationFailedError):
        jwt.decode(forged_compact, secret_key, Alg.HS256)

    # decode with no signature verification
    unsafe_token = inspect(forged_compact)
    assert unsafe_token.payload["sub"] == forged_claims.sub
    unsafe_token = jwt.inspect(forged_compact)
    assert unsafe_token.payload["sub"] == forged_claims.sub

    # detached mode
    detached_compact = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b"."
        b"."
        b"7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )
    unsafe_token_detached = jwt.inspect(detached_compact, has_detached_payload=True)
    assert unsafe_token_detached.payload == {}


def test_detached_payload(jwt: JWT, claims_fixed_dt, secret_key):
    token = jwt.encode(claims_fixed_dt, secret_key, Alg.HS256)
    compact = token.compact
    token_detached = jwt.detach_payload()
    compact_detached = token_detached.compact
    compact_detached2 = encode(
        claims_fixed_dt, secret_key, Alg.HS256, detach_payload=True
    )
    assert compact_detached == compact_detached2

    decoded_claims_detached = jwt.decode(
        compact_detached, secret_key, Alg.HS256, with_detached_payload=claims_fixed_dt
    ).payload
    assert decoded_claims_detached == claims_fixed_dt.to_dict()
    decoded_claims = jwt.decode(compact, secret_key, Alg.HS256).payload
    assert decoded_claims == decoded_claims_detached


def test_detached_payload_no_jws_instance(jwt: JWT):
    with pytest.raises(SuperJWTError):
        jwt.detach_payload()


def test_expired_token(jwt: JWT, secret_key: str):
    claims = JWTClaims.model_construct(exp=datetime.now(UTC) - timedelta(days=1))
    compact = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact
    with pytest.raises(TokenExpiredError):
        jwt.encode(claims, secret_key, Alg.HS256)
    jwt.decode(compact, secret_key, Alg.HS256)  # passes (no validation)
    decoded_claims = jwt.decode(
        compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).payload
    assert decoded_claims["exp"] == claims.to_dict()["exp"]
    with pytest.raises(TokenExpiredError):
        jwt.decode(compact, secret_key, Alg.HS256, claims_validation=JWTClaims)

    # test with dict
    past_exp_dict = {
        "sub": "test_user",
        "exp": (datetime.now(UTC) - timedelta(days=365)).timestamp(),
    }
    compact_dict = jwt.encode(
        past_exp_dict, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact
    with pytest.raises(TokenExpiredError):
        jwt.decode(compact_dict, secret_key, Alg.HS256, claims_validation=JWTClaims)


def test_not_yet_valid_token(jwt: JWT, secret_key: str):
    claims = JWTClaims.model_construct(nbf=datetime.now(UTC) + timedelta(days=1))
    compact = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact
    with pytest.raises(TokenNotYetValidError):
        jwt.encode(claims, secret_key, Alg.HS256)
    jwt.decode(compact, secret_key, Alg.HS256)  # passes (no validation)
    decoded_claims = jwt.decode(
        compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).payload
    assert decoded_claims["nbf"] == claims.to_dict()["nbf"]
    with pytest.raises(TokenNotYetValidError):
        jwt.decode(compact, secret_key, Alg.HS256, claims_validation=JWTClaims)

    # test with dict
    future_nbf_dict = {
        "sub": "test_user",
        "nbf": (datetime.now(UTC) + timedelta(days=365)).timestamp(),
    }
    compact_dict = jwt.encode(
        future_nbf_dict, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact
    with pytest.raises(TokenNotYetValidError):
        jwt.decode(compact_dict, secret_key, Alg.HS256, claims_validation=JWTClaims)


def test_exp_nbf_validation_in_jwt_workflow(jwt: JWT, secret_key: str):
    """Test exp/nbf validators in full encode/decode workflow."""
    now = datetime.now(UTC)

    # Test with claims containing all time fields using model_construct
    # (normal validation impossible when iat is present with nbf/exp)
    past_iat = datetime.now(UTC) - timedelta(days=365)
    past_nbf = datetime.now(UTC) - timedelta(days=180)
    past_exp = datetime.now(UTC) - timedelta(days=90)
    valid_claims = JWTClaims.model_construct(
        sub="user123", iat=past_iat, nbf=past_nbf, exp=past_exp
    )
    compact = jwt.encode(
        valid_claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact
    decoded = jwt.decode(
        compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )
    assert decoded.payload["iat"] == int(past_iat.timestamp())
    assert decoded.payload["nbf"] == int(past_nbf.timestamp())
    assert decoded.payload["exp"] == int(past_exp.timestamp())

    # Test encoding with past exp WITHOUT iat (validation disabled), then decode with validation
    past_exp_claims = JWTClaims.model_construct(
        sub="user123", exp=now - timedelta(hours=1)
    )
    compact_expired = jwt.encode(
        past_exp_claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact

    # Decoding with validation enabled should fail
    with pytest.raises(TokenExpiredError):
        jwt.decode(compact_expired, secret_key, Alg.HS256, claims_validation=JWTClaims)

    # Test encoding with future nbf WITHOUT iat (validation disabled), then decode with validation
    future_nbf_claims = JWTClaims.model_construct(
        sub="user123", nbf=now + timedelta(hours=1)
    )
    compact_not_yet = jwt.encode(
        future_nbf_claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact

    # Decoding with validation enabled should fail
    with pytest.raises(TokenNotYetValidError):
        jwt.decode(compact_not_yet, secret_key, Alg.HS256, claims_validation=JWTClaims)


def test_claims_model_data(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    # encode + claims as pydantic
    token = jwt.encode(claims, secret_key, Alg.HS256, claims_validation=JWTCustomClaims)
    assert isinstance(token.model.claims, JWTCustomClaims)
    token = jwt.encode(claims, secret_key, Alg.HS256)
    assert isinstance(token.model.claims, JWTCustomClaims)
    token = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )
    assert isinstance(token.model.claims, JWTBaseModel)

    # encode + claims as dict
    token = jwt.encode(
        claims.to_dict(), secret_key, Alg.HS256, claims_validation=JWTCustomClaims
    )
    assert isinstance(token.model.claims, JWTCustomClaims)
    token = jwt.encode(claims.to_dict(), secret_key, Alg.HS256)
    assert isinstance(token.model.claims, JWTBaseModel)
    token = jwt.encode(
        claims.to_dict(), secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )
    compact = token.compact
    assert isinstance(token.model.claims, JWTBaseModel)

    # decode
    token = jwt.decode(compact, secret_key, Alg.HS256, claims_validation=JWTCustomClaims)
    assert isinstance(token.model.claims, JWTCustomClaims)
    token = jwt.decode(compact, secret_key, Alg.HS256)
    assert isinstance(token.model.claims, JWTBaseModel)
    token = jwt.decode(
        compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )
    assert isinstance(token.model.claims, JWTBaseModel)


def test_custom_headers_validation(jwt: JWT, secret_key: str):
    # test with a wrong object type for claims_validation
    with pytest.raises(TypeError):
        jwt.encode({}, secret_key, Alg.HS256, headers_validation="not_a_model")  # type: ignore

    class CustomHeader(JOSEHeader):
        custom_header: str

    headers = CustomHeader.model_construct(
        alg="HS256"
    )  # non compliant with CustomHeader, but with JOSEHeader

    # pydantic headers
    jwt.encode(
        {}, secret_key, Alg.HS256, headers=headers, headers_validation=JOSEHeader
    )  # passes
    with pytest.raises(HeadersValidationError):
        jwt.encode({}, secret_key, Alg.HS256, headers=headers)

    # make headers no more compliant with JOSEHeader
    headers.typ = 123  # invalid type for typ # type: ignore
    with pytest.raises(HeadersValidationError):
        jwt.encode(
            {},
            secret_key,
            Alg.HS256,
            headers=headers,
            headers_validation=JOSEHeader,  # no longer compliant (typ should be str)
        )
    with pytest.raises(HeadersValidationError):
        jwt.encode({}, secret_key, Alg.HS256, headers=headers)

    compact = jwt.encode(
        {}, secret_key, Alg.HS256, headers=headers, headers_validation=Validation.DISABLE
    ).compact
    decoded_claims = jwt.decode(
        compact, secret_key, Alg.HS256, headers_validation=Validation.DISABLE
    ).payload
    with pytest.raises(HeadersValidationError):
        jwt.decode(
            compact, secret_key, Alg.HS256
        )  # fails because validation defaults to JOSEHeader
    with pytest.raises(HeadersValidationError):
        jwt.decode(compact, secret_key, Alg.HS256, headers_validation=JOSEHeader)
    with pytest.raises(HeadersValidationError):
        jwt.decode(compact, secret_key, Alg.HS256, headers_validation=CustomHeader)
    assert decoded_claims == {}


def test_headers_model_data(jwt: JWT, secret_key: str):
    class CustomHeader(JOSEHeader):
        custom_header: str

    headers = CustomHeader(alg="HS256", custom_header="custom_value")

    # encode + headers as pydantic
    token = jwt.encode(
        {}, secret_key, Alg.HS256, headers=headers, headers_validation=CustomHeader
    )
    assert isinstance(token.model.headers, CustomHeader)
    token = jwt.encode({}, secret_key, Alg.HS256, headers=headers)
    assert isinstance(token.model.headers, JOSEHeader)
    token = jwt.encode(
        {}, secret_key, Alg.HS256, headers=headers, headers_validation=Validation.DISABLE
    )
    assert isinstance(token.model.headers, JWTBaseModel)

    # encode + headers as dict
    token = jwt.encode(
        {},
        secret_key,
        Alg.HS256,
        headers=headers.to_dict(),
        headers_validation=CustomHeader,
    )
    assert isinstance(token.model.headers, CustomHeader)
    token = jwt.encode({}, secret_key, Alg.HS256, headers=headers.to_dict())
    assert isinstance(token.model.headers, JOSEHeader)
    token = jwt.encode(
        {},
        secret_key,
        Alg.HS256,
        headers=headers.to_dict(),
        headers_validation=Validation.DISABLE,
    )
    compact = token.compact
    assert isinstance(token.model.headers, JWTBaseModel)

    # decode
    token = jwt.decode(compact, secret_key, Alg.HS256, headers_validation=CustomHeader)
    assert isinstance(token.model.headers, CustomHeader)
    token = jwt.decode(compact, secret_key, Alg.HS256)
    assert isinstance(token.model.headers, JOSEHeader)
    token = jwt.decode(
        compact, secret_key, Alg.HS256, headers_validation=Validation.DISABLE
    )
    assert isinstance(token.model.headers, JWTBaseModel)


def test_custom_default_claims_validation_policy(
    claims_dict: dict[str, Any], secret_key: str
):
    """Test JWT instance with custom default claims validation policy."""

    # Create JWT instance with strict claims validation by default (JWTClaims)
    custom_validation_config = JWTValidation(
        validation_model=JWTClaims,
        data_model=JWTClaims,
    )
    jwt_strict = JWT(default_claims_validation=custom_validation_config)

    # Valid claims dict should pass validation
    valid_claims = claims_dict.copy()
    compact = jwt_strict.encode(valid_claims, secret_key, Alg.HS256).compact
    decoded_claims = jwt_strict.decode(compact, secret_key, Alg.HS256).payload
    assert decoded_claims["sub"] == valid_claims["sub"]

    # Invalid claims dict should fail validation (aud must be str or list[str])
    invalid_claims = claims_dict.copy()
    invalid_claims["aud"] = 123  # invalid type
    with pytest.raises(ClaimsValidationError):
        jwt_strict.encode(invalid_claims, secret_key, Alg.HS256)

    # Test with invalid future dates (exp <= iat)
    now = datetime.now(UTC)
    invalid_dates_claims = {
        "sub": "user123",
        "iat": now.timestamp(),
        "exp": (now - timedelta(minutes=5)).timestamp(),
    }
    with pytest.raises(ClaimsValidationError):
        jwt_strict.encode(invalid_dates_claims, secret_key, Alg.HS256)

    # Can still override validation on encode/decode
    compact_unvalidated = jwt_strict.encode(
        invalid_claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact
    # Decode with claims_validation=Validation.DISABLE should pass (no validation)
    jwt_strict.decode(
        compact_unvalidated, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )
    # Decode without specifying claims_validation should fail (uses custom default)
    with pytest.raises(ClaimsValidationError):
        jwt_strict.decode(compact_unvalidated, secret_key, Alg.HS256)

    # Same for invalid_dates_claims
    compact_invalid_dates = jwt_strict.encode(
        invalid_dates_claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    ).compact
    # Decode with claims_validation=Validation.DISABLE should pass (no validation)
    jwt_strict.decode(
        compact_invalid_dates, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )
    # Decode without specifying claims_validation should fail (uses custom default)
    with pytest.raises(ClaimsValidationError):
        jwt_strict.decode(compact_invalid_dates, secret_key, Alg.HS256)

    # Compare with default JWT instance behavior (no validation for dict claims)
    jwt_default = JWT()
    jwt_default.encode(invalid_claims, secret_key, Alg.HS256)  # passes without validation


def test_custom_default_headers_validation_policy(secret_key: str):
    """Test JWT instance with custom default headers validation policy."""

    class CustomHeader(JOSEHeader):
        custom_header: str

    # Create JWT instance with custom headers validation by default
    custom_validation_config = JWTValidation(
        validation_model=CustomHeader,
        data_model=CustomHeader,
    )
    jwt_custom = JWT(default_headers_validation=custom_validation_config)

    # Valid custom headers should pass validation
    valid_headers = {"alg": "HS256", "custom_header": "custom_value"}
    compact = jwt_custom.encode({}, secret_key, Alg.HS256, headers=valid_headers).compact
    decoded_claims = jwt_custom.decode(compact, secret_key, Alg.HS256).payload
    assert decoded_claims == {}

    # Missing custom_header should fail validation
    invalid_headers = {"alg": "HS256"}  # missing custom_header
    with pytest.raises(HeadersValidationError):
        jwt_custom.encode({}, secret_key, Alg.HS256, headers=invalid_headers)

    # Can still override validation on encode/decode
    compact_unvalidated = jwt_custom.encode(
        {},
        secret_key,
        Alg.HS256,
        headers=invalid_headers,
        headers_validation=Validation.DISABLE,
    ).compact
    # Decode with headers_validation=Validation.DISABLE should pass (no validation)
    jwt_custom.decode(
        compact_unvalidated, secret_key, Alg.HS256, headers_validation=Validation.DISABLE
    )
    # Decode without specifying headers_validation should fail (uses custom default)
    with pytest.raises(HeadersValidationError):
        jwt_custom.decode(compact_unvalidated, secret_key, Alg.HS256)

    # Compare with default JWT instance behavior (validates with JOSEHeader, not CustomHeader)
    jwt_default = JWT()
    jwt_default.encode(
        {}, secret_key, Alg.HS256, headers=invalid_headers
    )  # passes with JOSEHeader validation


def test_custom_default_claims_validation_policy_no_force_pydantic(
    claims_dict: dict[str, Any], secret_key: str
):
    """Test JWT instance with custom default validation but force_validation_on_pydantic_model=False."""

    # Create JWT instance with custom validation but without forcing Pydantic validation
    custom_validation_config = JWTValidation(
        validation_model=JWTClaims,  # Validate against JWTClaims
        forward_pydantic_model=False,  # Don't force Pydantic model type
        data_model=JWTBaseModel,
    )
    jwt_custom = JWT(default_claims_validation=custom_validation_config)

    # Create invalid Pydantic claims
    invalid_claims = JWTCustomClaims.model_construct(**claims_dict)
    invalid_claims.aud = 123  # invalid type  # type: ignore

    # Encode with Pydantic claims should validate against JWTClaims (not JWTCustomClaims)
    # (because force_validation_on_pydantic_model=False and default_validation_model=JWTClaims)
    with pytest.raises(ClaimsValidationError):
        jwt_custom.encode(
            invalid_claims, secret_key, Alg.HS256
        )  # fails JWTClaims validation

    # Create valid claims according to JWTClaims but invalid for JWTCustomClaims
    partial_claims = JWTCustomClaims.model_construct(**claims_dict)
    partial_claims.user_id = None  # type: ignore

    compact = jwt_custom.encode(partial_claims, secret_key, Alg.HS256).compact
    decoded_claims = jwt_custom.decode(compact, secret_key, Alg.HS256).payload
    assert "user_id" not in decoded_claims

    with pytest.raises(ClaimsValidationError):
        jwt_custom.decode(
            compact, secret_key, Alg.HS256, claims_validation=JWTCustomClaims
        )

    # Compare with default JWT instance behavior (validates Pydantic models automatically)
    jwt_default = JWT()
    with pytest.raises(ClaimsValidationError):
        jwt_default.encode(partial_claims, secret_key, Alg.HS256)


def test_size_exceeded_error(secret_key: str):
    jwt_strict = JWT()  # default max_size is 16 KB
    jwt_lenient = JWT(max_token_bytes=50 * 1024)  # max 50 KB

    claims_big = {"data": "!" * 11_500}  # will create a compact of ~< 16 KB
    claims_enormous = {"data": "𒃲" * 3_100}  # will create a compact of ~> 50 KB

    # case passing
    token_big = jwt_strict.encode(claims_big, secret_key, Alg.HS256)
    token_big2 = jwt_lenient.encode(claims_big, secret_key, Alg.HS256)
    assert token_big.signing_input == token_big2.signing_input
    token_enormous = jwt_lenient.encode(claims_enormous, secret_key, Alg.HS256)
    jwt_lenient.decode(token_enormous.compact, secret_key, Alg.HS256)
    jwt_lenient.decode(token_big.compact, secret_key, Alg.HS256)
    jwt_strict.decode(token_big.compact, secret_key, Alg.HS256)

    # case failing
    with pytest.raises(SizeExceededError):
        jwt_strict.encode(claims_enormous, secret_key, Alg.HS256)
    with pytest.raises(SizeExceededError):
        jwt_strict.decode(token_enormous.compact, secret_key, Alg.HS256)


def test_invalid_token_error_malformed_tokens(jwt: JWT, secret_key: str):
    """Test InvalidTokenError for various malformed token formats."""
    malformed_token_2_parts = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"
    with pytest.raises(InvalidTokenError):
        jwt.decode(malformed_token_2_parts, secret_key, Alg.HS256)

    malformed_token_4_parts = (
        b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl.ZXh0cmE"
    )
    with pytest.raises(InvalidTokenError):
        jwt.decode(malformed_token_4_parts, secret_key, Alg.HS256)

    valid_token = jwt.encode({"sub": "test"}, secret_key, Alg.HS256).compact
    # Corrupt the signature part with invalid base64
    parts = valid_token.split(b".")
    invalid_signature_token = b".".join([parts[0], parts[1], b"!!!invalid-base64!!!"])
    with pytest.raises(InvalidTokenError):
        jwt.decode(invalid_signature_token, secret_key, Alg.HS256)


def test_invalid_headers_error_base64_and_format(jwt: JWT, secret_key: str):
    """Test InvalidHeadersError for invalid base64 encoding and non-dict headers."""
    valid_token = jwt.encode({"sub": "test"}, secret_key, Alg.HS256).compact
    parts = valid_token.split(b".")

    # Invalid base64 in headers
    invalid_header_token = b".".join([b"!!!invalid-base64!!!", parts[1], parts[2]])
    with pytest.raises(InvalidHeadersError):
        jwt.decode(invalid_header_token, secret_key, Alg.HS256)

    # Non-dict headers
    array_header = urlsafe_b64encode(json.dumps(["HS256"]).encode())
    non_dict_header_token = b".".join([array_header, parts[1], parts[2]])
    with pytest.raises(InvalidHeadersError):
        jwt.decode(non_dict_header_token, secret_key, Alg.HS256)

    # Headers with invalid JSON (not a complete structure)
    invalid_json_headers = urlsafe_b64encode(b"{invalid json}")
    invalid_json_token = b".".join([invalid_json_headers, parts[1], parts[2]])
    with pytest.raises(InvalidHeadersError):
        jwt.decode(invalid_json_token, secret_key, Alg.HS256)


def test_invalid_payload_error_base64_and_format(jwt: JWT, secret_key: str):
    """Test InvalidPayloadError for invalid base64 encoding and non-dict payload."""
    valid_token = jwt.encode({"sub": "test"}, secret_key, Alg.HS256).compact
    parts = valid_token.split(b".")

    # Invalid base64 in payload
    invalid_payload_token = b".".join([parts[0], b"!!!invalid-base64!!!", parts[2]])
    with pytest.raises(InvalidPayloadError):
        jwt.decode(invalid_payload_token, secret_key, Alg.HS256)

    # Non-dict payload
    array_payload = urlsafe_b64encode(json.dumps(["claim1", "claim2"]).encode())
    non_dict_payload_token = b".".join([parts[0], array_payload, parts[2]])
    with pytest.raises(InvalidPayloadError):
        jwt.decode(non_dict_payload_token, secret_key, Alg.HS256)

    # Payload with invalid JSON (not a complete structure)
    invalid_json_payload = urlsafe_b64encode(b"{invalid json}")
    invalid_json_token = b".".join([parts[0], invalid_json_payload, parts[2]])
    with pytest.raises(InvalidPayloadError):
        jwt.decode(invalid_json_token, secret_key, Alg.HS256)


def test_detached_payload_conflict(jwt: JWT, secret_key: str):
    """Test InvalidTokenError when decoding a token with payload in detached mode."""
    normal_token = jwt.encode({"sub": "test", "user_id": "123"}, secret_key, Alg.HS256)

    with pytest.raises(InvalidTokenError, match="Detached payload conflict"):
        jwt.decode(
            normal_token.compact,
            secret_key,
            Alg.HS256,
            with_detached_payload={"sub": "test", "user_id": "123"},
        )


def test_timestamp_switching_modes(jwt, secret_key):
    """Test that switching serialization mode works correctly."""
    now = datetime.now(UTC)
    claims = JWTClaims(iat=now)

    # Encode with int mode
    claims.force_jwtdatetime_to_int()
    token_int = jwt.encode(claims, secret_key, Alg.HS256)
    decoded_int = jwt.decode(token_int.compact, secret_key, Alg.HS256)
    assert isinstance(decoded_int.payload["iat"], int)
    assert decoded_int.payload["iat"] == int(now.timestamp())

    # Encode with float mode
    claims.force_jwtdatetime_to_float()
    token_float = jwt.encode(claims, secret_key, Alg.HS256)
    decoded_float = jwt.decode(token_float.compact, secret_key, Alg.HS256)
    assert isinstance(decoded_float.payload["iat"], float)
    assert decoded_float.payload["iat"] == now.timestamp()

    # Invalid mode
    claims.internal__jwtdatetime_force_int = "invalid"  # type: ignore
    with pytest.raises(ValueError, match="Invalid timestamp config type"):
        jwt.encode(claims, secret_key, Alg.HS256)


def test_mixed_datetime_serialization_types(jwt, secret_key):
    """Test custom claims with mixed JWTDatetime, JWTDatetimeInt, and JWTDatetimeFloat."""

    class CustomMixedClaims(JWTClaims):
        # exp redefined as required
        exp: JWTDatetime = pydantic.Field(default=...)

        # nbf redefined as a required JWTDatetimeInt (always int)
        nbf: JWTDatetimeInt = pydantic.Field(default=...)

        # custom field with JWTDatetimeFloat (always float)
        custom_time: JWTDatetimeFloat = pydantic.Field(default=...)

    now = datetime.now(UTC)

    # Create instance with specific microseconds to test precision
    exp_time = now + timedelta(hours=10, minutes=30, seconds=15, microseconds=123456)
    nbf_time = now
    custom_time = datetime(2026, 3, 15, 8, 45, 22, 987654, tzinfo=UTC)

    claims = CustomMixedClaims(
        iat=now - timedelta(hours=1),
        exp=exp_time,
        nbf=nbf_time,
        custom_time=custom_time,
    )
    assert claims.internal__jwtdatetime_force_int is True

    token = jwt.encode(claims, secret_key, Alg.HS256)
    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)

    # exp should be int (because flag is True and it's JWTDatetime)
    assert isinstance(decoded.payload["exp"], int)
    assert decoded.payload["exp"] == int(exp_time.timestamp())

    # nbf should ALWAYS be int (JWTDatetimeInt ignores flag)
    assert isinstance(decoded.payload["nbf"], int)
    assert decoded.payload["nbf"] == int(nbf_time.timestamp())

    # custom_time should ALWAYS be float (JWTDatetimeFloat ignores flag)
    assert isinstance(decoded.payload["custom_time"], float)
    assert abs(decoded.payload["custom_time"] - custom_time.timestamp()) < 1e-6

    # Now switch to float mode
    claims.force_jwtdatetime_to_float()
    assert claims.internal__jwtdatetime_force_int is False

    # Encode and decode again
    token2 = jwt.encode(claims, secret_key, Alg.HS256)
    decoded2 = jwt.decode(token2.compact, secret_key, Alg.HS256)

    # exp should now be float (because flag is False and it's JWTDatetime)
    assert isinstance(decoded2.payload["exp"], float)
    assert abs(decoded2.payload["exp"] - exp_time.timestamp()) < 1e-6

    # nbf should STILL be int (JWTDatetimeInt always ignores flag)
    assert isinstance(decoded2.payload["nbf"], int)
    assert decoded2.payload["nbf"] == int(nbf_time.timestamp())

    # custom_time should STILL be float (JWTDatetimeFloat always ignores flag)
    assert isinstance(decoded2.payload["custom_time"], float)
    assert abs(decoded2.payload["custom_time"] - custom_time.timestamp()) < 1e-6

    # Switch back to int mode
    claims.force_jwtdatetime_to_int()
    assert claims.internal__jwtdatetime_force_int is True

    # Encode and decode one more time
    token3 = jwt.encode(claims, secret_key, Alg.HS256)
    decoded3 = jwt.decode(token3.compact, secret_key, Alg.HS256)

    # exp should be back to int
    assert isinstance(decoded3.payload["exp"], int)
    assert decoded3.payload["exp"] == int(exp_time.timestamp())

    # nbf and custom_time behavior unchanged
    assert isinstance(decoded3.payload["nbf"], int)
    assert isinstance(decoded3.payload["custom_time"], float)
