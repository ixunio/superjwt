import json
from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import Field, ValidationError
from superjwt import decode, encode, inspect
from superjwt.exceptions import (
    AlgorithmMismatchError,
    ClaimsValidationError,
    HeadersValidationError,
    InvalidAlgorithmError,
    InvalidHeadersError,
    InvalidPayloadError,
    InvalidTokenError,
    SignatureVerificationError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from superjwt.keys import ECKey, OKPKey, RSAKey
from superjwt.shared import Alg
from superjwt.utils import urlsafe_b64encode
from superjwt.validations import (
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    JWTDatetimeFloat,
    Validation,
    ValidationConfig,
)

from .conftest import JWTCustomClaims, check_claims_instance


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


def test_encode_decode_default_claims(secret_key):
    # Test with string for backward compatibility
    compact = encode(None, secret_key, "HS256")
    decoded_claims_pydantic = decode(compact, secret_key, "HS256")

    # Verify decode() returns a pydantic instance
    assert isinstance(decoded_claims_pydantic, JWTBaseModel)
    assert decoded_claims_pydantic.to_dict() == {}


def test_decode_returns_pydantic_instance(claims_dict: dict[str, Any], secret_key: str):
    """Verify that decode() returns pydantic instance with proper validation."""

    # Test 1: Dict claims with default validation
    compact = encode(claims_dict, secret_key, Alg.HS256)
    decoded_pydantic = decode(compact, secret_key, Alg.HS256)
    assert isinstance(decoded_pydantic, JWTBaseModel)

    # The decoded instance has deserialized datetime objects
    if isinstance(decoded_pydantic, JWTClaims):
        assert isinstance(decoded_pydantic.iat, datetime)
        assert isinstance(decoded_pydantic.exp, datetime)

    # Test 2: Pydantic claims with custom model
    claims_pydantic = JWTCustomClaims(**claims_dict)
    compact2 = encode(claims_pydantic, secret_key, Alg.HS256, validation=JWTCustomClaims)
    decoded_pydantic2 = decode(
        compact2, secret_key, Alg.HS256, validation=JWTCustomClaims
    )
    assert isinstance(decoded_pydantic2, JWTCustomClaims)

    # Test 3: With validation disabled
    compact3 = encode(claims_dict, secret_key, Alg.HS256, validation=Validation.DISABLE)
    decoded_pydantic3 = decode(
        compact3, secret_key, Alg.HS256, validation=Validation.DISABLE
    )
    assert isinstance(decoded_pydantic3, JWTBaseModel)


def test_payload_datetime_serialization(secret_key: str):
    """Test that datetime fields are properly serialized and deserialized."""
    now = datetime.now(UTC)

    claims = JWTClaims(
        sub="user123",
        iat=now,
        exp=now + timedelta(hours=1),
        nbf=now + timedelta(minutes=5),
    )

    compact = encode(claims, secret_key, Alg.HS256)

    # Spoof time to after nbf to allow decoding
    spoofed_now = now + timedelta(minutes=10)
    decoded = decode(
        compact,
        secret_key,
        Alg.HS256,
        validation=ValidationConfig(model=JWTClaims, now=spoofed_now),
    )

    # The decoded model is a validated Pydantic instance
    assert isinstance(decoded, JWTClaims)
    assert decoded.sub == "user123"
    assert isinstance(decoded.iat, datetime)
    assert isinstance(decoded.exp, datetime)
    assert isinstance(decoded.nbf, datetime)

    # Timestamps are properly serialized to int
    model_dict = decoded.to_dict()
    assert isinstance(model_dict["iat"], int)
    assert isinstance(model_dict["exp"], int)
    assert isinstance(model_dict["nbf"], int)


def test_encode_decode_dict_claims(claims_dict, secret_key):
    compact = encode(claims_dict, secret_key, Alg.HS256)
    decoded_claims_dict = decode(compact, secret_key, Alg.HS256).to_dict()

    # standard claims
    assert decoded_claims_dict["iss"] == claims_dict["iss"]
    assert decoded_claims_dict["sub"] == claims_dict["sub"]
    assert decoded_claims_dict.get("aud") is None
    assert decoded_claims_dict.get("jti") is None

    # standard claims (datetime data with various input types)
    # they will be serialized uniformly as int (timestamp) thanks to JWTClaims validation
    assert decoded_claims_dict["iat"] == int(claims_dict["iat"])
    assert decoded_claims_dict.get("nbf") is None
    assert decoded_claims_dict["exp"] == int(claims_dict["exp"])

    # custom claims
    # won't be any type conversion here, nor validation
    assert decoded_claims_dict["user_id"] == claims_dict["user_id"]
    assert decoded_claims_dict.get("optional_id") is None


# def test_encode_decode_dict_custom_datetime_claim(secret_key):
#     # custom datetime claim from dict cannot be validated without pydantic
#     # it MUST be serializable
#     # it SHOULD be an int timestamp
#     custom_dt_unserializable = {
#         "custom_date": datetime.strptime(
#             "2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z"
#         ),
#     }
#     custom_dt_serializable_str = {"custom_date": "2042-04-02T:00:42:42.123456+0000"}
#     custom_dt_correct = {
#         "custom_date": int(
#             datetime.strptime(
#                 "2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z"
#             ).timestamp()
#         ),
#     }

#     # cannot encode datetime in custom claims
#     with pytest.raises(ClaimsValidationError):
#         encode({"custom_date": custom_dt_unserializable}, secret_key, Alg.HS256)

#     # cannot encode datetime in nested custom claims (recursive check)
#     nested_dt = {"nested": {"deep": datetime.now(UTC)}}
#     with pytest.raises(ClaimsValidationError):
#         encode({"custom_nested": nested_dt}, secret_key, Alg.HS256)

#     # cannot encode datetime in list within custom claims
#     list_with_dt = [datetime.now(UTC), "other"]
#     with pytest.raises(ClaimsValidationError):
#         encode({"custom_list": list_with_dt}, secret_key, Alg.HS256)

#     # can encode serializable datetime string, this will not be serialized as a timestamp
#     # unlike the standard datetime claims (iat, nbf, exp)
#     compact = encode({"custom_date": custom_dt_serializable_str}, secret_key, Alg.HS256)
#     decoded = decode(compact, secret_key, Alg.HS256).to_dict()
#     assert decoded["custom_date"] == custom_dt_serializable_str

#     # can encode integer timestamp
#     compact = encode({"custom_date": custom_dt_correct}, secret_key, Alg.HS256)
#     decoded = decode(compact, secret_key, Alg.HS256).to_dict()
#     assert decoded["custom_date"] == custom_dt_correct


def test_add_iat_add_exp(secret_key):
    # custom datetime claim set to None should be handled correctly
    claims = JWTClaims().with_issued_at().with_expiration(minutes=30)
    compact = encode(claims, secret_key, Alg.HS256)
    decoded = decode(compact, secret_key, Alg.HS256).to_dict()
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
    decoded = decode(compact, secret_key, Alg.HS256).to_dict()
    assert "iat" not in decoded


def test_with_expiration_negative():
    # custom datetime claim set to invalid type should be handled correctly
    with pytest.raises(ValueError):
        JWTClaims().with_expiration(minutes=-15)


def test_rewrite_incorrect_exp_type():
    class JWTIncorrectExpClaim(JWTClaims):
        exp: JWTDatetimeFloat = Field(default=...)

    with pytest.raises(ValidationError):
        JWTIncorrectExpClaim(exp=True)  # type: ignore


def test_encode_decode_pydantic_claims(claims_dict: dict[str, Any], secret_key: str):
    claims = JWTCustomClaims(**claims_dict)

    compact = encode(claims, secret_key, Alg.HS256)
    decoded_claims = JWTCustomClaims(**decode(compact, secret_key, Alg.HS256).to_dict())

    check_claims_instance(claims, decoded_claims)

    # test non compliant claims
    claims = JWTCustomClaims(**claims_dict)
    claims.aud = 123  # invalid type for aud  # type: ignore
    with pytest.raises(ClaimsValidationError):
        encode(claims, secret_key, Alg.HS256)

    # test custom claims model validation
    claims = JWTCustomClaims(**claims_dict)
    # encoding valid
    compact = encode(claims, secret_key, Alg.HS256)
    compact2 = encode(claims, secret_key, Alg.HS256, validation=JWTCustomClaims)
    assert compact == compact2
    # decoding
    claims.user_id = None  # invalid type for user_id  # type: ignore
    compact = encode(claims, secret_key, Alg.HS256, validation=Validation.DISABLE)
    # passes (validation with default JWTClaims)
    decode(compact, secret_key, Alg.HS256)
    # fails (validation with JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        decode(compact, secret_key, Alg.HS256, validation=JWTCustomClaims)


def test_decode_invalid_signature(claims: JWTCustomClaims, secret_key: str):
    wrong_key = "wrongkey_but_long_enough"
    compact = encode(claims, secret_key, Alg.HS256)

    with pytest.raises(SignatureVerificationError):
        decode(compact, wrong_key, Alg.HS256)


def test_encode_decode_claims_validation_disabled(
    claims: JWTCustomClaims, secret_key_random: str
):
    # prepare an invalid claims pydantic instance
    unvalidated_claims = JWTCustomClaims.model_construct(
        **claims.to_dict()
    )  # zero validation (even for datetime)
    unvalidated_claims.sub = 1  # invalid type for sub  # type: ignore
    with pytest.raises(ClaimsValidationError):
        encode(unvalidated_claims, secret_key_random, Alg.HS256)
    compact = encode(
        unvalidated_claims,
        secret_key_random,
        Alg.HS256,
        validation=Validation.DISABLE,
    )

    with pytest.raises(ClaimsValidationError):
        decode(compact, secret_key_random, Alg.HS256, validation=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        decode(
            compact, secret_key_random, Alg.HS256
        )  # fails (default JWTClaims validation)

    decoded = decode(
        compact, secret_key_random, Alg.HS256, validation=Validation.DISABLE
    ).to_dict()
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims.sub  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime
    check_claims_instance(claims, decoded_claims)


def test_encode_decode_claims_dict_validation_disabled(
    claims_dict: dict[str, Any], exp: float, secret_key_random: str
):
    # prepare an invalid claims dict
    unvalidated_claims_dict = claims_dict.copy()
    unvalidated_claims_dict["sub"] = 1  # invalid type for sub
    with pytest.raises(ClaimsValidationError):
        encode(
            unvalidated_claims_dict, secret_key_random, Alg.HS256
        )  # fails (default JWTClaims validation)
    with pytest.raises(ClaimsValidationError):
        encode(
            unvalidated_claims_dict,
            secret_key_random,
            Alg.HS256,
            validation=JWTClaims,
        )
    # run encoding again with validation disabled, does not raise error
    compact = encode(
        unvalidated_claims_dict,
        secret_key_random,
        Alg.HS256,
        validation=Validation.DISABLE,
    )
    with pytest.raises(ClaimsValidationError):
        decode(
            compact, secret_key_random, Alg.HS256
        )  # fails (default JWTClaims validation)
    with pytest.raises(ClaimsValidationError):
        decode(compact, secret_key_random, Alg.HS256, validation=JWTClaims)
    # run decoding again with validation disabled, does not raise error
    decoded = decode(
        compact, secret_key_random, Alg.HS256, validation=Validation.DISABLE
    ).to_dict()
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims_dict["sub"]  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime as int timestamp
    claims = JWTCustomClaims(**claims_dict)  # the original claims data
    check_claims_instance(claims, decoded_claims)


def test_custom_claims_validation(claims: JWTCustomClaims, secret_key: str):
    # test with a wrong object type for validation parameter
    with pytest.raises(TypeError):
        encode(claims, secret_key, Alg.HS256, validation="not_a_model")  # type: ignore

    claims.sub = None  # remove required field 'sub'  # type: ignore

    encode(
        claims, secret_key, Alg.HS256, validation=JWTClaims
    )  # passes because compliant with JWTClaims
    with pytest.raises(ClaimsValidationError):
        encode(claims, secret_key, Alg.HS256, validation=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        encode(
            claims, secret_key, Alg.HS256
        )  # same as validation=JWTCustomClaims (pydantic object is validated by default)

    claims.aud = 123  # invalid registered claim  # type: ignore
    with pytest.raises(ClaimsValidationError):
        encode(
            claims, secret_key, Alg.HS256, validation=JWTClaims
        )  # no more compliant with JWTClaims (aud should be str | list[str] | None)

    with pytest.raises(ClaimsValidationError):
        encode(claims, secret_key, Alg.HS256, validation=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        encode(claims, secret_key, Alg.HS256)  # same as validation=JWTCustomClaims

    compact = encode(
        claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    )  # create token anyway
    with pytest.raises(ClaimsValidationError):
        decode(compact, secret_key, Alg.HS256)  # fails (default JWTClaims validation)
    with pytest.raises(ClaimsValidationError):
        decode(
            compact, secret_key, Alg.HS256, validation=JWTClaims
        )  # fails JWTClaims validation (aud wrong type)
    with pytest.raises(ClaimsValidationError):
        decode(compact, secret_key, Alg.HS256, validation=JWTCustomClaims)
    decoded_claims = decode(
        compact, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).to_dict()
    with pytest.raises(ValidationError):
        JWTCustomClaims(**decoded_claims)

    # test detached payload
    compact_detached = encode(
        claims, secret_key, Alg.HS256, detach_payload=True, validation=Validation.DISABLE
    )
    with pytest.raises(ClaimsValidationError):
        decode(
            compact_detached,
            secret_key,
            Alg.HS256,
            with_detached_payload=claims.to_dict(),
        )  # fails (default JWTClaims validation)
    with pytest.raises(ClaimsValidationError):
        decode(
            compact_detached,
            secret_key,
            Alg.HS256,
            validation=JWTClaims,
            with_detached_payload=claims.to_dict(),
        )
    with pytest.raises(ClaimsValidationError):
        decode(
            compact_detached,
            secret_key,
            Alg.HS256,
            validation=JWTCustomClaims,
            with_detached_payload=claims.to_dict(),
        )
    decode(
        compact_detached,
        secret_key,
        Alg.HS256,
        with_detached_payload=claims.to_dict(),
        validation=Validation.DISABLE,
    )  # passes


def test_invalid_claims_future_dates(secret_key: str):
    now = datetime.now(UTC)

    # exp <= iat is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "exp": (now - timedelta(minutes=5)).timestamp(),
    }

    with pytest.raises(ClaimsValidationError):
        encode(claims_dict, secret_key, Alg.HS256)  # fails (default JWTClaims validation)
    encode(
        claims_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    )  # passes (validation disabled)
    with pytest.raises(ClaimsValidationError):
        encode(claims_dict, secret_key, Alg.HS256, validation=JWTClaims)

    # nbf <= iat is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "nbf": (now - timedelta(minutes=5)).timestamp(),
    }
    encode(
        claims_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    )  # passes (validation disabled)
    with pytest.raises(ClaimsValidationError):
        encode(claims_dict, secret_key, Alg.HS256, validation=JWTClaims)

    # nbf >= exp is forbidden (token would never be valid)
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "nbf": (now + timedelta(days=5)).timestamp(),
        "exp": (now + timedelta(minutes=5)).timestamp(),
    }
    encode(
        claims_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    )  # no validation
    with pytest.raises(ClaimsValidationError):
        encode(claims_dict, secret_key, Alg.HS256, validation=JWTClaims)


def test_claims_type_error(secret_key: str):
    with pytest.raises(TypeError):
        encode("not_a_dict_or_jwtclaims", secret_key, Alg.HS256)  # type: ignore


def test_unsafe_inspect(claims_fixed_dt, secret_key: str):
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

    compact = encode(claims_fixed_dt, secret_key, Alg.HS256)
    assert compact.rsplit(b".", 1)[0] == compact.rsplit(b".", 1)[0]

    decoded_claims = decode(compact, secret_key, Alg.HS256).to_dict()
    assert decoded_claims["sub"] == claims_fixed_dt.sub

    # check the JWT was tampered with
    with pytest.raises(SignatureVerificationError):
        decode(forged_compact, secret_key, Alg.HS256)

    # decode with no signature verification
    unsafe_token = inspect(forged_compact)
    assert unsafe_token.payload["sub"] == forged_claims.sub
    unsafe_token = inspect(forged_compact)
    assert unsafe_token.payload["sub"] == forged_claims.sub

    # detached mode
    detached_compact = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b"."
        b"."
        b"7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )
    unsafe_token_detached = inspect(detached_compact)
    assert unsafe_token_detached.payload == {}


def test_detached_payload(claims_fixed_dt, secret_key):
    compact = encode(claims_fixed_dt, secret_key, Alg.HS256)
    compact_detached = encode(claims_fixed_dt, secret_key, Alg.HS256, detach_payload=True)
    compact_detached2 = encode(
        claims_fixed_dt, secret_key, Alg.HS256, detach_payload=True
    )
    assert compact_detached == compact_detached2

    decoded_claims_detached = decode(
        compact_detached, secret_key, Alg.HS256, with_detached_payload=claims_fixed_dt
    ).to_dict()
    assert decoded_claims_detached == claims_fixed_dt.to_dict()
    decoded_claims = decode(compact, secret_key, Alg.HS256).to_dict()
    assert decoded_claims == decoded_claims_detached


def test_payload_model_claims_consistency_with_timestamp_fields(secret_key):
    """Verify timestamp serialization works correctly with JWTDatetimeInt vs JWTDatetimeFloat."""

    now = datetime.now(UTC)
    claims_int = JWTClaims(sub="user123", iat=now, exp=now + timedelta(hours=1))

    compact = encode(claims_int, secret_key, Alg.HS256)
    decoded = decode(compact, secret_key, Alg.HS256)

    # Payload contains int timestamps (JWTDatetimeInt)
    decoded_dict = decoded.to_dict()
    assert isinstance(decoded_dict["iat"], int)
    assert isinstance(decoded_dict["exp"], int)

    # Module-level decode returns equivalent pydantic instance
    assert isinstance(decoded, JWTClaims)
    assert isinstance(decoded.iat, datetime)
    assert isinstance(decoded.exp, datetime)

    # Test with custom JWTDatetimeFloat field
    class FloatClaims(JWTClaims):
        exp: JWTDatetimeFloat = Field(default=...)  # type: ignore

    claims_float = FloatClaims(sub="user456", iat=now, exp=now + timedelta(hours=2))

    compact2 = encode(claims_float, secret_key, Alg.HS256, validation=FloatClaims)
    decoded2 = decode(compact2, secret_key, Alg.HS256, validation=FloatClaims)

    # Payload has mixed int/float timestamps
    decoded2_dict = decoded2.to_dict()
    assert isinstance(decoded2_dict["iat"], int)  # JWTDatetimeInt
    assert isinstance(decoded2_dict["exp"], float)  # JWTDatetimeFloat

    # Module-level decode returns equivalent pydantic instance
    assert isinstance(decoded2, FloatClaims)
    assert isinstance(decoded2.iat, datetime)
    assert isinstance(decoded2.exp, datetime)


#
#
def test_expired_token(secret_key: str):
    claims = JWTClaims.model_construct(exp=datetime.now(UTC) - timedelta(days=1))
    compact = encode(claims, secret_key, Alg.HS256, validation=Validation.DISABLE)
    with pytest.raises(TokenExpiredError):
        encode(claims, secret_key, Alg.HS256)
    with pytest.raises(TokenExpiredError):
        decode(compact, secret_key, Alg.HS256)  # fails (default JWTClaims validation)
    decoded_claims = decode(
        compact, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).to_dict()
    assert decoded_claims["exp"] == claims.to_dict()["exp"]
    with pytest.raises(TokenExpiredError):
        decode(compact, secret_key, Alg.HS256, validation=JWTClaims)

    # test with dict
    past_exp_dict = {
        "sub": "test_user",
        "exp": (datetime.now(UTC) - timedelta(days=365)).timestamp(),
    }
    compact_dict = encode(
        past_exp_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    )
    with pytest.raises(TokenExpiredError):
        decode(compact_dict, secret_key, Alg.HS256, validation=JWTClaims)


def test_not_yet_valid_token(secret_key: str):
    claims = JWTClaims.model_construct(nbf=datetime.now(UTC) + timedelta(days=1))
    compact = encode(claims, secret_key, Alg.HS256, validation=Validation.DISABLE)
    # nbf validation only happens during decode, not encode
    encode(claims, secret_key, Alg.HS256)
    with pytest.raises(TokenNotYetValidError):
        decode(compact, secret_key, Alg.HS256)  # fails (default JWTClaims validation)
    decoded_claims = decode(
        compact, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).to_dict()
    assert decoded_claims["nbf"] == claims.to_dict()["nbf"]
    with pytest.raises(TokenNotYetValidError):
        decode(compact, secret_key, Alg.HS256, validation=JWTClaims)

    # test with dict
    future_nbf_dict = {
        "sub": "test_user",
        "nbf": (datetime.now(UTC) + timedelta(days=365)).timestamp(),
    }
    compact_dict = encode(
        future_nbf_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    )
    with pytest.raises(TokenNotYetValidError):
        decode(compact_dict, secret_key, Alg.HS256, validation=JWTClaims)


def test_exp_nbf_validation_in_jwt_workflow(secret_key: str):
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
    compact = encode(valid_claims, secret_key, Alg.HS256, validation=Validation.DISABLE)
    decoded = decode(compact, secret_key, Alg.HS256, validation=Validation.DISABLE)
    decoded_dict = decoded.to_dict()
    assert decoded_dict["iat"] == int(past_iat.timestamp())
    assert decoded_dict["nbf"] == int(past_nbf.timestamp())
    assert decoded_dict["exp"] == int(past_exp.timestamp())

    # Test encoding with past exp WITHOUT iat (validation disabled), then decode with validation
    past_exp_claims = JWTClaims.model_construct(
        sub="user123", exp=now - timedelta(hours=1)
    )
    compact_expired = encode(
        past_exp_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    )

    # Decoding with validation enabled should fail
    with pytest.raises(TokenExpiredError):
        decode(compact_expired, secret_key, Alg.HS256, validation=JWTClaims)

    # Test encoding with future nbf WITHOUT iat (validation disabled), then decode with validation
    future_nbf_claims = JWTClaims.model_construct(
        sub="user123", nbf=now + timedelta(hours=1)
    )
    compact_not_yet = encode(
        future_nbf_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    )

    # Decoding with validation enabled should fail
    with pytest.raises(TokenNotYetValidError):
        decode(compact_not_yet, secret_key, Alg.HS256, validation=JWTClaims)


#
#
def test_custom_headers_validation(secret_key: str):
    # test with a wrong object type for headers_validation
    with pytest.raises(TypeError):
        encode(
            {},
            secret_key,
            Alg.HS256,
            headers={"custom": "header"},
            headers_validation="not_a_model",  # type: ignore
        )

    class CustomHeader(JOSEHeader):
        custom_header: str

    headers = CustomHeader.model_construct(
        alg="HS256"
    )  # non compliant with CustomHeader, but with JOSEHeader

    # pydantic headers
    encode(
        {}, secret_key, Alg.HS256, headers=headers, headers_validation=JOSEHeader
    )  # passes
    with pytest.raises(HeadersValidationError):
        encode({}, secret_key, Alg.HS256, headers=headers)

    # make headers no more compliant with JOSEHeader
    headers.typ = 123  # invalid type for typ # type: ignore
    with pytest.raises(HeadersValidationError):
        encode(
            {},
            secret_key,
            Alg.HS256,
            headers=headers,
            headers_validation=JOSEHeader,  # no longer compliant (typ should be str)
        )
    with pytest.raises(HeadersValidationError):
        encode({}, secret_key, Alg.HS256, headers=headers)

    compact = encode(
        {}, secret_key, Alg.HS256, headers=headers, headers_validation=Validation.DISABLE
    )
    decoded_claims = decode(
        compact, secret_key, Alg.HS256, headers_validation=Validation.DISABLE
    ).to_dict()
    with pytest.raises(HeadersValidationError):
        decode(
            compact, secret_key, Alg.HS256
        )  # fails because validation defaults to JOSEHeader
    with pytest.raises(HeadersValidationError):
        decode(compact, secret_key, Alg.HS256, headers_validation=JOSEHeader)
    with pytest.raises(HeadersValidationError):
        decode(compact, secret_key, Alg.HS256, headers_validation=CustomHeader)
    assert decoded_claims == {}


def test_custom_headers_validation_with_custom_model(secret_key: str):
    """Test header validation with custom header models that include extra fields."""

    class CustomHeader(JOSEHeader):
        custom_header: str

    # Test with dict that has extra field
    headers_dict = {"alg": "HS256", "custom_header": "value"}

    # With CustomHeader, passes
    encode(
        {}, secret_key, Alg.HS256, headers=headers_dict, headers_validation=CustomHeader
    )

    # With JOSEHeader, passes (extra allowed)
    encode({}, secret_key, Alg.HS256, headers=headers_dict)

    # With Validation.DISABLE, passes
    encode(
        {},
        secret_key,
        Alg.HS256,
        headers=headers_dict,
        headers_validation=Validation.DISABLE,
    )

    # Test with invalid type for custom field
    invalid_headers_dict = {"alg": "HS256", "custom_header": 123}

    # With CustomHeader, fails
    with pytest.raises(HeadersValidationError):
        encode(
            {},
            secret_key,
            Alg.HS256,
            headers=invalid_headers_dict,
            headers_validation=CustomHeader,
        )

    # With JOSEHeader, passes (extra allowed, and custom_header not validated)
    encode({}, secret_key, Alg.HS256, headers=invalid_headers_dict)

    # With Validation.DISABLE, passes
    encode(
        {},
        secret_key,
        Alg.HS256,
        headers=invalid_headers_dict,
        headers_validation=Validation.DISABLE,
    )

    # Test decode
    compact = encode(
        {},
        secret_key,
        Alg.HS256,
        headers=headers_dict,
        headers_validation=Validation.DISABLE,
    )

    # Decode with CustomHeader, passes
    decode(compact, secret_key, Alg.HS256, headers_validation=CustomHeader)

    # Decode with JOSEHeader, passes
    decode(compact, secret_key, Alg.HS256)

    # Decode with Validation.DISABLE, passes
    decode(compact, secret_key, Alg.HS256, headers_validation=Validation.DISABLE)

    # With invalid
    compact_invalid = encode(
        {},
        secret_key,
        Alg.HS256,
        headers=invalid_headers_dict,
        headers_validation=Validation.DISABLE,
    )

    # Decode with CustomHeader, fails
    with pytest.raises(HeadersValidationError):
        decode(compact_invalid, secret_key, Alg.HS256, headers_validation=CustomHeader)

    # Decode with JOSEHeader, passes
    decode(compact_invalid, secret_key, Alg.HS256)

    # Decode with Validation.DISABLE, passes
    decode(compact_invalid, secret_key, Alg.HS256, headers_validation=Validation.DISABLE)


def test_headers_validation_ignored_when_no_headers_provided(secret_key: str):
    """Test that headers_validation parameter has no effect when headers parameter is not provided."""

    class CustomHeader(JOSEHeader):
        custom_header: str = "required"

    # When no headers parameter is provided, headers_validation should be ignored
    # The encode should succeed regardless of headers_validation value
    claims = {"sub": "test"}

    # These should all succeed because no custom headers are provided
    token1 = encode(claims, secret_key, Alg.HS256, headers_validation=JOSEHeader)
    token2 = encode(claims, secret_key, Alg.HS256, headers_validation=CustomHeader)
    token3 = encode(claims, secret_key, Alg.HS256, headers_validation=Validation.DISABLE)
    token4 = encode(claims, secret_key, Alg.HS256)

    # All tokens should be identical since default headers are used
    assert token1 == token2 == token3 == token4

    # All should decode successfully
    decoded1 = decode(token1, secret_key, Alg.HS256)
    decoded2 = decode(token2, secret_key, Alg.HS256)
    decoded3 = decode(token3, secret_key, Alg.HS256)
    decoded4 = decode(token4, secret_key, Alg.HS256)

    assert (
        decoded1.to_dict()
        == decoded2.to_dict()
        == decoded3.to_dict()
        == decoded4.to_dict()
        == claims
    )


def test_invalid_token_error_malformed_tokens(secret_key: str):
    """Test InvalidTokenError for various malformed token formats."""
    malformed_token_2_parts = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"
    with pytest.raises(InvalidTokenError):
        decode(malformed_token_2_parts, secret_key, Alg.HS256)

    malformed_token_4_parts = (
        b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl.ZXh0cmE"
    )
    with pytest.raises(InvalidTokenError):
        decode(malformed_token_4_parts, secret_key, Alg.HS256)

    valid_token = encode({"sub": "test"}, secret_key, Alg.HS256)
    # Corrupt the signature part with invalid base64
    parts = valid_token.split(b".")
    invalid_signature_token = b".".join([parts[0], parts[1], b"!!!invalid-base64!!!"])
    with pytest.raises(InvalidTokenError):
        decode(invalid_signature_token, secret_key, Alg.HS256)


def test_invalid_headers_error_base64_and_format(secret_key: str):
    """Test InvalidHeadersError for invalid base64 encoding and non-dict headers."""
    valid_token = encode({"sub": "test"}, secret_key, Alg.HS256)
    parts = valid_token.split(b".")

    # Invalid base64 in headers
    invalid_header_token = b".".join([b"!!!invalid-base64!!!", parts[1], parts[2]])
    with pytest.raises(InvalidHeadersError):
        decode(invalid_header_token, secret_key, Alg.HS256)

    # Non-dict headers
    array_header = urlsafe_b64encode(json.dumps(["HS256"]).encode())
    non_dict_header_token = b".".join([array_header, parts[1], parts[2]])
    with pytest.raises(InvalidHeadersError):
        decode(non_dict_header_token, secret_key, Alg.HS256)

    # Headers with invalid JSON (not a complete structure)
    invalid_json_headers = urlsafe_b64encode(b"{invalid json}")
    invalid_json_token = b".".join([invalid_json_headers, parts[1], parts[2]])
    with pytest.raises(InvalidHeadersError):
        decode(invalid_json_token, secret_key, Alg.HS256)


def test_invalid_payload_error_base64_and_format(secret_key: str):
    """Test InvalidPayloadError for invalid base64 encoding and non-dict payload."""
    valid_token = encode({"sub": "test"}, secret_key, Alg.HS256)
    parts = valid_token.split(b".")

    # Invalid base64 in payload
    invalid_payload_token = b".".join([parts[0], b"!!!invalid-base64!!!", parts[2]])
    with pytest.raises(InvalidPayloadError):
        decode(invalid_payload_token, secret_key, Alg.HS256)

    # Non-dict payload
    array_payload = urlsafe_b64encode(json.dumps(["claim1", "claim2"]).encode())
    non_dict_payload_token = b".".join([parts[0], array_payload, parts[2]])
    with pytest.raises(InvalidPayloadError):
        decode(non_dict_payload_token, secret_key, Alg.HS256)

    # Payload with invalid JSON (not a complete structure)
    invalid_json_payload = urlsafe_b64encode(b"{invalid json}")
    invalid_json_token = b".".join([parts[0], invalid_json_payload, parts[2]])
    with pytest.raises(InvalidPayloadError):
        decode(invalid_json_token, secret_key, Alg.HS256)


def test_detached_payload_conflict(secret_key: str):
    """Test InvalidTokenError when decoding a token with payload in detached mode."""
    normal_token = encode({"sub": "test", "user_id": "123"}, secret_key, Alg.HS256)

    with pytest.raises(InvalidTokenError, match="Detached payload conflict"):
        decode(
            normal_token,
            secret_key,
            Alg.HS256,
            with_detached_payload={"sub": "test", "user_id": "123"},
        )


def test_hmac_algorithms(claims: JWTCustomClaims, secret_key: str):
    hmac_algorithms = [Alg.HS256, Alg.HS384, Alg.HS512]

    for alg in hmac_algorithms:
        token = encode(claims, secret_key, alg)
        decoded_claims = JWTCustomClaims(**decode(token, secret_key, alg).to_dict())

        check_claims_instance(claims, decoded_claims)


def test_rsa_pkcs1_algorithms(claims: JWTCustomClaims, rsa_2048_key_pair):
    """Test RSA PKCS#1 v1.5 algorithms with different key usage patterns."""
    rsa_algorithms = [Alg.RS256, Alg.RS384, Alg.RS512]

    for alg in rsa_algorithms:
        # Scenario 1: Raw private/public keys
        token = encode(claims, rsa_2048_key_pair.key_instance_from_private_pem, alg)
        decoded_claims = JWTCustomClaims(
            **decode(token, rsa_2048_key_pair.key_instance_from_public_pem, alg).to_dict()
        )
        check_claims_instance(claims, decoded_claims)

        # Verify with private key (contains public component)
        decoded_with_private = JWTCustomClaims(
            **decode(
                token, rsa_2048_key_pair.key_instance_from_private_pem, alg
            ).to_dict()
        )
        check_claims_instance(claims, decoded_with_private)

        # Scenario 2: Using RSAKey.import_signing_key() / RSAKey.import_verifying_key()
        signing_key = RSAKey.import_private_key(rsa_2048_key_pair.private_pem)
        verifying_key = RSAKey.import_public_key(rsa_2048_key_pair.public_pem)

        token2 = encode(claims, signing_key, alg)
        decoded_claims2 = JWTCustomClaims(**decode(token2, verifying_key, alg).to_dict())
        check_claims_instance(claims, decoded_claims2)

        # Scenario 3: Using RSAKey.import_key(private_key) for both encode and decode
        combined_key = RSAKey.import_key(rsa_2048_key_pair.private_pem)

        token3 = encode(claims, combined_key, alg)
        decoded_claims3 = JWTCustomClaims(**decode(token3, combined_key, alg).to_dict())
        check_claims_instance(claims, decoded_claims3)


def test_rsa_pss_algorithms(claims: JWTCustomClaims, rsa_2048_key_pair):
    """Test RSA-PSS algorithms with different key usage patterns."""
    rsa_pss_algorithms = [Alg.PS256, Alg.PS384, Alg.PS512]

    for alg in rsa_pss_algorithms:
        # Scenario 1: Raw private/public keys
        token = encode(claims, rsa_2048_key_pair.key_instance_from_private_pem, alg)
        decoded_claims = JWTCustomClaims(
            **decode(token, rsa_2048_key_pair.key_instance_from_public_pem, alg).to_dict()
        )
        check_claims_instance(claims, decoded_claims)

        # Verify with private key (contains public component)
        decoded_with_private = JWTCustomClaims(
            **decode(
                token, rsa_2048_key_pair.key_instance_from_private_pem, alg
            ).to_dict()
        )
        check_claims_instance(claims, decoded_with_private)

        # Scenario 2: Using RSAKey.import_signing_key() / RSAKey.import_verifying_key()
        signing_key = RSAKey.import_private_key(rsa_2048_key_pair.private_pem)
        verifying_key = RSAKey.import_public_key(rsa_2048_key_pair.public_pem)

        token2 = encode(claims, signing_key, alg)
        decoded_claims2 = JWTCustomClaims(**decode(token2, verifying_key, alg).to_dict())
        check_claims_instance(claims, decoded_claims2)

        # Scenario 3: Using RSAKey.import_key(private_key) for both encode and decode
        combined_key = RSAKey.import_key(rsa_2048_key_pair.private_pem)

        token3 = encode(claims, combined_key, alg)
        decoded_claims3 = JWTCustomClaims(**decode(token3, combined_key, alg).to_dict())
        check_claims_instance(claims, decoded_claims3)


def test_ecdsa_algorithms(
    claims: JWTCustomClaims,
    ec_p256_key_pair,
    ec_p384_key_pair,
    ec_p521_key_pair,
):
    """Test ECDSA algorithms with different key usage patterns."""
    # Map algorithms to their corresponding key pairs
    ecdsa_test_cases = [
        (Alg.ES256, ec_p256_key_pair),
        (Alg.ES384, ec_p384_key_pair),
        (Alg.ES512, ec_p521_key_pair),
    ]

    for alg, key_pair in ecdsa_test_cases:
        # Scenario 1: Raw private/public keys
        token = encode(claims, key_pair.key_instance_from_private_pem, alg)
        decoded_claims = JWTCustomClaims(
            **decode(token, key_pair.key_instance_from_public_pem, alg).to_dict()
        )
        check_claims_instance(claims, decoded_claims)

        # Verify with private key (contains public component)
        decoded_with_private = JWTCustomClaims(
            **decode(token, key_pair.key_instance_from_private_pem, alg).to_dict()
        )
        check_claims_instance(claims, decoded_with_private)

        # Scenario 2: Using ECKey.import_signing_key() / ECKey.import_verifying_key()
        signing_key = ECKey.import_private_key(key_pair.private_pem)
        verifying_key = ECKey.import_public_key(key_pair.public_pem)

        token2 = encode(claims, signing_key, alg)
        decoded_claims2 = JWTCustomClaims(**decode(token2, verifying_key, alg).to_dict())
        check_claims_instance(claims, decoded_claims2)

        # Scenario 3: Using ECKey.import_key(private_key) for both encode and decode
        combined_key = ECKey.import_key(key_pair.private_pem)

        token3 = encode(claims, combined_key, alg)
        decoded_claims3 = JWTCustomClaims(**decode(token3, combined_key, alg).to_dict())
        check_claims_instance(claims, decoded_claims3)


def test_eddsa_algorithms(claims: JWTCustomClaims, ed25519_key_pair, ed448_key_pair):
    """Test EdDSA algorithms with different key usage patterns."""
    # Map algorithms to their corresponding key pairs
    eddsa_test_cases = [
        (Alg.Ed25519, ed25519_key_pair),
        (Alg.Ed448, ed448_key_pair),
    ]

    for alg, key_pair in eddsa_test_cases:
        # Scenario 1: Raw private/public keys
        token = encode(claims, key_pair.key_instance_from_private_pem, alg)
        decoded_claims = JWTCustomClaims(
            **decode(token, key_pair.key_instance_from_public_pem, alg).to_dict()
        )
        check_claims_instance(claims, decoded_claims)

        # Verify with private key (contains public component)
        decoded_with_private = JWTCustomClaims(
            **decode(token, key_pair.key_instance_from_private_pem, alg).to_dict()
        )
        check_claims_instance(claims, decoded_with_private)

        # Scenario 2: Using OKPKey.import_signing_key() / OKPKey.import_verifying_key()
        signing_key = OKPKey.import_private_key(key_pair.private_pem)
        verifying_key = OKPKey.import_public_key(key_pair.public_pem)

        token2 = encode(claims, signing_key, alg)
        decoded_claims2 = JWTCustomClaims(**decode(token2, verifying_key, alg).to_dict())
        check_claims_instance(claims, decoded_claims2)

        # Scenario 3: Using OKPKey.import_key(private_key) for both encode and decode
        combined_key = OKPKey.import_key(key_pair.private_pem)

        token3 = encode(claims, combined_key, alg)
        decoded_claims3 = JWTCustomClaims(**decode(token3, combined_key, alg).to_dict())
        check_claims_instance(claims, decoded_claims3)


def test_none_algorithm_rejection(secret_key: str):
    """Test that 'none' algorithm is explicitly rejected for security."""
    claims = {"sub": "user123", "iss": "test"}

    # Test 1: Encoding with 'none' algorithm should fail
    with pytest.raises(InvalidAlgorithmError, match="not a valid JWS algorithm"):
        encode(claims, secret_key, "none")  # type: ignore

    # Test 2: Decoding a token with 'none' algorithm in header should fail
    # Manually craft a token with 'none' algorithm
    none_header = urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    none_payload = urlsafe_b64encode(json.dumps(claims).encode())
    none_signature = b""  # 'none' algorithm has empty signature
    none_token = b".".join([none_header, none_payload, none_signature])

    # Should fail when trying to decode with any valid algorithm
    # The library correctly rejects 'none' during header validation
    with pytest.raises(HeadersValidationError, match="not a valid algorithm"):
        decode(none_token, secret_key, Alg.HS256)

    # Test 3: Using Alg enum should not have 'none'
    assert "none" not in [alg.value for alg in Alg]


def test_algorithm_downgrade_attack_prevention(secret_key: str, rsa_2048_key_pair):
    """Test protection against algorithm downgrade attacks.

    An attacker might try to change the algorithm in the header from RS256 to HS256
    and use the public key as the HMAC secret to forge signatures.
    """
    claims = {"sub": "admin", "role": "user"}

    # Create a legitimate RS256 token
    rsa_private_key = RSAKey.import_private_key(rsa_2048_key_pair.private_pem)
    rsa_public_key = RSAKey.import_public_key(rsa_2048_key_pair.public_pem)
    legitimate_token = encode(claims, rsa_private_key, Alg.RS256)

    # Verify the legitimate token works
    decoded = decode(legitimate_token, rsa_public_key, Alg.RS256)
    assert decoded.to_dict()["sub"] == "admin"

    # Test 1: Try to decode RS256 token with HS256 algorithm (should fail)
    with pytest.raises(AlgorithmMismatchError, match="does not match"):
        decode(legitimate_token, secret_key, Alg.HS256)

    # Test 2: Verify that algorithm from token must match expected algorithm
    hs256_token = encode(claims, secret_key, Alg.HS256)
    with pytest.raises(AlgorithmMismatchError):
        decode(hs256_token, secret_key, Alg.HS384)


def test_algorithm_substitution_attack(secret_key: str):
    """Test that algorithm substitution between similar algorithms is prevented."""
    claims = {"sub": "user123"}

    # Create token with HS256
    token_hs256 = encode(claims, secret_key, Alg.HS256)

    # Try to verify with HS384 (different algorithm) - should fail
    with pytest.raises(AlgorithmMismatchError):
        decode(token_hs256, secret_key, Alg.HS384)

    # Try to verify with HS512 - should fail
    with pytest.raises(AlgorithmMismatchError):
        decode(token_hs256, secret_key, Alg.HS512)


def test_cross_algorithm_family_attack(
    secret_key: str, rsa_2048_key_pair, ec_p256_key_pair
):
    """Test that tokens from different algorithm families cannot be interchanged."""
    claims = {"sub": "user123"}

    # HMAC token
    hmac_token = encode(claims, secret_key, Alg.HS256)

    # RSA token
    rsa_key = RSAKey.import_private_key(rsa_2048_key_pair.private_pem)
    rsa_token = encode(claims, rsa_key, Alg.RS256)

    # ECDSA token
    ec_key = ECKey.import_private_key(ec_p256_key_pair.private_pem)
    ec_token = encode(claims, ec_key, Alg.ES256)

    # Try to decode HMAC token with RSA algorithm - should fail
    with pytest.raises(AlgorithmMismatchError):
        decode(hmac_token, rsa_key, Alg.RS256)

    # Try to decode RSA token with ECDSA algorithm - should fail
    with pytest.raises(AlgorithmMismatchError):
        decode(rsa_token, ec_key, Alg.ES256)

    # Try to decode ECDSA token with HMAC algorithm - should fail
    with pytest.raises(AlgorithmMismatchError):
        decode(ec_token, secret_key, Alg.HS256)
