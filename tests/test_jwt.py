import json
from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import Field, ValidationError
from superjwt import decode, encode, inspect
from superjwt.algorithms import Alg
from superjwt.exceptions import (
    ClaimsValidationError,
    HeadersValidationError,
    InvalidHeadersError,
    InvalidPayloadError,
    InvalidTokenError,
    SignatureVerificationError,
    SizeExceededError,
    SuperJWTError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from superjwt.jwt import JWT
from superjwt.keys import ECKey, OKPKey, RSAKey
from superjwt.utils import urlsafe_b64encode
from superjwt.validations import (
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    JWTDatetimeFloat,
    Validation,
    ValidationConfig,
)

from .conftest import JWTCustomClaims, check_claims_instance, requires_cryptography


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


def test_decode_returns_pydantic_instance_consistent_with_payload(
    jwt: JWT, claims_dict: dict[str, Any], secret_key: str
):
    """Verify that decode() returns pydantic instance and understand payload vs model relationship."""

    # Test 1: Dict claims with default validation
    compact = encode(claims_dict, secret_key, Alg.HS256)

    # Module-level decode returns pydantic instance
    decoded_pydantic = decode(compact, secret_key, Alg.HS256)
    assert isinstance(decoded_pydantic, JWTBaseModel)

    # JWT.decode returns JWSToken with the pydantic instance (model.claims) and payload
    jws_token = jwt.decode(compact, secret_key, Alg.HS256)

    # Verify module-level decode() returns an equivalent Pydantic instance
    assert decoded_pydantic == jws_token.model.claims
    assert decoded_pydantic.to_dict() == jws_token.model.claims.to_dict()

    # The payload contains serialized data (dict input had floats, but JWTDatetimeInt serialized them to int)
    assert isinstance(jws_token.payload["iat"], int)
    assert isinstance(jws_token.payload["exp"], int)

    # Model.claims has deserialized datetime objects
    if isinstance(decoded_pydantic, JWTClaims):
        assert isinstance(decoded_pydantic.iat, datetime)
        assert isinstance(decoded_pydantic.exp, datetime)

    # Verify the invariant: payload matches model.claims.to_dict()
    assert jws_token.payload == jws_token.model.claims.to_dict()

    # Test 2: Pydantic claims with custom model
    claims_pydantic = JWTCustomClaims(**claims_dict)
    compact2 = encode(claims_pydantic, secret_key, Alg.HS256, validation=JWTCustomClaims)

    decoded_pydantic2 = decode(
        compact2, secret_key, Alg.HS256, validation=JWTCustomClaims
    )
    assert isinstance(decoded_pydantic2, JWTCustomClaims)

    jws_token2 = jwt.decode(compact2, secret_key, Alg.HS256, validation=JWTCustomClaims)

    # Module-level decode returns an equivalent model.claims instance
    assert decoded_pydantic2 == jws_token2.model.claims
    assert decoded_pydantic2.to_dict() == jws_token2.model.claims.to_dict()

    # Test 3: With validation disabled
    compact3 = encode(claims_dict, secret_key, Alg.HS256, validation=Validation.DISABLE)

    decoded_pydantic3 = decode(
        compact3, secret_key, Alg.HS256, validation=Validation.DISABLE
    )
    assert isinstance(decoded_pydantic3, JWTBaseModel)

    jws_token3 = jwt.decode(
        compact3, secret_key, Alg.HS256, validation=Validation.DISABLE
    )

    # Module-level decode returns an equivalent model.claims instance
    assert decoded_pydantic3 == jws_token3.model.claims
    assert decoded_pydantic3.to_dict() == jws_token3.model.claims.to_dict()


def test_payload_vs_model_claims_relationship(jwt: JWT, secret_key: str):
    """Document and test the relationship between payload dict and model.claims pydantic instance."""
    now = datetime.now(UTC)

    claims = JWTClaims(
        sub="user123",
        iat=now,
        exp=now + timedelta(hours=1),
        nbf=now + timedelta(minutes=5),
    )

    compact = jwt.encode(claims, secret_key, Alg.HS256).compact

    # Spoof time to after nbf to allow decoding
    spoofed_now = now + timedelta(minutes=10)
    jws_token = jwt.decode(
        compact,
        secret_key,
        Alg.HS256,
        validation=ValidationConfig(model=JWTClaims, now=spoofed_now),
    )

    # Standard claims (iat, exp, nbf) are stored as int timestamps
    assert isinstance(jws_token.payload["iat"], int)
    assert isinstance(jws_token.payload["exp"], int)
    assert isinstance(jws_token.payload["nbf"], int)

    # The model.claims is a validated Pydantic instance
    assert isinstance(jws_token.model.claims, JWTClaims)
    assert jws_token.model.claims.sub == "user123"
    assert isinstance(jws_token.model.claims.iat, datetime)
    assert isinstance(jws_token.model.claims.exp, datetime)
    assert isinstance(jws_token.model.claims.nbf, datetime)

    model_dict = jws_token.model.claims.to_dict()

    assert model_dict["sub"] == jws_token.payload["sub"]
    assert model_dict["iat"] == jws_token.payload["iat"]
    assert model_dict["exp"] == jws_token.payload["exp"]
    assert model_dict["nbf"] == jws_token.payload["nbf"]

    decoded = decode(
        compact,
        secret_key,
        Alg.HS256,
        validation=ValidationConfig(model=JWTClaims, now=spoofed_now),
    )
    assert decoded == jws_token.model.claims
    assert decoded.to_dict() == jws_token.model.claims.to_dict()
    assert decoded.to_dict() == model_dict


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
    decoded = decode(compact, secret_key, Alg.HS256).to_dict()
    assert decoded["custom_date"] == custom_dt_serializable_str

    # can encode integer timestamp
    compact = encode({"custom_date": custom_dt_correct}, secret_key, Alg.HS256)
    decoded = decode(compact, secret_key, Alg.HS256).to_dict()
    assert decoded["custom_date"] == custom_dt_correct


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


def test_encode_decode_pydantic_claims(
    jwt: JWT, claims_dict: dict[str, Any], secret_key: str
):
    claims = JWTCustomClaims(**claims_dict)

    compact = jwt.encode(claims, secret_key, Alg.HS256).compact
    decoded_claims = JWTCustomClaims(**jwt.decode(compact, secret_key, Alg.HS256).payload)

    check_claims_instance(claims, decoded_claims)

    # test non compliant claims
    claims = JWTCustomClaims(**claims_dict)
    claims.aud = 123  # invalid type for aud  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256)

    # test custom claims model validation
    claims = JWTCustomClaims(**claims_dict)
    # encoding valid
    jws_token = jwt.encode(claims, secret_key, Alg.HS256)
    jws_token2 = jwt.encode(claims, secret_key, Alg.HS256, validation=JWTCustomClaims)
    assert jws_token.compact == jws_token2.compact
    # decoding
    claims.user_id = None  # invalid type for user_id  # type: ignore
    compact = jwt.encode(
        claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact
    # passes (validation with default JWTClaims)
    jwt.decode(compact, secret_key, Alg.HS256)
    # fails (validation with JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(compact, secret_key, Alg.HS256, validation=JWTCustomClaims)


def test_decode_invalid_signature(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    wrong_key = "wrongkey_but_long_enough"
    compact = jwt.encode(claims, secret_key, Alg.HS256).compact

    with pytest.raises(SignatureVerificationError):
        jwt.decode(compact, wrong_key, Alg.HS256)


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
        validation=Validation.DISABLE,
    ).compact

    with pytest.raises(ClaimsValidationError):
        jwt.decode(compact, secret_key_random, Alg.HS256, validation=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact, secret_key_random, Alg.HS256
        )  # fails (default JWTClaims validation)

    decoded = jwt.decode(
        compact, secret_key_random, Alg.HS256, validation=Validation.DISABLE
    ).payload
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims.sub  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime
    check_claims_instance(claims, decoded_claims)


def test_encode_decode_claims_dict_validation_disabled(
    jwt: JWT, claims_dict: dict[str, Any], exp: float, secret_key_random: str
):
    # prepare an invalid claims dict
    unvalidated_claims_dict = claims_dict.copy()
    unvalidated_claims_dict["sub"] = 1  # invalid type for sub
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            unvalidated_claims_dict, secret_key_random, Alg.HS256
        )  # fails (default JWTClaims validation)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            unvalidated_claims_dict,
            secret_key_random,
            Alg.HS256,
            validation=JWTClaims,
        )
    # run encoding again with validation disabled, does not raise error
    compact = jwt.encode(
        unvalidated_claims_dict,
        secret_key_random,
        Alg.HS256,
        validation=Validation.DISABLE,
    ).compact
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact, secret_key_random, Alg.HS256
        )  # fails (default JWTClaims validation)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(compact, secret_key_random, Alg.HS256, validation=JWTClaims)
    # run decoding again with validation disabled, does not raise error
    decoded = jwt.decode(
        compact, secret_key_random, Alg.HS256, validation=Validation.DISABLE
    ).payload
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims_dict["sub"]  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime as int timestamp
    claims = JWTCustomClaims(**claims_dict)  # the original claims data
    check_claims_instance(claims, decoded_claims)


def test_custom_claims_validation(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    # test with a wrong object type for validation parameter
    with pytest.raises(TypeError):
        jwt.encode(claims, secret_key, Alg.HS256, validation="not_a_model")  # type: ignore

    claims.sub = None  # remove required field 'sub'  # type: ignore

    jwt.encode(
        claims, secret_key, Alg.HS256, validation=JWTClaims
    )  # passes because compliant with JWTClaims
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256, validation=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims, secret_key, Alg.HS256
        )  # same as validation=JWTCustomClaims (pydantic object is validated by default)

    claims.aud = 123  # invalid registered claim  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims, secret_key, Alg.HS256, validation=JWTClaims
        )  # no more compliant with JWTClaims (aud should be str | list[str] | None)

    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256, validation=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256)  # same as validation=JWTCustomClaims

    compact = jwt.encode(
        claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact  # create token anyway
    with pytest.raises(ClaimsValidationError):
        jwt.decode(compact, secret_key, Alg.HS256)  # fails (default JWTClaims validation)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact, secret_key, Alg.HS256, validation=JWTClaims
        )  # fails JWTClaims validation (aud wrong type)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(compact, secret_key, Alg.HS256, validation=JWTCustomClaims)
    decoded_claims = jwt.decode(
        compact, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).payload
    with pytest.raises(ValidationError):
        JWTCustomClaims(**decoded_claims)

    # test detached payload
    jwt.encode(claims, secret_key, Alg.HS256, validation=Validation.DISABLE)
    compact_detached = jwt.detach_payload().compact  # switch to detached mode
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact_detached,
            secret_key,
            Alg.HS256,
            with_detached_payload=claims.to_dict(),
        )  # fails (default JWTClaims validation)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact_detached,
            secret_key,
            Alg.HS256,
            validation=JWTClaims,
            with_detached_payload=claims.to_dict(),
        )
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            compact_detached,
            secret_key,
            Alg.HS256,
            validation=JWTCustomClaims,
            with_detached_payload=claims.to_dict(),
        )
    jwt.decode(
        compact_detached,
        secret_key,
        Alg.HS256,
        with_detached_payload=claims.to_dict(),
        validation=Validation.DISABLE,
    )  # passes


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

    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims_dict, secret_key, Alg.HS256
        )  # fails (default JWTClaims validation)
    jwt.encode(
        claims_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    )  # passes (validation disabled)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, Alg.HS256, validation=JWTClaims)

    # nbf <= iat is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "nbf": (now - timedelta(minutes=5)).timestamp(),
    }
    jwt.encode(
        claims_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    )  # passes (validation disabled)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, Alg.HS256, validation=JWTClaims)

    # nbf >= exp is forbidden (token would never be valid)
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "nbf": (now + timedelta(days=5)).timestamp(),
        "exp": (now + timedelta(minutes=5)).timestamp(),
    }
    jwt.encode(
        claims_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    )  # no validation
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, Alg.HS256, validation=JWTClaims)


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
    with pytest.raises(SignatureVerificationError):
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


def test_payload_model_claims_consistency_detached(jwt: JWT, claims_fixed_dt, secret_key):
    """Verify module-level decode() works correctly with detached payload."""
    compact_detached = encode(claims_fixed_dt, secret_key, Alg.HS256, detach_payload=True)

    jws_token = jwt.decode(
        compact_detached, secret_key, Alg.HS256, with_detached_payload=claims_fixed_dt
    )

    decoded_pydantic = decode(
        compact_detached, secret_key, Alg.HS256, with_detached_payload=claims_fixed_dt
    )

    # Verify module-level decode() returns an equivalent model.claims pydantic instance
    assert isinstance(decoded_pydantic, JWTBaseModel)
    assert decoded_pydantic == jws_token.model.claims
    assert decoded_pydantic.to_dict() == jws_token.model.claims.to_dict()

    assert jws_token.payload == claims_fixed_dt.to_dict()


def test_payload_model_claims_consistency_with_timestamp_fields(jwt: JWT, secret_key):
    """Verify timestamp serialization works correctly with JWTDatetimeInt vs JWTDatetimeFloat."""

    now = datetime.now(UTC)
    claims_int = JWTClaims(sub="user123", iat=now, exp=now + timedelta(hours=1))

    compact = jwt.encode(claims_int, secret_key, Alg.HS256).compact
    jws_token = jwt.decode(compact, secret_key, Alg.HS256)

    # Payload contains int timestamps (JWTDatetimeInt)
    assert isinstance(jws_token.payload["iat"], int)
    assert isinstance(jws_token.payload["exp"], int)

    # Module-level decode returns equivalent pydantic instance
    decoded = decode(compact, secret_key, Alg.HS256)
    assert decoded == jws_token.model.claims
    assert decoded.to_dict() == jws_token.model.claims.to_dict()
    assert isinstance(decoded, JWTClaims)
    assert isinstance(decoded.iat, datetime)
    assert isinstance(decoded.exp, datetime)

    # Test with custom JWTDatetimeFloat field
    class FloatClaims(JWTClaims):
        exp: JWTDatetimeFloat = Field(default=...)  # type: ignore

    claims_float = FloatClaims(sub="user456", iat=now, exp=now + timedelta(hours=2))

    compact2 = jwt.encode(
        claims_float, secret_key, Alg.HS256, validation=FloatClaims
    ).compact
    jws_token2 = jwt.decode(compact2, secret_key, Alg.HS256, validation=FloatClaims)

    # Payload has mixed int/float timestamps
    assert isinstance(jws_token2.payload["iat"], int)  # JWTDatetimeInt
    assert isinstance(jws_token2.payload["exp"], float)  # JWTDatetimeFloat

    # Module-level decode returns equivalent pydantic instance
    decoded2 = decode(compact2, secret_key, Alg.HS256, validation=FloatClaims)
    assert decoded2 == jws_token2.model.claims
    assert isinstance(decoded2, FloatClaims)
    assert isinstance(decoded2.iat, datetime)
    assert isinstance(decoded2.exp, datetime)


def test_expired_token(jwt: JWT, secret_key: str):
    claims = JWTClaims.model_construct(exp=datetime.now(UTC) - timedelta(days=1))
    compact = jwt.encode(
        claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact
    with pytest.raises(TokenExpiredError):
        jwt.encode(claims, secret_key, Alg.HS256)
    with pytest.raises(TokenExpiredError):
        jwt.decode(compact, secret_key, Alg.HS256)  # fails (default JWTClaims validation)
    decoded_claims = jwt.decode(
        compact, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).payload
    assert decoded_claims["exp"] == claims.to_dict()["exp"]
    with pytest.raises(TokenExpiredError):
        jwt.decode(compact, secret_key, Alg.HS256, validation=JWTClaims)

    # test with dict
    past_exp_dict = {
        "sub": "test_user",
        "exp": (datetime.now(UTC) - timedelta(days=365)).timestamp(),
    }
    compact_dict = jwt.encode(
        past_exp_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact
    with pytest.raises(TokenExpiredError):
        jwt.decode(compact_dict, secret_key, Alg.HS256, validation=JWTClaims)


def test_not_yet_valid_token(jwt: JWT, secret_key: str):
    claims = JWTClaims.model_construct(nbf=datetime.now(UTC) + timedelta(days=1))
    compact = jwt.encode(
        claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact
    # nbf validation only happens during decode, not encode
    jwt.encode(claims, secret_key, Alg.HS256)
    with pytest.raises(TokenNotYetValidError):
        jwt.decode(compact, secret_key, Alg.HS256)  # fails (default JWTClaims validation)
    decoded_claims = jwt.decode(
        compact, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).payload
    assert decoded_claims["nbf"] == claims.to_dict()["nbf"]
    with pytest.raises(TokenNotYetValidError):
        jwt.decode(compact, secret_key, Alg.HS256, validation=JWTClaims)

    # test with dict
    future_nbf_dict = {
        "sub": "test_user",
        "nbf": (datetime.now(UTC) + timedelta(days=365)).timestamp(),
    }
    compact_dict = jwt.encode(
        future_nbf_dict, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact
    with pytest.raises(TokenNotYetValidError):
        jwt.decode(compact_dict, secret_key, Alg.HS256, validation=JWTClaims)


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
        valid_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact
    decoded = jwt.decode(compact, secret_key, Alg.HS256, validation=Validation.DISABLE)
    assert decoded.payload["iat"] == int(past_iat.timestamp())
    assert decoded.payload["nbf"] == int(past_nbf.timestamp())
    assert decoded.payload["exp"] == int(past_exp.timestamp())

    # Test encoding with past exp WITHOUT iat (validation disabled), then decode with validation
    past_exp_claims = JWTClaims.model_construct(
        sub="user123", exp=now - timedelta(hours=1)
    )
    compact_expired = jwt.encode(
        past_exp_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact

    # Decoding with validation enabled should fail
    with pytest.raises(TokenExpiredError):
        jwt.decode(compact_expired, secret_key, Alg.HS256, validation=JWTClaims)

    # Test encoding with future nbf WITHOUT iat (validation disabled), then decode with validation
    future_nbf_claims = JWTClaims.model_construct(
        sub="user123", nbf=now + timedelta(hours=1)
    )
    compact_not_yet = jwt.encode(
        future_nbf_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact

    # Decoding with validation enabled should fail
    with pytest.raises(TokenNotYetValidError):
        jwt.decode(compact_not_yet, secret_key, Alg.HS256, validation=JWTClaims)


def test_claims_model_data(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    # encode + claims as pydantic
    token = jwt.encode(claims, secret_key, Alg.HS256, validation=JWTCustomClaims)
    assert isinstance(token.model.claims, JWTCustomClaims)
    token = jwt.encode(claims, secret_key, Alg.HS256)
    assert isinstance(token.model.claims, JWTCustomClaims)
    token = jwt.encode(claims, secret_key, Alg.HS256, validation=Validation.DISABLE)
    assert isinstance(token.model.claims, JWTBaseModel)

    # encode + claims as dict
    token = jwt.encode(
        claims.to_dict(), secret_key, Alg.HS256, validation=JWTCustomClaims
    )
    assert isinstance(token.model.claims, JWTCustomClaims)
    token = jwt.encode(claims.to_dict(), secret_key, Alg.HS256)
    assert isinstance(token.model.claims, JWTBaseModel)
    token = jwt.encode(
        claims.to_dict(), secret_key, Alg.HS256, validation=Validation.DISABLE
    )
    compact = token.compact
    assert isinstance(token.model.claims, JWTBaseModel)

    # decode
    token = jwt.decode(compact, secret_key, Alg.HS256, validation=JWTCustomClaims)
    assert isinstance(token.model.claims, JWTCustomClaims)
    token = jwt.decode(compact, secret_key, Alg.HS256)
    assert isinstance(token.model.claims, JWTBaseModel)
    token = jwt.decode(compact, secret_key, Alg.HS256, validation=Validation.DISABLE)
    assert isinstance(token.model.claims, JWTBaseModel)


def test_custom_headers_validation(jwt: JWT, secret_key: str):
    # test with a wrong object type for headers_validation
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
    jwt_strict = JWT()

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
        invalid_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact
    # Decode with validation=Validation.DISABLE should pass (no validation)
    jwt_strict.decode(
        compact_unvalidated, secret_key, Alg.HS256, validation=Validation.DISABLE
    )
    # Decode without specifying validation should fail (uses custom default)
    with pytest.raises(ClaimsValidationError):
        jwt_strict.decode(compact_unvalidated, secret_key, Alg.HS256)

    # Same for invalid_dates_claims
    compact_invalid_dates = jwt_strict.encode(
        invalid_dates_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
    ).compact
    # Decode with validation=Validation.DISABLE should pass (no validation)
    jwt_strict.decode(
        compact_invalid_dates, secret_key, Alg.HS256, validation=Validation.DISABLE
    )
    # Decode without specifying validation should fail (uses custom default)
    with pytest.raises(ClaimsValidationError):
        jwt_strict.decode(compact_invalid_dates, secret_key, Alg.HS256)

    # Compare with default JWT instance behavior (no validation for dict claims)
    jwt_lenient = JWT(default_claims_validation=ValidationConfig(model=JWTBaseModel))
    jwt_lenient.encode(invalid_claims, secret_key, Alg.HS256)  # passes without validation


def test_custom_default_headers_validation_policy(secret_key: str):
    """Test JWT instance with custom default headers validation policy."""

    class CustomHeader(JOSEHeader):
        custom_header: str

    # Create JWT instance with custom headers validation by default
    custom_validation_config = ValidationConfig(
        model=CustomHeader,
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
    custom_validation_config = ValidationConfig(
        model=JWTClaims,  # Validate against JWTClaims
        forward_pydantic_model=False,  # Don't force Pydantic model type
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
        jwt_custom.decode(compact, secret_key, Alg.HS256, validation=JWTCustomClaims)

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


def test_hmac_algorithms(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    hmac_algorithms = [Alg.HS256, Alg.HS384, Alg.HS512]

    for alg in hmac_algorithms:
        token = jwt.encode(claims, secret_key, alg).compact
        decoded_claims = JWTCustomClaims(**jwt.decode(token, secret_key, alg).payload)

        check_claims_instance(claims, decoded_claims)


@requires_cryptography
def test_rsa_pkcs1_algorithms(jwt: JWT, claims: JWTCustomClaims, rsa_2048_key_pair):
    """Test RSA PKCS#1 v1.5 algorithms with different key usage patterns."""
    rsa_algorithms = [Alg.RS256, Alg.RS384, Alg.RS512]

    for alg in rsa_algorithms:
        # Scenario 1: Raw private/public keys
        token = jwt.encode(
            claims, rsa_2048_key_pair.key_instance_from_private_pem, alg
        ).compact
        decoded_claims = JWTCustomClaims(
            **jwt.decode(
                token, rsa_2048_key_pair.key_instance_from_public_pem, alg
            ).payload
        )
        check_claims_instance(claims, decoded_claims)

        # Verify with private key (contains public component)
        decoded_with_private = JWTCustomClaims(
            **jwt.decode(
                token, rsa_2048_key_pair.key_instance_from_private_pem, alg
            ).payload
        )
        check_claims_instance(claims, decoded_with_private)

        # Scenario 2: Using RSAKey.import_signing_key() / RSAKey.import_verifying_key()
        signing_key = RSAKey.import_private_key(rsa_2048_key_pair.private_pem)
        verifying_key = RSAKey.import_public_key(rsa_2048_key_pair.public_pem)

        token2 = jwt.encode(claims, signing_key, alg).compact
        decoded_claims2 = JWTCustomClaims(
            **jwt.decode(token2, verifying_key, alg).payload
        )
        check_claims_instance(claims, decoded_claims2)

        # Scenario 3: Using RSAKey.import_key(private_key) for both encode and decode
        combined_key = RSAKey.import_key(rsa_2048_key_pair.private_pem)

        token3 = jwt.encode(claims, combined_key, alg).compact
        decoded_claims3 = JWTCustomClaims(**jwt.decode(token3, combined_key, alg).payload)
        check_claims_instance(claims, decoded_claims3)


@requires_cryptography
def test_rsa_pss_algorithms(jwt: JWT, claims: JWTCustomClaims, rsa_2048_key_pair):
    """Test RSA-PSS algorithms with different key usage patterns."""
    rsa_pss_algorithms = [Alg.PS256, Alg.PS384, Alg.PS512]

    for alg in rsa_pss_algorithms:
        # Scenario 1: Raw private/public keys
        token = jwt.encode(
            claims, rsa_2048_key_pair.key_instance_from_private_pem, alg
        ).compact
        decoded_claims = JWTCustomClaims(
            **jwt.decode(
                token, rsa_2048_key_pair.key_instance_from_public_pem, alg
            ).payload
        )
        check_claims_instance(claims, decoded_claims)

        # Verify with private key (contains public component)
        decoded_with_private = JWTCustomClaims(
            **jwt.decode(
                token, rsa_2048_key_pair.key_instance_from_private_pem, alg
            ).payload
        )
        check_claims_instance(claims, decoded_with_private)

        # Scenario 2: Using RSAKey.import_signing_key() / RSAKey.import_verifying_key()
        signing_key = RSAKey.import_private_key(rsa_2048_key_pair.private_pem)
        verifying_key = RSAKey.import_public_key(rsa_2048_key_pair.public_pem)

        token2 = jwt.encode(claims, signing_key, alg).compact
        decoded_claims2 = JWTCustomClaims(
            **jwt.decode(token2, verifying_key, alg).payload
        )
        check_claims_instance(claims, decoded_claims2)

        # Scenario 3: Using RSAKey.import_key(private_key) for both encode and decode
        combined_key = RSAKey.import_key(rsa_2048_key_pair.private_pem)

        token3 = jwt.encode(claims, combined_key, alg).compact
        decoded_claims3 = JWTCustomClaims(**jwt.decode(token3, combined_key, alg).payload)
        check_claims_instance(claims, decoded_claims3)


@requires_cryptography
def test_ecdsa_algorithms(
    jwt: JWT,
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
        token = jwt.encode(claims, key_pair.key_instance_from_private_pem, alg).compact
        decoded_claims = JWTCustomClaims(
            **jwt.decode(token, key_pair.key_instance_from_public_pem, alg).payload
        )
        check_claims_instance(claims, decoded_claims)

        # Verify with private key (contains public component)
        decoded_with_private = JWTCustomClaims(
            **jwt.decode(token, key_pair.key_instance_from_private_pem, alg).payload
        )
        check_claims_instance(claims, decoded_with_private)

        # Scenario 2: Using ECKey.import_signing_key() / ECKey.import_verifying_key()
        signing_key = ECKey.import_private_key(key_pair.private_pem)
        verifying_key = ECKey.import_public_key(key_pair.public_pem)

        token2 = jwt.encode(claims, signing_key, alg).compact
        decoded_claims2 = JWTCustomClaims(
            **jwt.decode(token2, verifying_key, alg).payload
        )
        check_claims_instance(claims, decoded_claims2)

        # Scenario 3: Using ECKey.import_key(private_key) for both encode and decode
        combined_key = ECKey.import_key(key_pair.private_pem)

        token3 = jwt.encode(claims, combined_key, alg).compact
        decoded_claims3 = JWTCustomClaims(**jwt.decode(token3, combined_key, alg).payload)
        check_claims_instance(claims, decoded_claims3)


@requires_cryptography
def test_eddsa_algorithms(
    jwt: JWT, claims: JWTCustomClaims, ed25519_key_pair, ed448_key_pair
):
    """Test EdDSA algorithms with different key usage patterns."""
    # Map algorithms to their corresponding key pairs
    eddsa_test_cases = [
        (Alg.Ed25519, ed25519_key_pair),
        (Alg.Ed448, ed448_key_pair),
    ]

    for alg, key_pair in eddsa_test_cases:
        # Scenario 1: Raw private/public keys
        token = jwt.encode(claims, key_pair.key_instance_from_private_pem, alg).compact
        decoded_claims = JWTCustomClaims(
            **jwt.decode(token, key_pair.key_instance_from_public_pem, alg).payload
        )
        check_claims_instance(claims, decoded_claims)

        # Verify with private key (contains public component)
        decoded_with_private = JWTCustomClaims(
            **jwt.decode(token, key_pair.key_instance_from_private_pem, alg).payload
        )
        check_claims_instance(claims, decoded_with_private)

        # Scenario 2: Using OKPKey.import_signing_key() / OKPKey.import_verifying_key()
        signing_key = OKPKey.import_private_key(key_pair.private_pem)
        verifying_key = OKPKey.import_public_key(key_pair.public_pem)

        token2 = jwt.encode(claims, signing_key, alg).compact
        decoded_claims2 = JWTCustomClaims(
            **jwt.decode(token2, verifying_key, alg).payload
        )
        check_claims_instance(claims, decoded_claims2)

        # Scenario 3: Using OKPKey.import_key(private_key) for both encode and decode
        combined_key = OKPKey.import_key(key_pair.private_pem)

        token3 = jwt.encode(claims, combined_key, alg).compact
        decoded_claims3 = JWTCustomClaims(**jwt.decode(token3, combined_key, alg).payload)
        check_claims_instance(claims, decoded_claims3)
