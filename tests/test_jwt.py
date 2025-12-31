from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Any

import pydantic
import pytest
from superjwt import decode, encode
from superjwt.definitions import (
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    JWTDatetime,
    JWTValidationModelConfig,
    check_future_dates,
)
from superjwt.exceptions import (
    ClaimsValidationError,
    HeaderValidationError,
    InvalidHeaderError,
    JWTError,
    SignatureVerificationFailedError,
    TokenExpiredError,
)
from superjwt.jwt import JWT

from tests.conftest import JWTCustomClaims, check_claims_instance


if TYPE_CHECKING:
    from superjwt.definitions import Algorithm

try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


def test_encode_decode_default_claims(secret_key):
    token = encode(None, secret_key, "HS256")
    decoded_claims = decode(token, secret_key, "HS256")
    assert decoded_claims == {}


def test_encode_decode_dict_claims(claims_dict, secret_key):
    token = encode(claims_dict, secret_key, "HS256")
    decoded_claims_dict = decode(token, secret_key, "HS256")

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
        encode({"custom_date": custom_dt_unserializable}, secret_key, "HS256")

    # can encode serializable datetime string, this will not be serialized as a timestamp
    # unlike the standard datetime claims (iat, nbf, exp)
    token = encode({"custom_date": custom_dt_serializable_str}, secret_key, "HS256")
    decoded = decode(token, secret_key, "HS256")
    assert decoded["custom_date"] == custom_dt_serializable_str

    # can encode integer timestamp
    token = encode({"custom_date": custom_dt_correct}, secret_key, "HS256")
    decoded = decode(token, secret_key, "HS256")
    assert decoded["custom_date"] == custom_dt_correct


def test_empty_iat_with_exp(secret_key):
    # custom datetime claim set to None should be handled correctly
    claims = JWTClaims(
        iat=None,
        exp=datetime.strptime(
            "2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z"
        ),
    )
    token = encode(claims, secret_key, "HS256")
    decoded = decode(token, secret_key, "HS256")
    assert "iat" not in decoded


def test_with_expiration_negative():
    # custom datetime claim set to invalid type should be handled correctly
    with pytest.raises(ValueError):
        JWTClaims().with_expiration(minutes=-15)


def test_rewrite_incorrect_exp_type():
    # custom datetime claim set to invalid type should be handled correctly

    class JWTIncorrectExpClaim(JWTClaims):
        iat: JWTDatetime = datetime.now(UTC)
        exp: Annotated[Any, pydantic.AfterValidator(check_future_dates)]  # type: ignore

    with pytest.raises(TypeError):
        JWTIncorrectExpClaim(exp=True)


def test_encode_decode_pydantic_claims(
    jwt: JWT, claims_dict: dict[str, Any], secret_key: str
):
    claims = JWTCustomClaims(**claims_dict)

    token = jwt.encode(claims, secret_key, "HS256")
    decoded_claims = JWTCustomClaims(**jwt.decode(token, secret_key, "HS256"))

    check_claims_instance(claims, decoded_claims)

    # test non compliant claims
    claims = JWTCustomClaims(**claims_dict)
    claims.aud = 123  # invalid type for aud  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, "HS256")

    # test custom claims model validation
    claims = JWTCustomClaims(**claims_dict)
    # encoding valid
    token = jwt.encode(claims, secret_key, "HS256")
    jws_token = jwt.jws.token.validated
    jwt.encode(claims, secret_key, "HS256", validation_claims=JWTCustomClaims)
    jws_token2 = jwt.jws.token.validated
    assert jws_token.encoded.compact == jws_token2.encoded.compact
    # decoding
    claims.user_id = None  # invalid type for user_id  # type: ignore
    token = jwt.encode(claims, secret_key, "HS256", validation_claims=None)
    # passes (validation with default JWTClaims)
    jwt.decode(token, secret_key, "HS256")
    # fails (validation with JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(token, secret_key, "HS256", validation_claims=JWTCustomClaims)


def test_decode_invalid_signature(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    wrong_key = "wrongkey_but_long_enough"
    token = jwt.encode(claims, secret_key, "HS256")

    with pytest.raises(SignatureVerificationFailedError):
        jwt.decode(token, wrong_key, "HS256")


def test_hmac_algorithms(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    hmac_algorithms: list[Algorithm] = ["HS256", "HS384", "HS512"]

    for alg in hmac_algorithms:
        token = jwt.encode(claims, secret_key, alg)
        decoded_claims = JWTCustomClaims(**jwt.decode(token, secret_key, alg))

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
        jwt.encode(unvalidated_claims, secret_key_random, "HS256")
    encoded = jwt.encode(
        unvalidated_claims, secret_key_random, "HS256", validation_claims=None
    )

    with pytest.raises(ClaimsValidationError):
        jwt.decode(encoded, secret_key_random, "HS256", validation_claims=JWTCustomClaims)
    jwt.decode(encoded, secret_key_random, "HS256")  # passes (no validation)
    decoded = jwt.decode(encoded, secret_key_random, "HS256", validation_claims=None)
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
    jwt.encode(
        unvalidated_claims_dict, secret_key_random, "HS256"
    )  # passes (no encode validation as dict)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            unvalidated_claims_dict,
            secret_key_random,
            "HS256",
            validation_claims=JWTClaims,
        )
    # run encoding again with validation disabled, does not raise error
    encoded = jwt.encode(
        unvalidated_claims_dict, secret_key_random, "HS256", validation_claims=None
    )
    jwt.decode(
        encoded, secret_key_random, "HS256"
    )  # passes (no decode validation as dict)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(encoded, secret_key_random, "HS256", validation_claims=JWTClaims)
    # run decoding again with validation disabled, does not raise error
    decoded = jwt.decode(encoded, secret_key_random, "HS256", validation_claims=None)
    decoded_claims = JWTCustomClaims.model_construct(**decoded)

    decoded_claims.sub = claims_dict["sub"]  # fix type for sub to match original claims
    decoded_claims = JWTCustomClaims(
        **decoded_claims.to_dict()
    )  # ensure validation + serialization for datetime
    claims = JWTCustomClaims(**claims_dict)  # the original claims data
    check_claims_instance(claims, decoded_claims)


def test_custom_validation(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    claims.sub = None  # remove required field 'sub'  # type: ignore

    jwt.encode(
        claims, secret_key, "HS256", validation_claims=JWTClaims
    )  # passes because compliant with JWTClaims
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, "HS256", validation_claims=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims, secret_key, "HS256"
        )  # same as validation_claims=JWTCustomClaims (pydantic object is validated by default)

    claims.aud = 123  # invalid registered claim  # type: ignore
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims, secret_key, "HS256", validation_claims=JWTClaims
        )  # no more compliant with JWTClaims (aud should be str | list[str] | None)

    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, "HS256", validation_claims=JWTCustomClaims)
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            claims, secret_key, "HS256"
        )  # same as validation_claims=JWTCustomClaims

    encoded = jwt.encode(
        claims, secret_key, "HS256", validation_claims=None
    )  # create token anyway
    jwt.decode(encoded, secret_key, "HS256")  # passes (no validation)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            encoded, secret_key, "HS256", validation_claims=JWTClaims
        )  # fails JWTClaims validation (aud wrong type)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(encoded, secret_key, "HS256", validation_claims=JWTCustomClaims)
    decoded = jwt.decode(encoded, secret_key, "HS256", validation_claims=None)
    with pytest.raises(pydantic.ValidationError):
        JWTCustomClaims(**decoded)

    # test detached payload
    jwt.encode(claims, secret_key, "HS256", validation_claims=None)
    encoded = jwt.detach_payload()  # switch to detached mode
    jwt.decode(
        encoded, secret_key, "HS256", with_detached_payload=claims.to_dict()
    )  # passes (no validation)
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            encoded,
            secret_key,
            "HS256",
            validation_claims=JWTClaims,
            with_detached_payload=claims.to_dict(),
        )
    with pytest.raises(ClaimsValidationError):
        jwt.decode(
            encoded,
            secret_key,
            "HS256",
            validation_claims=JWTCustomClaims,
            with_detached_payload=claims.to_dict(),
        )


def test_unsupported_b64_header(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    # 'b64' header parameter is not supported
    with pytest.raises(InvalidHeaderError):
        jwt.encode(claims, secret_key, "HS256", headers={"alg": "HS256", "b64": False})


def test_invalid_claims_future_dates(jwt: JWT, secret_key: str):
    now = datetime.now(UTC)

    # exp <= iat is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "exp": (now - timedelta(minutes=5)).timestamp(),
    }

    jwt.encode(claims_dict, secret_key, "HS256")  # no validation
    jwt.encode(claims_dict, secret_key, "HS256", validation_claims=None)  # no validation
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, "HS256", validation_claims=JWTClaims)

    # nbf <= iat is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "nbf": (now - timedelta(minutes=5)).timestamp(),
    }
    jwt.encode(claims_dict, secret_key, "HS256")  # no validation
    jwt.encode(claims_dict, secret_key, "HS256", validation_claims=None)  # no validation
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, "HS256", validation_claims=JWTClaims)

    # nbf >= exp is invalid
    claims_dict = {
        "sub": "user123",
        "iat": now.timestamp(),
        "nbf": (now + timedelta(days=5)).timestamp(),
        "exp": (now + timedelta(minutes=5)).timestamp(),
    }
    jwt.encode(claims_dict, secret_key, "HS256")  # no validation
    jwt.encode(claims_dict, secret_key, "HS256", validation_claims=None)  # no validation
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims_dict, secret_key, "HS256", validation_claims=JWTClaims)


def test_claims_type_error(jwt: JWT, secret_key: str):
    with pytest.raises(TypeError):
        jwt.encode("not_a_dict_or_jwtclaims", secret_key, "HS256")  # type: ignore


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

    encoded_token = jwt.encode(claims_fixed_dt, secret_key, "HS256")
    assert encoded_token.rsplit(b".", 1)[0] == compact.rsplit(b".", 1)[0]

    decoded_claims = jwt.decode(token=compact, key=secret_key)
    assert decoded_claims["sub"] == claims_fixed_dt.sub

    # check the JWT was tampered with
    with pytest.raises(SignatureVerificationFailedError):
        jwt.decode(forged_compact, secret_key, "HS256")

    # decode with no signature verification
    unsafe_token = jwt.inspect(forged_compact)
    assert unsafe_token.decoded.payload["sub"] == forged_claims.sub

    # detached mode
    detached_compact = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b"."
        b"."
        b"7J8anGc2Ytg-vyaTVN0ln2IjouLupxgHXiIEwxTO-oE"
    )
    unsafe_token_detached = jwt.inspect(detached_compact, has_detached_payload=True)
    assert unsafe_token_detached.decoded.payload == {}


def test_detached_payload(jwt: JWT, claims_fixed_dt, secret_key):
    encoded_token = jwt.encode(claims_fixed_dt, secret_key, "HS256")
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
        detached_compact, secret_key, "HS256", with_detached_payload=claims_fixed_dt
    )
    assert decoded == claims_fixed_dt.to_dict()

    decoded = jwt.decode(
        detached_compact,
        secret_key,
        "HS256",
        with_detached_payload=claims_fixed_dt.to_dict(),
    )
    assert decoded == claims_fixed_dt.to_dict()


def test_detached_payload_no_jws_instance(jwt: JWT):
    with pytest.raises(JWTError):
        jwt.detach_payload()


def test_expired_token(jwt: JWT, secret_key: str):
    claims = JWTClaims.model_construct(exp=datetime.now(UTC) - timedelta(days=1))
    token = jwt.encode(claims, secret_key, "HS256", validation_claims=None)
    with pytest.raises(TokenExpiredError):
        jwt.encode(claims, secret_key, "HS256")
    jwt.decode(token, secret_key, "HS256")  # passes (no validation)
    decoded = jwt.decode(token, secret_key, "HS256", validation_claims=None)
    assert decoded["exp"] == claims.to_dict()["exp"]


def test_claims_model_data(jwt: JWT, claims: JWTCustomClaims, secret_key: str):
    # encode + claims as pydantic
    jwt.encode(claims, secret_key, "HS256", validation_claims=JWTCustomClaims)
    assert isinstance(jwt.token.model.claims, JWTCustomClaims)
    jwt.encode(claims, secret_key, "HS256")
    assert isinstance(jwt.token.model.claims, JWTCustomClaims)
    jwt.encode(claims, secret_key, "HS256", validation_claims=None)
    assert isinstance(jwt.token.model.claims, JWTBaseModel)

    # encode + claims as dict
    jwt.encode(claims.to_dict(), secret_key, "HS256", validation_claims=JWTCustomClaims)
    assert isinstance(jwt.token.model.claims, JWTCustomClaims)
    jwt.encode(claims.to_dict(), secret_key, "HS256")
    assert isinstance(jwt.token.model.claims, JWTBaseModel)
    token = jwt.encode(claims.to_dict(), secret_key, "HS256", validation_claims=None)
    assert isinstance(jwt.token.model.claims, JWTBaseModel)

    # decode
    jwt.decode(token, secret_key, "HS256", validation_claims=JWTCustomClaims)
    assert isinstance(jwt.token.model.claims, JWTCustomClaims)
    jwt.decode(token, secret_key, "HS256")
    assert isinstance(jwt.token.model.claims, JWTBaseModel)
    jwt.decode(token, secret_key, "HS256", validation_claims=None)
    assert isinstance(jwt.token.model.claims, JWTBaseModel)


def test_custom_headers_validation(jwt: JWT, secret_key: str):
    class CustomHeader(JOSEHeader):
        custom_header: str

    headers = CustomHeader.model_construct(
        alg="HS256"
    )  # non compliant with CustomHeader, but with JOSEHeader

    # pydantic headers
    jwt.encode(
        {}, secret_key, "HS256", headers=headers, validation_headers=JOSEHeader
    )  # passes
    with pytest.raises(HeaderValidationError):
        jwt.encode({}, secret_key, "HS256", headers=headers)

    # make headers no more compliant with JOSEHeader
    headers.typ = 123  # invalid type for typ # type: ignore
    with pytest.raises(HeaderValidationError):
        jwt.encode(
            {},
            secret_key,
            "HS256",
            headers=headers,
            validation_headers=JOSEHeader,  # no longer compliant (typ should be str)
        )
    with pytest.raises(HeaderValidationError):
        jwt.encode({}, secret_key, "HS256", headers=headers)

    token = jwt.encode({}, secret_key, "HS256", headers=headers, validation_headers=None)
    decoded = jwt.decode(token, secret_key, "HS256", validation_headers=None)
    with pytest.raises(HeaderValidationError):
        jwt.decode(
            token, secret_key, "HS256"
        )  # fails because validation defaults to JOSEHeader
    with pytest.raises(HeaderValidationError):
        jwt.decode(token, secret_key, "HS256", validation_headers=JOSEHeader)
    with pytest.raises(HeaderValidationError):
        jwt.decode(token, secret_key, "HS256", validation_headers=CustomHeader)
    assert decoded == {}


def test_headers_model_data(jwt: JWT, secret_key: str):
    class CustomHeader(JOSEHeader):
        custom_header: str

    headers = CustomHeader(alg="HS256", custom_header="custom_value")

    # encode + headers as pydantic
    jwt.encode({}, secret_key, "HS256", headers=headers, validation_headers=CustomHeader)
    assert isinstance(jwt.token.model.headers, CustomHeader)
    jwt.encode({}, secret_key, "HS256", headers=headers)
    assert isinstance(jwt.token.model.headers, JOSEHeader)
    jwt.encode({}, secret_key, "HS256", headers=headers, validation_headers=None)
    assert isinstance(jwt.token.model.headers, JWTBaseModel)

    # encode + headers as dict
    jwt.encode(
        {},
        secret_key,
        "HS256",
        headers=headers.to_dict(),
        validation_headers=CustomHeader,
    )
    assert isinstance(jwt.token.model.headers, CustomHeader)
    jwt.encode({}, secret_key, "HS256", headers=headers.to_dict())
    assert isinstance(jwt.token.model.headers, JOSEHeader)
    token = jwt.encode(
        {}, secret_key, "HS256", headers=headers.to_dict(), validation_headers=None
    )

    # decode
    assert isinstance(jwt.token.model.headers, JWTBaseModel)
    jwt.decode(token, secret_key, "HS256", validation_headers=CustomHeader)
    assert isinstance(jwt.token.model.headers, CustomHeader)
    jwt.decode(token, secret_key, "HS256")
    assert isinstance(jwt.token.model.headers, JOSEHeader)
    jwt.decode(token, secret_key, "HS256", validation_headers=None)
    assert isinstance(jwt.token.model.headers, JWTBaseModel)


def test_custom_default_claims_validation_policy(
    claims_dict: dict[str, Any], secret_key: str
):
    """Test JWT instance with custom default claims validation policy."""

    # Create JWT instance with strict claims validation by default (JWTClaims)
    custom_validation_config = JWTValidationModelConfig(
        default_validation_model=JWTClaims,
        force_validation_on_pydantic_model=True,
        default_data_model=JWTClaims,
    )
    jwt_strict = JWT(default_claims_validation=custom_validation_config)

    # Valid claims dict should pass validation
    valid_claims = claims_dict.copy()
    token = jwt_strict.encode(valid_claims, secret_key, "HS256")
    decoded = jwt_strict.decode(token, secret_key, "HS256")
    assert decoded["sub"] == valid_claims["sub"]

    # Invalid claims dict should fail validation (aud must be str or list[str])
    invalid_claims = claims_dict.copy()
    invalid_claims["aud"] = 123  # invalid type
    with pytest.raises(ClaimsValidationError):
        jwt_strict.encode(invalid_claims, secret_key, "HS256")

    # Test with invalid future dates (exp <= iat)
    now = datetime.now(UTC)
    invalid_dates_claims = {
        "sub": "user123",
        "iat": now.timestamp(),
        "exp": (now - timedelta(minutes=5)).timestamp(),
    }
    with pytest.raises(ClaimsValidationError):
        jwt_strict.encode(invalid_dates_claims, secret_key, "HS256")

    # Can still override validation on encode/decode
    token_unvalidated = jwt_strict.encode(
        invalid_claims, secret_key, "HS256", validation_claims=None
    )
    # Decode with validation_claims=None should pass (no validation)
    jwt_strict.decode(token_unvalidated, secret_key, "HS256", validation_claims=None)
    # Decode without specifying validation_claims should fail (uses custom default)
    with pytest.raises(ClaimsValidationError):
        jwt_strict.decode(token_unvalidated, secret_key, "HS256")

    # Same for invalid_dates_claims
    token_invalid_dates = jwt_strict.encode(
        invalid_dates_claims, secret_key, "HS256", validation_claims=None
    )
    # Decode with validation_claims=None should pass (no validation)
    jwt_strict.decode(token_invalid_dates, secret_key, "HS256", validation_claims=None)
    # Decode without specifying validation_claims should fail (uses custom default)
    with pytest.raises(ClaimsValidationError):
        jwt_strict.decode(token_invalid_dates, secret_key, "HS256")

    # Compare with default JWT instance behavior (no validation for dict claims)
    jwt_default = JWT()
    jwt_default.encode(invalid_claims, secret_key, "HS256")  # passes without validation


def test_custom_default_headers_validation_policy(secret_key: str):
    """Test JWT instance with custom default headers validation policy."""

    class CustomHeader(JOSEHeader):
        custom_header: str

    # Create JWT instance with custom headers validation by default
    custom_validation_config = JWTValidationModelConfig(
        default_validation_model=CustomHeader,
        force_validation_on_pydantic_model=True,
        default_data_model=CustomHeader,
    )
    jwt_custom = JWT(default_headers_validation=custom_validation_config)

    # Valid custom headers should pass validation
    valid_headers = {"alg": "HS256", "custom_header": "custom_value"}
    token = jwt_custom.encode({}, secret_key, "HS256", headers=valid_headers)
    decoded = jwt_custom.decode(token, secret_key, "HS256")
    assert decoded == {}

    # Missing custom_header should fail validation
    invalid_headers = {"alg": "HS256"}  # missing custom_header
    with pytest.raises(HeaderValidationError):
        jwt_custom.encode({}, secret_key, "HS256", headers=invalid_headers)

    # Can still override validation on encode/decode
    token_unvalidated = jwt_custom.encode(
        {}, secret_key, "HS256", headers=invalid_headers, validation_headers=None
    )
    # Decode with validation_headers=None should pass (no validation)
    jwt_custom.decode(token_unvalidated, secret_key, "HS256", validation_headers=None)
    # Decode without specifying validation_headers should fail (uses custom default)
    with pytest.raises(HeaderValidationError):
        jwt_custom.decode(token_unvalidated, secret_key, "HS256")

    # Compare with default JWT instance behavior (validates with JOSEHeader, not CustomHeader)
    jwt_default = JWT()
    jwt_default.encode(
        {}, secret_key, "HS256", headers=invalid_headers
    )  # passes with JOSEHeader validation


def test_custom_default_claims_validation_policy_no_force_pydantic(
    claims_dict: dict[str, Any], secret_key: str
):
    """Test JWT instance with custom default validation but force_validation_on_pydantic_model=False."""

    # Create JWT instance with custom validation but without forcing Pydantic validation
    # When force_validation_on_pydantic_model=False, Pydantic claims use default_validation_model
    custom_validation_config = JWTValidationModelConfig(
        default_validation_model=JWTClaims,  # Validate against JWTClaims
        force_validation_on_pydantic_model=False,  # Don't force Pydantic model type
        default_data_model=JWTBaseModel,
    )
    jwt_custom = JWT(default_claims_validation=custom_validation_config)

    # Create invalid Pydantic claims (aud has wrong type)
    invalid_claims = JWTCustomClaims.model_construct(**claims_dict)
    invalid_claims.aud = 123  # invalid type  # type: ignore

    # Encode with Pydantic claims should validate against JWTClaims (not JWTCustomClaims)
    # (because force_validation_on_pydantic_model=False and default_validation_model=JWTClaims)
    with pytest.raises(ClaimsValidationError):
        jwt_custom.encode(
            invalid_claims, secret_key, "HS256"
        )  # fails JWTClaims validation

    # Create valid claims according to JWTClaims but invalid for JWTCustomClaims
    # (missing required 'user_id' field from JWTCustomClaims)
    partial_claims = JWTCustomClaims.model_construct(**claims_dict)
    partial_claims.user_id = (
        None  # invalid for JWTCustomClaims but valid for JWTClaims  # type: ignore
    )

    # Should pass because it only validates against JWTClaims (not JWTCustomClaims)
    token = jwt_custom.encode(partial_claims, secret_key, "HS256")
    decoded = jwt_custom.decode(token, secret_key, "HS256")
    assert "user_id" not in decoded  # user_id is None so excluded

    # But explicitly requesting JWTCustomClaims validation should fail
    with pytest.raises(ClaimsValidationError):
        jwt_custom.decode(token, secret_key, "HS256", validation_claims=JWTCustomClaims)

    # Compare with default JWT instance behavior (validates Pydantic models automatically)
    jwt_default = JWT()
    with pytest.raises(ClaimsValidationError):
        jwt_default.encode(
            partial_claims, secret_key, "HS256"
        )  # fails with default behavior (validates against JWTCustomClaims)
