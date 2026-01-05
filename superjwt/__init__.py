from typing import Any

from superjwt._version import __version__
from superjwt.definitions import (
    Alg,
    JOSEHeader,
    JWSToken,
    JWTBaseModel,
    JWTClaims,
    JWTDatetime,
    JWTDatetimeFloat,
    JWTDatetimeInt,
    JWTValidationCfg,
    Validation,
)
from superjwt.jwt import JWT
from superjwt.keys import BaseKey


__all__ = [
    "JWT",
    "Alg",
    "JOSEHeader",
    "JWTClaims",
    "JWTDatetime",
    "JWTDatetimeFloat",
    "JWTDatetimeInt",
    "__version__",
    "decode",
    "encode",
    "inspect",
]


def encode(
    claims: JWTBaseModel | dict[str, Any] | None,
    key: str | bytes | BaseKey,
    algorithm: Alg | str,
    *,
    headers: JOSEHeader | dict[str, Any] | None = None,
    detach_payload: bool = False,
    claims_validation: type[JWTBaseModel]
    | JWTValidationCfg
    | Validation
    | None = Validation.DEFAULT,
    headers_validation: type[JOSEHeader]
    | JWTValidationCfg
    | Validation
    | None = Validation.DEFAULT,
) -> bytes:
    """Encode and sign the claims as a JWT token.

    Args:
        claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
        key (str | bytes | BaseKey): The key instance to sign the JWT with.
        algorithm (Algorithm): The algorithm to use for signing the JWT.
        headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
            in the JWT. Will use default JWS headers if not provided.
        detach_payload (bool, opt.): whether to produce a JWT token with detached payload.
        claims_validation (type[JWTBaseModel] | JWTValidationCfg | Validation | None, opt.):
            Validation configuration for claims. Can be a pydantic model class, a JWTValidationCfg
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (disables validation).
        headers_validation (type[JOSEHeader] | JWTValidationCfg | Validation | None, opt.):
            Validation configuration for headers. Can be a pydantic model class, a JWTValidationCfg
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (no validation).

    Returns:
        bytes: the encoded compact JWT token
    """

    jwt = JWT()
    jws_token = jwt.encode(
        claims,
        key,
        algorithm,
        headers=headers,
        claims_validation=claims_validation,
        headers_validation=headers_validation,
    )

    if detach_payload:
        jws_token = jwt.detach_payload()

    return jws_token.compact


def decode(
    compact: bytes | str,
    key: str | bytes | BaseKey,
    algorithm: Alg | str,
    *,
    with_detached_payload: JWTClaims | dict[str, Any] | None = None,
    claims_validation: type[JWTBaseModel]
    | JWTValidationCfg
    | Validation
    | None = Validation.DEFAULT,
    headers_validation: type[JOSEHeader]
    | JWTValidationCfg
    | Validation
    | None = Validation.DEFAULT,
) -> dict[str, Any]:
    """Decode the JWT token with signature verification.

    Args:
        token (str | bytes): The JWT compact token to decode.
        key (str | bytes | BaseKey): The key instance to verify the JWT signature.
        algorithm (Algorithm): The algorithm to use for verifying the JWT.
        with_detached_payload (JWTClaims | dict[str, Any] | None, opt.):
            Detached payload to use for signature verification, if any.
        claims_validation (type[JWTBaseModel] | JWTValidationCfg | Validation | None, opt.):
            Validation configuration for claims. Can be a pydantic model class, a JWTValidationCfg
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (disables validation).
        headers_validation (type[JOSEHeader] | JWTValidationCfg | Validation | None, opt.):
            Validation configuration for headers. Can be a pydantic model class, a JWTValidationCfg
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (no validation).

    Returns:
        dict[str, Any]: The decoded and verified JWT claims as a dictionary.
    """

    jwt = JWT()
    jws_token = jwt.decode(
        compact,
        key,
        algorithm,
        with_detached_payload=with_detached_payload,
        claims_validation=claims_validation,
        headers_validation=headers_validation,
    )

    return jws_token.payload


def inspect(
    compact: str | bytes,
    has_detached_payload: bool = False,
) -> JWSToken:
    """Decode the JWT token without signature verification.
    For debugging purposes only. Never to be used in production.

    Args:
        compact (str | bytes): The JWT compact token to decode.
        has_detached_payload (bool, opt.): If True, indicates that the token has a detached payload.

    Returns:
        JWSToken: The unsafe/not verified decoded JWT token as a raw JWSToken instance.
    """

    jwt = JWT()
    jws_token = jwt.inspect(compact, has_detached_payload)

    return jws_token
