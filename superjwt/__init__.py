from typing import Any

from superjwt._version import __version__
from superjwt.algorithms import Alg
from superjwt.jws import JWSToken
from superjwt.jwt import JWT
from superjwt.keys import ECKey, Key, OctKey, OKPKey, RSAKey
from superjwt.validations import (
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    JWTDatetimeFloat,
    JWTDatetimeInt,
    Validation,
    ValidationConfig,
)


__all__ = [
    "JWT",
    "Alg",
    "ECKey",
    "JOSEHeader",
    "JWSToken",
    "JWTBaseModel",
    "JWTClaims",
    "JWTDatetimeFloat",
    "JWTDatetimeInt",
    "OKPKey",
    "OctKey",
    "RSAKey",
    "Validation",
    "ValidationConfig",
    "__version__",
    "decode",
    "encode",
    "inspect",
]


def encode(
    claims: JWTBaseModel | dict[str, Any] | None,
    key: Key | bytes | str,
    algorithm: Alg | str,
    *,
    headers: JOSEHeader | dict[str, Any] | None = None,
    detach_payload: bool = False,
    validation: type[JWTBaseModel]
    | ValidationConfig
    | Validation
    | None = Validation.DEFAULT,
    headers_validation: type[JOSEHeader]
    | ValidationConfig
    | Validation
    | None = Validation.DEFAULT,
) -> bytes:
    """Encode and sign the claims as a JWT token.

    Args:
        claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
        key (Key | bytes | str): The key instance to sign the JWT with.
        algorithm (Algorithm): The algorithm to use for signing the JWT.
        headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
            in the JWT. Will use default JWS headers if not provided.
        detach_payload (bool, opt.): whether to produce a JWT token with detached payload.
        validation (type[JWTBaseModel] | ValidationConfig | Validation | None, opt.):
            Validation configuration for claims. Can be a pydantic model class, a ValidationConfig
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (no validation).
        headers_validation (type[JOSEHeader] | ValidationConfig | Validation | None, opt.):
            Validation configuration for headers. Can be a pydantic model class, a ValidationConfig
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
        validation=validation,
        headers_validation=headers_validation,
    )

    if detach_payload:
        jws_token = jwt.detach_payload()

    return jws_token.compact


def decode(
    compact: bytes | str,
    key: Key | bytes | str,
    algorithm: Alg | str,
    *,
    with_detached_payload: JWTBaseModel | dict[str, Any] | None = None,
    validation: type[JWTBaseModel]
    | ValidationConfig
    | Validation
    | None = Validation.DEFAULT,
    headers_validation: type[JOSEHeader]
    | ValidationConfig
    | Validation
    | None = Validation.DEFAULT,
) -> JWTBaseModel:
    """Decode the JWT token with signature verification.

    Args:
        token (bytes | str): The JWT compact token to decode.
        key (Key | bytes | str): The key instance to verify the JWT signature.
        algorithm (Algorithm): The algorithm to use for verifying the JWT.
        with_detached_payload (JWTBaseModel | dict[str, Any] | None, opt.):
            Detached payload to use for signature verification, if any.
        validation (type[JWTBaseModel] | ValidationConfig | Validation | None, opt.):
            Validation configuration for claims. Can be a pydantic model class, a ValidationConfig
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (no validation).
        headers_validation (type[JOSEHeader] | ValidationConfig | Validation | None, opt.):
            Validation configuration for headers. Can be a pydantic model class, a ValidationConfig
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
        validation=validation,
        headers_validation=headers_validation,
    )

    return jws_token.model.claims


def inspect(
    compact: bytes | str,
    has_detached_payload: bool = False,
) -> JWSToken:
    """Decode the JWT token without signature verification.
    For debugging purposes only. Never to be used in production.

    Args:
        compact (bytes | str): The JWT compact token to decode.
        has_detached_payload (bool, opt.): If True, indicates that the token has a detached payload.

    Returns:
        JWSToken: The unsafe/not verified decoded JWT token as a raw JWSToken instance.
    """

    jwt = JWT()
    jws_token = jwt.inspect(compact, has_detached_payload)

    return jws_token
