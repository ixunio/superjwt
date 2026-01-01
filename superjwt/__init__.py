from typing import Any

from pydantic import BaseModel

from superjwt._version import __version__
from superjwt.definitions import (
    Algorithm,
    DefaultValidation,
    DefaultValidationFlag,
    JOSEHeader,
    JWSToken,
    JWTBaseModel,
    JWTClaims,
    JWTDatetime,
)
from superjwt.jwt import JWT
from superjwt.keys import BaseKey


__all__ = [
    "JWT",
    "JOSEHeader",
    "JWTClaims",
    "JWTDatetime",
    "__version__",
    "decode",
    "encode",
    "inspect",
]


def encode(
    claims: JWTBaseModel | dict[str, Any] | None,
    key: str | bytes | BaseKey,
    algorithm: Algorithm,
    *,
    headers: JOSEHeader | dict[str, Any] | None = None,
    validation_claims: type[BaseModel] | DefaultValidationFlag | None = DefaultValidation,
    validation_headers: type[BaseModel]
    | DefaultValidationFlag
    | None = DefaultValidation,
    detach_payload: bool = False,
) -> bytes:
    """Encode and sign the claims as a JWT token.

    Args:
        claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
        key (str | bytes | BaseKey): The key instance to sign the JWT with.
        algorithm (Algorithm): The algorithm to use for signing the JWT.
        headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
            in the JWT. Will use default JWS headers if not provided.
        validation_claims (type[JWTBaseModel] | None, opt.): the pydantic model
            to use for claims validation. If None, claims validation is disabled.
            If 'claims' is a pydantic instance, defaults to its pydantic model.
            Otherwise, defaults to JWTBaseModel (i.e. no validation).
        validation_headers (type[JOSEHeader] | None, opt.): the pydantic model
            to use for headers validation. If None, headers validation is disabled.
            If 'headers' is a pydantic instance, defaults to its pydantic model.
            Otherwise, defaults to JOSEHeader (standard JOSE Header).
        detach_payload (bool, opt.): whether to produce a JWT token with detached payload.

    Returns:
        bytes: the encoded compact JWT token
    """

    jwt = JWT()
    jws_token = jwt.encode(
        claims,
        key,
        algorithm,
        headers=headers,
        validation_claims=validation_claims,
        validation_headers=validation_headers,
    )

    if detach_payload:
        jws_token = jwt.detach_payload()

    return jws_token.compact


def decode(
    compact: bytes | str,
    key: str | bytes | BaseKey,
    algorithm: Algorithm,
    *,
    with_detached_payload: JWTClaims | dict[str, Any] | None = None,
    validation_claims: type[BaseModel] | DefaultValidationFlag | None = DefaultValidation,
    validation_headers: type[BaseModel]
    | DefaultValidationFlag
    | None = DefaultValidation,
) -> dict[str, Any]:
    """Decode the JWT token with signature verification.

    Args:
        token (str | bytes): The JWT compact token to decode.
        key (str | bytes | BaseKey): The key instance to verify the JWT signature.
        algorithm (Algorithm): The algorithm to use for verifying the JWT.
        with_detached_payload (JWTClaims | dict[str, Any] | None, opt.):
            Detached payload to use for signature verification, if any.
        validation_claims (type[JWTBaseModel] | None, opt.): the pydantic model
            to use for claims validation. If None, claims validation is disabled.
        validation_headers (type[JOSEHeader] | None, opt.): the pydantic model
            to use for headers validation. If None, headers validation is disabled.
            Defaults to JOSEHeader (standard JOSE Header).

    Returns:
        dict[str, Any]: The decoded and verified JWT claims as a dictionary.
    """

    jwt = JWT()
    jws_token = jwt.decode(
        compact,
        key,
        algorithm,
        with_detached_payload=with_detached_payload,
        validation_claims=validation_claims,
        validation_headers=validation_headers,
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
