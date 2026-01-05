from typing import Any

from pydantic import BaseModel

from superjwt._version import __version__
from superjwt.definitions import (
    Algorithm,
    JOSEHeader,
    JWSToken,
    JWTBaseModel,
    JWTClaims,
    JWTDatetime,
    Validation,
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
    detach_payload: bool = False,
    claims_validation: type[JWTBaseModel] | Validation | None = Validation.DEFAULT,
    headers_validation: type[JOSEHeader] | Validation | None = Validation.DEFAULT,
) -> bytes:
    """Encode and sign the claims as a JWT token.

    Args:
        claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
        key (str | bytes | BaseKey): The key instance to sign the JWT with.
        algorithm (Algorithm): The algorithm to use for signing the JWT.
        headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
            in the JWT. Will use default JWS headers if not provided.
        detach_payload (bool, opt.): whether to produce a JWT token with detached payload.
        claims_validation (type[JWTBaseModel] | None, opt.): the pydantic model
            to use for claims validation. If None, claims validation is disabled.
            If 'claims' is a pydantic instance, defaults to its pydantic model.
            Otherwise, defaults to JWTBaseModel (i.e. no validation).
        headers_validation (type[JOSEHeader] | None, opt.): the pydantic model
            to use for headers validation. If None, headers validation is disabled.
            If 'headers' is a pydantic instance, defaults to its pydantic model.
            Otherwise, defaults to JOSEHeader (standard JOSE Header).

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
    algorithm: Algorithm,
    *,
    with_detached_payload: JWTClaims | dict[str, Any] | None = None,
    claims_validation: type[JWTBaseModel] | Validation | None = Validation.DEFAULT,
    headers_validation: type[JOSEHeader] | Validation | None = Validation.DEFAULT,
) -> dict[str, Any]:
    """Decode the JWT token with signature verification.

    Args:
        token (str | bytes): The JWT compact token to decode.
        key (str | bytes | BaseKey): The key instance to verify the JWT signature.
        algorithm (Algorithm): The algorithm to use for verifying the JWT.
        with_detached_payload (JWTClaims | dict[str, Any] | None, opt.):
            Detached payload to use for signature verification, if any.
        claims_validation (type[JWTBaseModel] | None, opt.): the pydantic model
            to use for claims validation. If None, claims validation is disabled.
        headers_validation (type[JOSEHeader] | None, opt.): the pydantic model
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
