from typing import Any

from pydantic import ValidationError

from superjwt.exceptions import ClaimsValidationError
from superjwt.jws import (
    JWSToken,
    check_compact_size,
    decode_raw_headers,
    decode_raw_payload,
    decode_raw_signature,
    extract_parts,
    jws_decode,
    jws_encode,
)
from superjwt.keys import Key
from superjwt.shared import Alg
from superjwt.utils import as_bytes
from superjwt.validations import (
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    Operation,
    Validation,
    ValidationConfig,
)


def encode(
    claims: JWTBaseModel | dict[str, Any] | None,
    key: Key | bytes | str,
    algorithm: Alg | str,
    *,
    headers: JOSEHeader | dict[str, Any] | None = None,
    validation: type[JWTBaseModel]
    | ValidationConfig
    | Validation.Flags
    | None = Validation.DEFAULT,
    headers_validation: type[JOSEHeader]
    | ValidationConfig
    | Validation.Flags
    | None = Validation.DEFAULT,
    detach_payload: bool = False,
) -> bytes:
    """Encode and sign the claims as a JWT token

    Args:
        claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
        key (Key | bytes | str): The key instance to sign the JWT with.
        algorithm (Algorithm): The algorithm to use for signing the JWT.
            Will default to 'HS256' (HMAC with SHA-256).
        headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
            in the JWT. Will use default JWS headers if not provided.
        validation (type[JWTBaseModel] | ValidationConfig | Validation.Flags | None, opt.):
            Validation configuration for claims. Can be a pydantic model class, a ValidationConfig
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (no validation).
        headers_validation (type[JOSEHeader] | ValidationConfig | Validation.Flags | None, opt.):
            Validation configuration for headers. Can be a pydantic model class, a ValidationConfig
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (no validation).
        detach_payload (bool), opt.): If True, indicates that the payload is detached from the JWT.

    Returns:
        bytes: the compact JWT token.
    """

    # prepare claims data and perform validation
    if claims is None:
        claims = JWTBaseModel()
    elif not isinstance(claims, (JWTBaseModel, dict)):
        raise TypeError("Claims must be a JWTBaseModel instance, dict, or None")

    claims_validation = Validation.get(claims, validation, JWTClaims, JWTBaseModel)

    try:
        _, _, claims_json = claims_validation.run(
            claims, operation=Operation.ENCODE, dump_json=True
        )
    except ValidationError as e:
        raise ClaimsValidationError(validation_errors=e.errors()) from e

    # encode as JWS
    return jws_encode(
        headers=headers,
        payload_json=claims_json,
        key=key,
        jws_algorithm=Alg.get_algorithm(algorithm),
        headers_validation=headers_validation,
        detach_payload=detach_payload,
    )


def decode(
    compact: bytes | str,
    key: Key | bytes | str,
    algorithm: Alg | str,
    *,
    validation: type[JWTBaseModel]
    | ValidationConfig
    | Validation.Flags
    | None = Validation.DEFAULT,
    headers_validation: type[JOSEHeader]
    | ValidationConfig
    | Validation.Flags
    | None = Validation.DEFAULT,
    with_detached_payload: JWTBaseModel | dict[str, Any] | None = None,
) -> JWTBaseModel:
    """Decode the JWT token with signature verification.

    Args:
        compact (bytes | str): The JWT compact token to decode.
        key (Key | bytes | str): The key instance to verify the JWT signature.
        algorithm (Algorithm): The algorithm to use for verifying the JWT.
        validation (type[JWTBaseModel] | ValidationConfig | Validation.Flags | None, opt.):
            Validation configuration for claims. Can be a pydantic model class, a ValidationConfig
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (no validation).
        headers_validation (type[JOSEHeader] | ValidationConfig | Validation.Flags | None, opt.):
            Validation configuration for headers. Can be a pydantic model class, a ValidationConfig
            instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
            or None (no validation).
        with_detached_payload (JWTBaseModel | dict[str, Any] | None, opt.):
            Detached payload to use for signature verification, if any.

    Returns:
        JWSToken: a JWSToken instance representing the decoded and verified JWT token.
    """

    # CASE 1: detached payload mode
    if with_detached_payload is not None:
        # prepare detached claims data and validate
        claims_validation = Validation.get(
            with_detached_payload, validation, JWTClaims, JWTBaseModel
        )
        try:
            claims_pydantic, claims_dict, _ = claims_validation.run(
                with_detached_payload, operation=Operation.DECODE, dump_dict=True
            )
        except ValidationError as e:
            raise ClaimsValidationError(validation_errors=e.errors()) from e

        # JWS decode
        jws_decode(
            compact,
            key,
            Alg.get_algorithm(algorithm),
            with_detached_payload=claims_dict,
            headers_validation=headers_validation,
        )

    # CASE 2: normal mode
    else:
        # JWS decode
        claims_dict = jws_decode(
            compact,
            key,
            Alg.get_algorithm(algorithm),
            headers_validation=headers_validation,
        )

        # validate claims
        claims_validation = Validation.get(
            claims_dict, validation, JWTClaims, JWTBaseModel
        )
        try:
            claims_pydantic, _, _ = claims_validation.run(
                claims_dict, operation=Operation.DECODE
            )
        except ValidationError as e:
            raise ClaimsValidationError(validation_errors=e.errors()) from e

    return claims_pydantic


def inspect(compact: bytes | str) -> JWSToken:
    """Decode the JWT token without signature verification.
    For debugging purposes only. Never to be used in production.

    Args:
        compact (bytes | str): The JWT compact token to decode.
        has_detached_payload (bool, opt.): If True, indicates that the token has a detached payload.

    Returns:
        JWSToken: a JWSToken instance representing the unsafe non-verified decoded JWT token.
    """

    check_compact_size(compact)
    token = JWSToken()

    # extract encoded parts
    token.encoded_headers, token.encoded_payload, token.encoded_signature = extract_parts(
        as_bytes(compact)
    )

    # decode parts
    token.headers = decode_raw_headers(token.encoded_headers)
    token.payload = decode_raw_payload(token.encoded_payload)
    token.signature = decode_raw_signature(token.encoded_signature)

    return token
