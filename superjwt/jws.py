import json
from typing import Any, cast

from pydantic import BaseModel, ValidationError, computed_field

from superjwt.algorithms import BaseJWSAlgorithm
from superjwt.exceptions import (
    AlgorithmMismatchError,
    HeadersValidationError,
    InvalidHeadersError,
    InvalidPayloadError,
    InvalidTokenError,
    SignatureVerificationError,
    SizeExceededError,
)
from superjwt.keys import Key
from superjwt.shared import get_max_token_bytes
from superjwt.utils import as_bytes, trim_str, urlsafe_b64decode, urlsafe_b64encode
from superjwt.validations import (
    JOSEHeader,
    Operation,
    Validation,
    ValidationConfig,
)


def jws_encode(
    headers: JOSEHeader | dict[str, Any] | None,
    payload_json: str,
    key: Key | bytes | str,
    jws_algorithm: BaseJWSAlgorithm[Key],
    *,
    headers_validation: type[JOSEHeader]
    | ValidationConfig
    | Validation.Flags
    | None = Validation.DEFAULT,
    detach_payload: bool = False,
) -> bytes:
    key = prepare_signing_key(key, jws_algorithm)

    segments = []

    if headers is None:
        segments.append(
            urlsafe_b64encode(json.dumps({"alg": jws_algorithm.name}).encode("utf-8"))
        )
    else:
        validation = Validation.get(headers, headers_validation, JOSEHeader, JOSEHeader)
        try:
            headers_pydantic, headers_dict, _ = validation.run(headers, dump_dict=True)
        except ValidationError as e:
            raise HeadersValidationError(validation_errors=e.errors()) from e
        headers_pydantic = cast("JOSEHeader", headers_pydantic)
        segments.append(
            urlsafe_b64encode(
                json.dumps(headers_dict, separators=(",", ":")).encode("utf-8")
            )
        )
        # check algorithm match
        if headers_pydantic.alg != jws_algorithm.name:
            raise AlgorithmMismatchError(
                f"Algorithm in headers "
                f"'{trim_str(headers_pydantic.alg, 16)}' "
                f"does not match the encoding algorithm '{jws_algorithm.name}'"
            )

    # add payload
    segments.append(urlsafe_b64encode(payload_json.encode("utf-8")))

    # add signature
    segments.append(urlsafe_b64encode(jws_algorithm.sign(b".".join(segments), key)))

    if detach_payload:
        segments[1] = b""

    compact = b".".join(segments)
    check_compact_size(compact)

    return compact


def jws_decode(
    compact: bytes | str,
    key: Key | bytes | str,
    jws_algorithm: BaseJWSAlgorithm[Key],
    *,
    headers_validation: type[JOSEHeader]
    | ValidationConfig
    | Validation.Flags
    | None = Validation.DEFAULT,
    with_detached_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    check_compact_size(compact)

    key = prepare_verifying_key(key, jws_algorithm)

    # decode JWT token parts
    compact = as_bytes(compact)
    encoded_headers, encoded_payload, encoded_signature = extract_parts(
        compact, with_detached_payload
    )

    # decode headers + validation
    headers = decode_raw_headers(encoded_headers)
    validate_headers_and_algorithm(headers, headers_validation, jws_algorithm)

    # decode payload
    payload = decode_raw_payload(encoded_payload, with_detached_payload)

    # decode signature
    signature = decode_raw_signature(encoded_signature)

    # verify signature
    signing_input = make_signing_input(encoded_headers, encoded_payload)
    verify_signature(signing_input, signature, key, jws_algorithm)

    return payload


def check_compact_size(compact: bytes | str) -> None:
    if len(compact) > get_max_token_bytes():
        raise SizeExceededError(
            f"Token size ({len(compact)} bytes) "
            f"exceeds maximum of {get_max_token_bytes()} bytes"
        )


def extract_parts(
    compact: bytes, with_detached_payload: dict[str, Any] | None = None
) -> tuple[bytes, bytes, bytes]:
    try:
        signing_input, encoded_signature = compact.rsplit(b".", 1)
        encoded_header, encoded_payload = signing_input.split(b".")
    except ValueError as e:
        raise InvalidTokenError(
            "Token must have exactly 3 parts separated by dots"
        ) from e

    if with_detached_payload is not None:
        if encoded_payload != b"":
            raise InvalidTokenError("Detached payload conflict")
        encoded_payload = urlsafe_b64encode(
            json.dumps(with_detached_payload, separators=(",", ":")).encode("utf-8")
        )

    return encoded_header, encoded_payload, encoded_signature


def _decode_dict_part(data: bytes, name: str, exc: type[Exception]) -> dict[str, Any]:
    try:
        decoded = json.loads(data)
        if not isinstance(decoded, dict):
            raise exc(f"{name} data does not result in a mapping")
        return decoded
    except ValueError as e:
        raise exc(f"{name} segment is not a valid JSON") from e


def decode_raw_headers(encoded_headers: bytes) -> dict[str, Any]:
    try:
        decoded = urlsafe_b64decode(encoded_headers)
    except ValueError as e:
        raise InvalidHeadersError("Headers are not encoded as a valid Base64url") from e
    decoded_dict = _decode_dict_part(decoded, "headers", InvalidHeadersError)
    return decoded_dict


def decode_raw_payload(
    encoded_payload: bytes, with_detached_payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    if bool(with_detached_payload):
        return with_detached_payload
    if encoded_payload == b"":
        return {}

    try:
        decoded = urlsafe_b64decode(encoded_payload)
    except ValueError as e:
        raise InvalidPayloadError("Payload is not encoded as a valid Base64url") from e
    decoded_dict = _decode_dict_part(decoded, "payload", InvalidPayloadError)
    return decoded_dict


def decode_raw_signature(encoded_signature: bytes) -> bytes:
    try:
        return urlsafe_b64decode(encoded_signature)
    except ValueError as e:
        raise InvalidTokenError("Signature is not encoded as a valid Base64url") from e


def validate_headers_and_algorithm(
    headers: dict[str, Any],
    headers_validation: type[JOSEHeader] | ValidationConfig | Validation.Flags | None,
    jws_algorithm: BaseJWSAlgorithm[Key],
) -> None:
    validation = Validation.get(headers, headers_validation, JOSEHeader, JOSEHeader)
    try:
        headers_pydantic, _, _ = validation.run(headers, operation=Operation.DECODE)
        headers_pydantic = cast("JOSEHeader", headers_pydantic)
    except ValidationError as e:
        raise HeadersValidationError(validation_errors=e.errors()) from e

    check_algorithm_match(headers_pydantic.alg, jws_algorithm)


def check_algorithm_match(
    value: str,
    jws_algorithm: BaseJWSAlgorithm[Key],
) -> None:
    if value != jws_algorithm.name:
        raise AlgorithmMismatchError(
            f"JWS algorithm '{trim_str(value, 16)}' "
            f"does not match expected '{jws_algorithm.name}'"
        )


def make_signing_input(encoded_headers: bytes, encoded_payload: bytes) -> bytes:
    return b".".join((encoded_headers, encoded_payload))


def verify_signature(
    signing_input: bytes, signature: bytes, key: Key, jws_algorithm: BaseJWSAlgorithm[Key]
) -> None:
    if not jws_algorithm.verify(
        signing_input,
        signature,
        key,
    ):
        raise SignatureVerificationError()


def prepare_signing_key(key: Key | bytes | str, algorithm: BaseJWSAlgorithm[Key]) -> Key:
    if not isinstance(key, Key):
        key = algorithm.key_type.import_signing_key(key)
    return key


def prepare_verifying_key(
    key: Key | bytes | str, algorithm: BaseJWSAlgorithm[Key]
) -> Key:
    if not isinstance(key, Key):
        key = algorithm.key_type.import_verifying_key(key)
    return key


class JWSToken(BaseModel):
    headers: dict[str, Any] = {}
    payload: dict[str, Any] = {}
    signature: bytes = b""

    encoded_headers: bytes = b""
    encoded_payload: bytes = b""
    encoded_signature: bytes = b""

    @computed_field
    @property
    def signing_input(self) -> bytes:
        return b".".join((self.encoded_headers, self.encoded_payload))

    @computed_field
    @property
    def compact(self) -> bytes:
        return b".".join(
            (
                self.encoded_headers,
                self.encoded_payload,
                self.encoded_signature,
            )
        )
