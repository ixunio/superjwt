import json
from typing import Any, cast

from pydantic import BaseModel, ValidationError, computed_field

from superjwt.algorithms import Alg, BaseJWSAlgorithm, NoneAlgorithm
from superjwt.exceptions import (
    AlgorithmMismatchError,
    HeadersValidationError,
    InvalidAlgorithmError,
    InvalidHeadersError,
    InvalidPayloadError,
    InvalidTokenError,
    SignatureVerificationError,
    SizeExceededError,
    SuperJWTError,
)
from superjwt.keys import Key
from superjwt.utils import as_bytes, trim_str, urlsafe_b64decode, urlsafe_b64encode
from superjwt.validations import (
    JOSEHeader,
    JWTBaseModel,
    JWTHeadersDefaultValidation,
    Validation,
    ValidationConfig,
    get_validation_config,
)


MAX_TOKEN_BYTES: int = 16 * 1024  # 16 KB


class JWS:
    def __init__(
        self,
        algorithm: Alg | BaseJWSAlgorithm | str,
        max_token_bytes: int = MAX_TOKEN_BYTES,
        default_headers_validation: ValidationConfig = JWTHeadersDefaultValidation,
    ):
        self.token: JWSTokenLifeCycle = JWSTokenLifeCycle()
        self.algorithm: BaseJWSAlgorithm[Key] = Alg.get_algorithm(algorithm)

        self.has_detached_payload: bool = False

        self.raw_jws: bytes = b""
        self.max_token_bytes = max_token_bytes
        self.default_headers_validation = default_headers_validation
        self._allow_none_algorithm = False

    def reset(self) -> None:
        self.token = JWSTokenLifeCycle()
        self.raw_jws = b""
        self.has_detached_payload = False

    def enable_detached_payload(self):
        self.has_detached_payload = True
        self.token.unsafe.has_detached_payload = True
        self.token.verified.has_detached_payload = True

    def encode(
        self,
        headers: JOSEHeader | dict[str, Any] | None,
        payload: dict[str, Any],
        key: Key | bytes | str,
        *,
        headers_validation: type[JOSEHeader]
        | ValidationConfig
        | Validation
        | None = Validation.DEFAULT,
    ) -> "JWSToken":
        if self.token.verified.compact != b"..":
            raise SuperJWTError("JWS instance data must be reset")

        # prepare key
        key = self.prepare_signing_key(key)

        # prepare headers data and perform validation
        if headers is None:
            headers = JOSEHeader.make_default(self.algorithm.name)
        headers_validation = self.get_headers_validation(headers, headers_validation)

        try:
            headers_pydantic, headers_dict = headers_validation.run(headers)
        except ValidationError as e:
            raise HeadersValidationError(validation_errors=e.errors()) from e

        # set headers data
        self.token.verified.model.headers = cast("JOSEHeader", headers_pydantic)
        self.token.verified.headers = headers_dict
        self.token.verified.encoded_headers = urlsafe_b64encode(
            json.dumps(headers_dict, separators=(",", ":")).encode("utf-8")
        )

        # check algorithm match
        if self.token.verified.model.headers.alg != self.algorithm.name:
            raise AlgorithmMismatchError(
                f"Algorithm in headers "
                f"'{trim_str(self.token.verified.model.headers.alg, 16)}' "
                f"does not match the encoding algorithm '{self.algorithm.name}'"
            )

        # set payload data
        self.token.verified.payload = payload
        self.token.verified.encoded_payload = urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )

        # set signature data
        if isinstance(self.algorithm, NoneAlgorithm) and not self._allow_none_algorithm:
            raise InvalidAlgorithmError("None algorithm is not allowed")

        signature = self.algorithm.sign(self.token.verified.signing_input, key)
        self.token.verified.signature = signature
        self.token.verified.encoded_signature = urlsafe_b64encode(signature)

        # check compact size
        if len(self.token.verified.compact) > self.max_token_bytes:
            raise SizeExceededError(
                f"Token size ({len(self.token.verified.compact)} bytes) "
                f"exceeds maximum of {self.max_token_bytes} bytes"
            )

        return self.token.verified

    def decode(
        self,
        compact: bytes | str,
        key: Key | bytes | str,
        *,
        with_detached_payload: dict[str, Any] | None = None,
        headers_validation: type[JOSEHeader]
        | ValidationConfig
        | Validation
        | None = Validation.DEFAULT,
    ) -> "JWSToken":
        if self.token.verified.compact != b".." or self.token.unsafe.compact != b"..":
            raise SuperJWTError("JWS instance data must be reset")

        # prepare key
        key = self.prepare_verifying_key(key)

        # decode JWT token parts
        self.decode_parts(compact, with_detached_payload)

        # validate headers and algorithm
        headers_validation = self.get_headers_validation(
            self.token.unsafe.headers, headers_validation
        )
        self.validate_headers_and_algorithm(headers_validation)

        # verify signature
        self.verify_signature(key)
        return self.token.verified

    def decode_parts(
        self, compact: bytes | str, detached_payload: dict[str, Any] | None = None
    ) -> None:
        if len(compact) > self.max_token_bytes:
            raise SizeExceededError(
                f"Token size ({len(compact)} bytes) "
                f"exceeds maximum of {self.max_token_bytes} bytes"
            )

        if compact is not None:
            self.raw_jws = as_bytes(compact)

        self.extract_parts()

        # decode headers
        self.decode_raw_headers()

        # decode payload
        if self.has_detached_payload:
            if detached_payload is None:
                self.token.unsafe.payload = {}
                self.token.unsafe.encoded_payload = urlsafe_b64encode(b"")
            else:
                self.token.unsafe.payload = detached_payload
                self.token.unsafe.encoded_payload = urlsafe_b64encode(
                    json.dumps(detached_payload, separators=(",", ":")).encode("utf-8")
                )
        else:
            self.decode_raw_payload()

        # decode signature
        self.decode_raw_signature()

    def extract_parts(self) -> tuple[bytes, bytes]:
        compact = self.raw_jws.strip(b".")
        try:
            signing_input, signature = compact.rsplit(b".", 1)
            header, payload = signing_input.split(b".")
        except ValueError as e:
            raise InvalidTokenError(
                "Token must have exactly 3 parts separated by dots"
            ) from e
        if self.has_detached_payload and payload != b"":
            raise InvalidTokenError("Detached payload conflict")

        self.token.unsafe.encoded_headers = header
        self.token.unsafe.encoded_payload = payload
        self.token.unsafe.encoded_signature = signature

        return header, payload

    @staticmethod
    def _decode_dict_part(data: bytes, name: str, exc: type[Exception]) -> dict[str, Any]:
        try:
            decoded = json.loads(data)
            if not isinstance(decoded, dict):
                raise exc(f"{name} data does not result in a mapping")
            return decoded
        except ValueError as e:
            raise exc(f"{name} segment is not a valid JSON") from e

    def decode_raw_headers(self) -> dict[str, Any]:
        try:
            decoded = urlsafe_b64decode(self.token.unsafe.encoded_headers)
        except ValueError as e:
            raise InvalidHeadersError(
                "Headers are not encoded as a valid Base64url"
            ) from e
        self.token.unsafe.headers = decoded_dict = self._decode_dict_part(
            decoded, "headers", InvalidHeadersError
        )
        return decoded_dict

    def decode_raw_payload(self) -> dict[str, Any]:
        try:
            decoded = urlsafe_b64decode(self.token.unsafe.encoded_payload)
        except ValueError as e:
            raise InvalidPayloadError(
                "Payload is not encoded as a valid Base64url"
            ) from e
        self.token.unsafe.payload = decoded_dict = self._decode_dict_part(
            decoded, "payload", InvalidPayloadError
        )
        return decoded_dict

    def decode_raw_signature(self) -> None:
        try:
            self.token.unsafe.signature = urlsafe_b64decode(
                self.token.unsafe.encoded_signature
            )
        except ValueError as e:
            raise InvalidTokenError(
                "Signature is not encoded as a valid Base64url"
            ) from e

    def prepare_signing_key(self, key: Key | bytes | str) -> Key:
        if not isinstance(key, Key):
            key_type = self.algorithm.key_type
            key = key_type.import_signing_key(key)
        self.algorithm.check_key(key)
        return key

    def prepare_verifying_key(self, key: Key | bytes | str) -> Key:
        if not isinstance(key, Key):
            key_type = self.algorithm.key_type
            key = key_type.import_verifying_key(key)
        self.algorithm.check_key(key)
        return key

    def validate_headers_and_algorithm(
        self, headers_validation: ValidationConfig
    ) -> None:
        # validate headers
        try:
            headers_pydantic, _ = headers_validation.run(
                self.token.unsafe.headers, fallback_model=JOSEHeader
            )
        except ValidationError as e:
            raise HeadersValidationError(validation_errors=e.errors()) from e

        # set headers model data
        headers_pydantic = cast("JOSEHeader", headers_pydantic)
        self.token.unsafe.model.headers = headers_pydantic

        # check algorithm match
        pass_through = self.algorithm.name == "none" and self._allow_none_algorithm
        if not pass_through and headers_pydantic.alg != self.algorithm.name:
            raise AlgorithmMismatchError(
                f"JWS algorithm '{trim_str(headers_pydantic.alg, 16)}' "
                f"does not match expected '{self.algorithm.name}'"
            )

    def verify_signature(self, key: Key) -> bool:
        if isinstance(self.algorithm, NoneAlgorithm) and not self._allow_none_algorithm:
            raise InvalidAlgorithmError("None algorithm is not allowed")
        self.algorithm.check_key(key)

        if not self.algorithm.verify(
            self.token.unsafe.signing_input,
            self.token.unsafe.signature,
            key,
        ):
            raise SignatureVerificationError()

        if not isinstance(self.algorithm, NoneAlgorithm):
            self.token.verified = self.token.unsafe.model_copy()
            self.token.unsafe = JWSToken()

        return True

    def get_headers_validation(
        self,
        data: JOSEHeader | dict[str, Any],
        validation: type[JOSEHeader] | ValidationConfig | Validation | None,
    ) -> ValidationConfig:
        return get_validation_config(data, validation, self.default_headers_validation)


class JWSTokenModel(BaseModel):
    headers: JOSEHeader = JOSEHeader.model_construct()
    claims: JWTBaseModel = JWTBaseModel()


class JWSToken(BaseModel):
    headers: dict[str, Any] = {}
    payload: dict[str, Any] = {}
    signature: bytes = b""

    encoded_headers: bytes = b""
    encoded_payload: bytes = b""
    encoded_signature: bytes = b""
    has_detached_payload: bool = False

    model: JWSTokenModel = JWSTokenModel()

    @computed_field
    @property
    def signing_input(self) -> bytes:
        return b".".join((self.encoded_headers, self.encoded_payload))

    @computed_field
    @property
    def compact(self) -> bytes:
        if self.has_detached_payload:
            return b".".join((self.encoded_headers, b"", self.encoded_signature))
        return b".".join(
            (
                self.encoded_headers,
                self.encoded_payload,
                self.encoded_signature,
            )
        )


class JWSTokenLifeCycle(BaseModel):
    unsafe: JWSToken = JWSToken()
    verified: JWSToken = JWSToken()
