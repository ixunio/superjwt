import json
from typing import Any, Literal, cast

from pydantic import SecretBytes, ValidationError

from superjwt.algorithms import BaseJWSAlgorithm, NoneAlgorithm
from superjwt.definitions import (
    MAX_TOKEN_LENGTH,
    Algorithm,
    JOSEHeader,
    JWSToken,
    JWSTokenLifeCycle,
    JWTHeadersValidationDefault,
    get_effective_data_model,
    get_effective_data_validation_model,
    get_jws_algorithm,
    prepare_and_validate_data,
)
from superjwt.exceptions import (
    HeaderValidationError,
    InvalidHeaderError,
    JWTError,
    MalformedTokenError,
    SignatureVerificationFailedError,
    SizeExceededError,
)
from superjwt.keys import BaseKey
from superjwt.utils import as_bytes, urlsafe_b64decode, urlsafe_b64encode


class JWS:
    def __init__(
        self,
        algorithm: Algorithm | Literal["none"],
        max_token_size: int = MAX_TOKEN_LENGTH,
    ):
        self.token: JWSTokenLifeCycle = JWSTokenLifeCycle()
        self.algorithm: BaseJWSAlgorithm[BaseKey] = get_jws_algorithm(algorithm)

        self.has_detached_payload: bool = False

        self.raw_jws: bytes = b""
        self.max_size = max_token_size
        self._allow_none_algorithm = False

    def reset(self) -> None:
        self.token = JWSTokenLifeCycle()
        self.raw_jws = b""
        self.has_detached_payload = False

    def enable_detached_payload(self):
        self.has_detached_payload = True
        self.token.unsafe.encoded.has_detached_payload = True
        self.token.validated.encoded.has_detached_payload = True

    def encode(
        self,
        headers: JOSEHeader | dict[str, Any] | None,
        payload: dict[str, Any],
        key: BaseKey,
        *,
        validation_headers: type[JOSEHeader] | None = JWTHeadersValidationDefault,
    ) -> bytes:
        if self.token.validated.encoded.compact != b"..":
            raise JWTError("JWS instance data must be reset")

        # prepare headers data and perform validation
        if headers is None:
            headers = JOSEHeader.make_default(cast("Algorithm", self.algorithm.name))
        validation_headers = get_effective_data_validation_model(
            headers, validation_headers, default=JOSEHeader
        )
        try:
            headers_dict = prepare_and_validate_data(
                data=headers,
                validation_model=validation_headers,
                type_err_msg="headers must be a JOSEHeader instance or a dict",
            )
        except ValidationError as e:
            raise HeaderValidationError(validation_errors=e.errors()) from e

        # set headers data
        default_headers_model = get_effective_data_model(
            headers, validation_headers, default=JOSEHeader
        )
        self.token.validated.model.headers = cast(
            "JOSEHeader", default_headers_model.model_construct(**headers_dict)
        )
        self.token.validated.decoded.headers = headers_dict
        self.token.validated.encoded.headers = urlsafe_b64encode(
            json.dumps(headers_dict, separators=(",", ":")).encode("utf-8")
        )

        # set payload data
        self.token.validated.decoded.payload = payload
        self.token.validated.encoded.payload = urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )

        # set signature data
        signature = self.algorithm.sign(self.token.validated.encoded.signing_input, key)
        self.token.validated.decoded.signature = SecretBytes(signature)
        self.token.validated.encoded.signature = SecretBytes(urlsafe_b64encode(signature))

        return self.token.validated.encoded.compact

    def decode(
        self,
        token: str | bytes,
        key: BaseKey,
        *,
        with_detached_payload: dict[str, Any] | None = None,
        validation_headers: type[JOSEHeader] | None = JWTHeadersValidationDefault,
    ) -> JWSToken:
        if (
            self.token.validated.encoded.compact != b".."
            or self.token.unsafe.encoded.compact != b".."
        ):
            raise JWTError("JWS instance data must be reset")

        # decode JWT token parts
        self.decode_parts(token, with_detached_payload)

        # validate headers and algorithm
        self.validate_headers_and_algorithm(validation_headers)

        # verify signature
        self.verify_signature(key)
        return self.token.validated

    def decode_parts(
        self, token: str | bytes, detached_payload: dict[str, Any] | None = None
    ) -> None:
        if len(token) > self.max_size:
            raise SizeExceededError(
                f"Token size ({len(token)} bytes) exceeds maximum of {self.max_size} bytes"
            )

        if token is not None:
            self.raw_jws = as_bytes(token)

        self.extract_parts()

        # decode headers
        self.decode_raw_headers()

        # decode payload
        if self.has_detached_payload:
            if detached_payload is None:
                self.token.unsafe.decoded.payload = {}
                self.token.unsafe.encoded.payload = urlsafe_b64encode(b"")
            else:
                self.token.unsafe.decoded.payload = detached_payload
                self.token.unsafe.encoded.payload = urlsafe_b64encode(
                    json.dumps(detached_payload, separators=(",", ":")).encode("utf-8")
                )
        else:
            self.decode_raw_payload()

        # decode signature
        self.decode_raw_signature()

    def extract_parts(self) -> tuple[bytes, bytes]:
        token = self.raw_jws.strip(b".")
        try:
            signing_input, signature = token.rsplit(b".", 1)
            header, payload = signing_input.split(b".")
        except ValueError as e:
            raise MalformedTokenError(
                "Token must have exactly 3 parts separated by dots"
            ) from e
        if len(header) == 0:
            raise InvalidHeaderError("Header is empty")
        if self.has_detached_payload and payload != b"":
            raise MalformedTokenError("Detached payload conflict")

        self.token.unsafe.encoded.headers = header
        self.token.unsafe.encoded.payload = payload
        self.token.unsafe.encoded.signature = SecretBytes(signature)

        return header, payload

    @staticmethod
    def _decode_raw_part(name: str, data: bytes) -> bytes:
        try:
            decoded = urlsafe_b64decode(data)
            return decoded
        except ValueError as e:
            raise MalformedTokenError(f"{name} is not a valid Base64url") from e

    @staticmethod
    def _decode_dict_part(name: str, data: bytes) -> dict[str, Any]:
        try:
            decoded = json.loads(data)
            if not isinstance(decoded, dict):
                raise MalformedTokenError(f"{name} does not result in a mapping")
            for k in decoded.keys():
                if not isinstance(k, str):
                    raise MalformedTokenError(f"{name} mapping contains non-string key")
            return decoded
        except ValueError as e:
            raise MalformedTokenError(f"{name} segment is not valid JSON") from e

    def decode_raw_headers(self) -> dict[str, Any]:
        decoded = self._decode_raw_part("headers", self.token.unsafe.encoded.headers)
        self.token.unsafe.decoded.headers = decoded_dict = self._decode_dict_part(
            "headers", decoded
        )
        return decoded_dict

    def decode_raw_payload(self) -> dict[str, Any]:
        decoded = self._decode_raw_part("payload", self.token.unsafe.encoded.payload)
        self.token.unsafe.decoded.payload = decoded_dict = self._decode_dict_part(
            "payload", decoded
        )
        return decoded_dict

    def decode_raw_signature(self) -> None:
        self.token.unsafe.decoded.signature = SecretBytes(
            self._decode_raw_part(
                "signature", self.token.unsafe.encoded.signature.get_secret_value()
            )
        )

    def validate_headers_and_algorithm(
        self,
        validation_model: type[JOSEHeader] | None,
    ) -> None:
        headers_dict = self.token.unsafe.decoded.headers

        # validate headers
        try:
            prepare_and_validate_data(
                data=headers_dict,
                validation_model=validation_model,
            )
        except ValidationError as e:
            raise HeaderValidationError(validation_errors=e.errors()) from e

        # set headers model data
        headers_dict = self.token.unsafe.decoded.headers
        headers_model = get_effective_data_model(
            headers_dict, validation_model, default=JOSEHeader
        )
        self.token.unsafe.model.headers = headers_validated = cast(
            "JOSEHeader", headers_model.model_construct(**headers_dict)
        )

        # check algorithm match
        pass_through = self.algorithm.name == "none" and self._allow_none_algorithm
        if not pass_through and headers_validated.alg != self.algorithm.name:
            raise InvalidHeaderError(
                f"JWS algorithm '{headers_validated.alg}' does not match expected '{self.algorithm.name}'"
            )

    def verify_signature(self, key: BaseKey) -> bool:
        if isinstance(self.algorithm, NoneAlgorithm) and not self._allow_none_algorithm:
            raise JWTError("None algorithm is not allowed")
        self.algorithm.check_key(key)

        if not self.algorithm.verify(
            self.token.unsafe.encoded.signing_input,
            self.token.unsafe.decoded.signature.get_secret_value(),
            key,
        ):
            raise SignatureVerificationFailedError()

        if not isinstance(self.algorithm, NoneAlgorithm):
            self.token.validated = self.token.unsafe.model_copy()
            self.token.unsafe = JWSToken()

        return True
