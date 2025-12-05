import json
from typing import Any, Literal

from pydantic import SecretBytes, ValidationError

from superjwt.algorithms import BaseJWSAlgorithm, NoneAlgorithm
from superjwt.definitions import (
    MAX_TOKEN_LENGTH,
    Algorithm,
    JOSEHeader,
    JWSToken,
    JWSTokenLifeCycle,
    JWTClaims,
    get_jws_algorithm,
)
from superjwt.exceptions import (
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
        crit_headers_strict_check: bool = False,
    ):
        self.token: JWSTokenLifeCycle = JWSTokenLifeCycle()
        self.algorithm: BaseJWSAlgorithm[BaseKey] = get_jws_algorithm(algorithm)

        self.has_detached_payload: bool = False

        self.raw_jws: bytes = b""
        self.max_size = max_token_size
        self.crit_headers_strict_check = crit_headers_strict_check
        self.allow_none_algorithm = False

    def encode(
        self,
        header: JOSEHeader,
        payload: JWTClaims,
        key: BaseKey,
    ) -> bytes:
        header_dict: dict[str, Any] = header.to_dict()
        encoded_header = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
        self.token.validated.decoded.header = header_dict
        self.token.validated.encoded.header = urlsafe_b64encode(encoded_header)

        payload_dict: dict[str, Any] = payload.to_dict()
        encoded_payload = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
        self.token.validated.decoded.payload = payload_dict
        self.token.validated.encoded.payload = urlsafe_b64encode(encoded_payload)

        signature = self.algorithm.sign(self.token.validated.encoded.signing_input, key)
        self.token.validated.decoded.signature = SecretBytes(signature)
        self.token.validated.encoded.signature = SecretBytes(urlsafe_b64encode(signature))
        return self.token.validated.encoded.compact

    def detach_payload(self):
        self.token.validated.encoded.has_detached_payload = True

    def decode(
        self,
        token: str | bytes,
        key: BaseKey,
        *,
        with_detached_payload: JWTClaims | None = None,
        disable_headers_validation: bool = False,
    ) -> JWSToken:
        # reset token object
        self.token = JWSTokenLifeCycle()

        # decode JWT token parts
        self.decode_parts(token, with_detached_payload)

        # validate headers
        if not disable_headers_validation:
            self.validate_header()

        # verify signature
        self.verify_signature(key)
        return self.token.validated

    def decode_parts(
        self, token: str | bytes, detached_payload: JWTClaims | None = None
    ) -> None:
        if len(token) > self.max_size:
            raise SizeExceededError(
                f"Token size ({len(token)} bytes) exceeds maximum of {self.max_size} bytes"
            )
        # decode detached payload if present
        if detached_payload is not None:
            self.has_detached_payload = True

        if token is not None:
            self.raw_jws = as_bytes(token)

        self.extract_parts()

        # decode headers
        self.decode_raw_headers()

        # decode payload
        if self.has_detached_payload and detached_payload is not None:
            payload_dict: dict[str, Any] = detached_payload.to_dict()
            encoded_payload = json.dumps(payload_dict, separators=(",", ":")).encode(
                "utf-8"
            )
            self.token.unsafe.decoded.payload = payload_dict
            self.token.unsafe.encoded.payload = urlsafe_b64encode(encoded_payload)
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

        self.token.unsafe.encoded.header = header
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
        decoded = self._decode_raw_part("header", self.token.unsafe.encoded.header)
        self.token.unsafe.decoded.header = decoded_dict = self._decode_dict_part(
            "header", decoded
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

    def validate_header(self) -> bool:
        if not self.token.unsafe.decoded.header:
            raise JWTError("JWS header was not decoded yet")

        # check headers
        try:
            header = JOSEHeader.model_validate(
                self.token.unsafe.decoded.header, context=self.crit_headers_strict_check
            )
        except ValidationError as e:
            raise InvalidHeaderError("JWS header contains invalid data") from e

        if header.alg != self.algorithm.name:
            raise InvalidHeaderError(
                f"JWS algorithm '{header.alg}' does not match expected '{self.algorithm.name}'"
            )

        return True

    def verify_signature(self, key: BaseKey) -> bool:
        if isinstance(self.algorithm, NoneAlgorithm) and not self.allow_none_algorithm:
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

        return True
