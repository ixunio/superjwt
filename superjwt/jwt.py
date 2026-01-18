import logging
from typing import Any

from pydantic import ValidationError

from superjwt.algorithms import Alg
from superjwt.exceptions import ClaimsValidationError, SuperJWTError
from superjwt.jws import JWS, MAX_TOKEN_BYTES, JWSToken
from superjwt.keys import Key, NoneKey
from superjwt.validations import (
    JOSEHeader,
    JWTBaseModel,
    JWTClaimsDefaultValidation,
    JWTHeadersDefaultValidation,
    Operation,
    Validation,
    ValidationConfig,
    get_validation_config,
)


logger = logging.getLogger(__name__)


class JWT:
    def __init__(
        self,
        max_token_bytes: int = MAX_TOKEN_BYTES,
        default_claims_validation: ValidationConfig = JWTClaimsDefaultValidation,
        default_headers_validation: ValidationConfig = JWTHeadersDefaultValidation,
    ) -> None:
        self.jws: JWS

        self.max_token_bytes = max_token_bytes
        self.default_claims_validation = default_claims_validation
        self.default_headers_validation = default_headers_validation

    def encode(
        self,
        claims: JWTBaseModel | dict[str, Any] | None,
        key: Key | bytes | str,
        algorithm: Alg | str,
        *,
        headers: JOSEHeader | dict[str, Any] | None = None,
        validation: type[JWTBaseModel]
        | ValidationConfig
        | Validation
        | None = Validation.DEFAULT,
        headers_validation: type[JOSEHeader]
        | ValidationConfig
        | Validation
        | None = Validation.DEFAULT,
    ) -> JWSToken:
        """Encode and sign the claims as a JWT token

        Args:
            claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
            key (Key | bytes | str): The key instance to sign the JWT with.
            algorithm (Algorithm): The algorithm to use for signing the JWT.
                Will default to 'HS256' (HMAC with SHA-256).
            headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
                in the JWT. Will use default JWS headers if not provided.
            validation (type[JWTBaseModel] | ValidationConfig | Validation | None, opt.):
                Validation configuration for claims. Can be a pydantic model class, a ValidationConfig
                instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
                or None (no validation).
            headers_validation (type[JOSEHeader] | ValidationConfig | Validation | None, opt.):
                Validation configuration for headers. Can be a pydantic model class, a ValidationConfig
                instance, Validation.DEFAULT (uses default validation), Validation.DISABLE (no validation),
                or None (no validation).

        Returns:
            JWSToken: a JWSToken instance representing the encoded and signed JWT token.
        """

        self.jws = JWS(
            algorithm,
            max_token_bytes=self.max_token_bytes,
            default_headers_validation=self.default_headers_validation,
        )

        # prepare claims data and perform validation
        if claims is None:
            claims = JWTBaseModel()
        claims_validation = self.get_claims_validation(claims, validation)

        try:
            claims_pydantic, claims_dict = claims_validation.run(
                claims, operation=Operation.ENCODE
            )
        except ValidationError as e:
            raise ClaimsValidationError(validation_errors=e.errors()) from e

        # encode as JWS
        self.jws.encode(
            headers=headers,
            payload=claims_dict,
            key=key,
            headers_validation=headers_validation,
        )

        # set claims model data
        self.jws.token.verified.model.claims = claims_pydantic

        return self.jws.token.verified

    def detach_payload(self) -> JWSToken:
        """Declare payload detached from JWT compact.
            The encoded payload part will be b""

        Returns:
            JWSToken: a JWSToken instance representing the encoded and signed JWT token.
        """
        if not hasattr(self, "jws") or not self.jws.token.verified:
            raise SuperJWTError("JWT token has not been encoded yet")
        self.jws.enable_detached_payload()

        return self.jws.token.verified

    def decode(
        self,
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
    ) -> JWSToken:
        """Decode the JWT token with signature verification.

        Args:
            compact (bytes | str): The JWT compact token to decode.
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
            JWSToken: a JWSToken instance representing the decoded and verified JWT token.
        """

        self.jws = JWS(
            algorithm,
            max_token_bytes=self.max_token_bytes,
            default_headers_validation=self.default_headers_validation,
        )

        # CASE 1: detached payload mode
        if with_detached_payload is not None:
            self.jws.enable_detached_payload()
            claims_validation = self.get_claims_validation(
                with_detached_payload, validation
            )

            # prepare detached claims data and validate
            try:
                claims_pydantic, claims_dict = claims_validation.run(
                    with_detached_payload, operation=Operation.DECODE
                )
            except ValidationError as e:
                raise ClaimsValidationError(validation_errors=e.errors()) from e

            # JWS decode
            self.jws.decode(
                compact,
                key,
                with_detached_payload=claims_dict,
                headers_validation=headers_validation,
            )

        # CASE 2: normal mode
        else:
            # JWS decode
            self.jws.decode(compact, key, headers_validation=headers_validation)
            claims_dict = self.jws.token.verified.payload
            claims_validation = self.get_claims_validation(claims_dict, validation)

            # validate claims
            try:
                claims_pydantic, _ = claims_validation.run(
                    claims_dict, operation=Operation.DECODE
                )
            except ValidationError as e:
                raise ClaimsValidationError(validation_errors=e.errors()) from e

        # set claims model data
        self.jws.token.verified.model.claims = claims_pydantic

        return self.jws.token.verified

    def inspect(
        self,
        compact: bytes | str,
        has_detached_payload: bool = False,
    ) -> JWSToken:
        """Decode the JWT token without signature verification.
        For debugging purposes only. Never to be used in production.

        Args:
            compact (bytes | str): The JWT compact token to decode.
            has_detached_payload (bool, opt.): If True, indicates that the token has a detached payload.

        Returns:
            JWSToken: a JWSToken instance representing the unsafe non-verified decoded JWT token.
        """
        from superjwt.algorithms import NoneAlgorithm

        self.jws = JWS(NoneAlgorithm(), max_token_bytes=self.max_token_bytes)

        if has_detached_payload:
            self.jws.enable_detached_payload()

        self.jws._allow_none_algorithm = True
        self.jws.decode(
            compact=compact, key=NoneKey(), headers_validation=Validation.DISABLE
        )
        self.jws._allow_none_algorithm = False

        return self.jws.token.unsafe

    def get_claims_validation(
        self,
        data: JWTBaseModel | dict[str, Any],
        validation: type[JWTBaseModel] | ValidationConfig | Validation | None,
    ) -> ValidationConfig:
        return get_validation_config(data, validation, self.default_claims_validation)
