import logging
from typing import Any

from pydantic import ValidationError

from superjwt.definitions import (
    Algorithm,
    DefaultClaimsValidationModel,
    DefaultHeadersValidationModel,
    JOSEHeader,
    JWSToken,
    JWTBaseModel,
    JWTClaims,
    make_key,
    prepare_and_validate_model,
    select_effective_validation_model,
)
from superjwt.exceptions import (
    ClaimsValidationError,
    JWTError,
)
from superjwt.jws import JWS
from superjwt.keys import BaseKey, NoneKey


logger = logging.getLogger(__name__)


class JWT:
    def __init__(self):
        self.jws: JWS
        self.token: JWSToken

    def reset_token(self) -> None:
        self.token = JWSToken()

    def encode(
        self,
        claims: JWTBaseModel | dict[str, Any] | None,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        claims_validation_model: type[JWTBaseModel] | None = DefaultClaimsValidationModel,
        headers: JOSEHeader | dict[str, Any] | None = None,
        headers_validation_model: type[JOSEHeader] | None = DefaultHeadersValidationModel,
    ) -> bytes:
        """Encode and sign the claims as a JWT token

        Args:
            claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
            key (str | bytes | BaseKey): The key instance to sign the JWT with.
            algorithm (Algorithm): The algorithm to use for signing the JWT.
                Will default to 'HS256' (HMAC with SHA-256).
            claims_validation_model (type[JWTBaseModel] | None, opt.): the pydantic model
                to use for claims validation. If None, claims validation is disabled.
                Default to DefaultClaimsValidationModel.
            headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
                in the JWT. Will use default JWS headers if not provided.
            headers_validation_model (type[JOSEHeader] | None, opt.): the pydantic model
                to use for headers validation. If None, headers validation is disabled.
                Default to DefaultHeadersValidationModel.

        Returns:
            bytes: the encoded compact JWT token
        """

        # reset session
        self.reset_token()

        # prepare claims data and perform validation
        claims = self.prepare_claims(claims, validation_model=claims_validation_model)

        # prepare headers data (validation will be done later in JWS instance)
        headers = JWS.prepare_headers(headers, algorithm, validation_model=None)

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        # encode as JWS
        self.jws = JWS(algorithm)
        self.jws.encode(
            headers=headers,
            payload=claims,
            key=key,
            headers_validation_model=headers_validation_model,
        )
        self.jws.token.validated.model.claims = claims

        self.token = self.jws.token.validated
        return self.token.encoded.compact

    def detach_payload(self) -> bytes:
        """Declare payload detached from JWT compact.
            The encoded payload part will be b""

        Returns:
            bytes: the compact JWT token with an empty payload bytes instead
        """
        if not hasattr(self, "jws") or not self.jws.token.validated:
            raise JWTError("JWT token has not been encoded yet")
        self.jws.enable_detached_payload()

        return self.token.encoded.compact

    @staticmethod
    def prepare_claims(
        claims: JWTBaseModel | dict[str, Any] | None,
        validation_model: type[JWTBaseModel] | None,
    ) -> JWTBaseModel:
        EffectiveValidationModel = select_effective_validation_model(
            claims,
            validation_model,
            DefaultClaimsValidationModel,
        )

        try:
            return prepare_and_validate_model(
                data=claims,
                EffectiveValidationModel=EffectiveValidationModel,
                type_err_msg="claims must be a JWTBaseModel instance or a dict",
                disable_validation=validation_model is None,
            )
        except ValidationError as e:
            raise ClaimsValidationError(validation_errors=e.errors()) from e

    def decode(
        self,
        token: str | bytes,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        with_detached_payload: JWTClaims | dict[str, Any] | None = None,
        claims_validation_model: type[JWTBaseModel] | None = DefaultClaimsValidationModel,
        headers_validation_model: type[JOSEHeader] | None = DefaultHeadersValidationModel,
    ) -> dict[str, Any]:
        """Decode the JWT token with signature verification.

        Args:
            token (str | bytes): The JWT token to decode.
            key (str | bytes | BaseKey): The key instance to verify the JWT signature.
            algorithm (Algorithm): The algorithm to use for verifying the JWT.
            with_detached_payload (JWTClaims | dict[str, Any] | None, opt.):
                Detached payload to use for signature verification, if any.
            claims_validation_model (type[JWTBaseModel] | None, opt.): the pydantic model
                to use for claims validation. If None, claims validation is disabled.
                Default to DefaultClaimsValidationModel.
            headers_validation_model (type[JOSEHeader] | None, opt.): the pydantic model
                to use for headers validation. If None, headers validation is disabled.
                Default to DefaultHeadersValidationModel.

        Returns:
            dict[str, Any]: The decoded and verified JWT claims as a dictionary.
        """

        # reset session
        self.reset_token()
        self.jws = JWS(algorithm)

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        if with_detached_payload is not None:
            # prepare and validate detached claims
            detached_claims = self.prepare_claims(
                with_detached_payload, validation_model=claims_validation_model
            )
            # JWS decode with detached payload
            self.jws.enable_detached_payload()
            self.jws.decode(
                token,
                key,
                with_detached_payload=detached_claims,
                headers_validation_model=headers_validation_model,
            )
            self.jws.token.validated.model.claims = detached_claims
        else:
            # JWS decode without detached payload
            self.jws.decode(
                token,
                key,
                headers_validation_model=headers_validation_model,
            )
            # validate claims
            self.jws.token.validated.model.claims = self.prepare_claims(
                self.jws.token.validated.decoded.payload,
                validation_model=claims_validation_model,
            )

        self.token = self.jws.token.validated
        return self.token.decoded.payload

    def inspect(
        self,
        token: str | bytes,
        has_detached_payload: bool = False,
    ) -> JWSToken:
        """Decode the JWT token without signature verification.
        For debugging purposes only. Never to be used in production.

        Args:
            token (str | bytes): The JWT token to decode.
            has_detached_payload (bool, opt.): If True, indicates that the token has a detached payload.

        Returns:
            JWSToken: The unsafe/not validated decoded JWT token as a raw JWSToken instance.
        """

        # reset session
        self.reset_token()

        self.jws = JWS(algorithm="none")
        if has_detached_payload:
            self.jws.enable_detached_payload()
        self.jws._allow_none_algorithm = True
        self.jws.decode(token=token, key=NoneKey(), headers_validation_model=None)
        self.jws._allow_none_algorithm = False

        self.token = self.jws.token.unsafe

        return self.jws.token.unsafe
