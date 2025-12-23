import logging
from typing import Any

from pydantic import ValidationError

from superjwt.definitions import (
    Algorithm,
    JOSEHeader,
    JWSToken,
    JWTBaseModel,
    JWTClaims,
    JWTCompliantClaims,
    make_key,
)
from superjwt.exceptions import (
    ClaimsValidationError,
    HeaderValidationError,
    JWTError,
)
from superjwt.jws import JWS
from superjwt.keys import BaseKey, NoneKey


logger = logging.getLogger(__name__)


class JWT:
    def __init__(self):
        self.jws: JWS
        self.token: JWSToken
        self.JWTEffectiveClaims: type[JWTBaseModel]

    def reset_token(self) -> None:
        self.token = JWSToken()

    def encode(
        self,
        claims: JWTBaseModel | dict[str, Any] | None,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        headers: JOSEHeader | dict[str, Any] | None = None,
        disable_claims_validation: bool = False,
        disable_headers_validation: bool = False,
    ) -> bytes:
        """Encode and sign the claims as a JWT token

        Args:
            claims (JWTClaims | dict[str, Any] | None): Claims to include in the JWT.
                Will use default claims if not provided ('iat')
            key (str | bytes | BaseKey): The key instance to sign the JWT with.
            algorithm (Algorithm): The algorithm to use for signing the JWT.
                Will default to 'HS256' (HMAC with SHA-256)
            headers (JOSEHeader | dict[str, Any] | None, opt.): Headers to include in the JWT.
                Will use default headers if not provided
            disable_claims_validation (bool, opt.): If True, disables claims validation.
            disable_headers_validation (bool, opt.): If True, disables headers validation.

        Returns:
            bytes: the encoded compact JWT token
        """

        # reset session
        self.reset_token()

        # prepare claims data
        self.JWTEffectiveClaims = JWTClaims
        claims = self.prepare_claims(claims, disable_claims_validation)

        # prepare headers data
        headers = self.prepare_headers(headers, algorithm, disable_headers_validation)

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        # encode as JWS
        self.jws = JWS(algorithm)
        self.jws.encode(header=headers, payload=claims, key=key)

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

    def prepare_claims(
        self,
        claims: JWTBaseModel | dict[str, Any] | None,
        disable_claims_validation: bool = False,
    ) -> JWTBaseModel:
        if claims is None:
            self.JWTEffectiveClaims = JWTCompliantClaims
            claims_dict = {}
        elif isinstance(claims, dict):
            self.JWTEffectiveClaims = JWTCompliantClaims
            claims_dict = claims.copy()
        elif isinstance(claims, JWTBaseModel):
            self.JWTEffectiveClaims = claims.__class__
            claims_dict = claims.to_dict()
        else:
            raise TypeError("claims must be a JWTBaseModel instance or a dict")

        if disable_claims_validation:
            return self.JWTEffectiveClaims.model_construct(**claims_dict)

        try:
            return self.JWTEffectiveClaims(**claims_dict)
        except ValidationError as e:
            raise ClaimsValidationError(validation_errors=e.errors()) from e

    def prepare_headers(
        self,
        headers: JOSEHeader | dict[str, Any] | None,
        algorithm: Algorithm,
        disable_headers_validation: bool = False,
    ) -> JOSEHeader:
        if headers is None:
            return JOSEHeader.make_default(algorithm)

        if isinstance(headers, dict):
            self.JWTEffectiveClaims = JWTCompliantClaims
            headers_dict = headers.copy()
        elif isinstance(headers, JOSEHeader):
            headers_dict = headers.to_dict()
        else:
            raise TypeError("headers must be a JOSEHeader instance or a dict")

        if disable_headers_validation:
            return JOSEHeader.model_construct(**headers_dict)

        try:
            return JOSEHeader(**headers_dict)
        except ValidationError as e:
            raise HeaderValidationError(validation_errors=e.errors()) from e

    def decode(
        self,
        token: str | bytes,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        with_detached_payload: JWTClaims | dict[str, Any] | None = None,
        disable_claims_validation: bool = False,
        disable_headers_validation: bool = False,
    ) -> dict[str, Any]:
        """Decode the JWT token with signature verification.

        Args:
            token (str | bytes): The JWT token to decode.
            key (str | bytes | BaseKey): The key instance to verify the JWT signature.
            algorithm (Algorithm): The algorithm to use for verifying the JWT.
            with_detached_payload (JWTClaims | dict[str, Any] | None, opt.):
                Detached payload to use for verification, if any.
            disable_claims_validation (bool, opt.): If True, disables claims validation.
                Signature verification is still performed.
            disable_headers_validation (bool, opt.): If True, disables headers validation.
                Signature verification is still performed.

        Returns:
            dict[str, Any]: The decoded and verified JWT claims as a dictionary.
        """

        # reset session
        self.reset_token()

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        # prepare detached claims
        detached_claims = None
        if with_detached_payload is not None:
            detached_claims = self.prepare_claims(
                with_detached_payload, disable_claims_validation
            )

        # decode from JWS
        self.jws = JWS(algorithm)
        if detached_claims is not None:
            self.jws.enable_detached_payload()
        self.jws.decode(
            token,
            key,
            with_detached_payload=detached_claims,
            disable_headers_validation=disable_headers_validation,
        )

        # validate claims
        try:
            self.JWTEffectiveClaims(**self.jws.token.validated.decoded.payload)
        except ValidationError as e:
            if not disable_claims_validation:
                raise ClaimsValidationError(validation_errors=e.errors()) from e
            logger.info(f"Validation error during decoding: {e}")

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
        self.jws.decode(token=token, key=NoneKey(), disable_headers_validation=True)
        self.jws._allow_none_algorithm = False

        self.token = self.jws.token.unsafe

        return self.jws.token.unsafe
