import logging
from typing import Any

from pydantic import ValidationError

from superjwt.definitions import (
    Algorithm,
    JOSEHeader,
    JWSToken,
    JWTClaims,
    JWTContent,
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
        self.token: JWTContent
        self.jws: JWS

        self.JWTEffectiveClaims: type[JWTClaims] = JWTClaims

    def encode(
        self,
        claims: JWTClaims | dict[str, Any] | None,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        headers: JOSEHeader | dict[str, Any] | None = None,
        disable_claims_validation: bool = False,
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
                Signature verification is still performed.

        Returns:
            bytes: the encoded compact JWT token
        """

        # prepare claims data
        self.JWTEffectiveClaims = JWTClaims
        claims = self.prepare_claims(claims, disable_claims_validation)

        # prepare headers data
        headers = self.prepare_headers(headers, algorithm)

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        # encode as JWS
        self.jws = JWS(algorithm)
        self.jws.encode(header=headers, payload=claims, key=key)

        try:
            self.JWTEffectiveClaims(**self.jws.token.validated.decoded.payload)
        except ValidationError as e:
            if not disable_claims_validation:
                raise ClaimsValidationError(validation_errors=e.errors()) from e

        self.token = JWTContent(
            claims=self.jws.token.validated.decoded.payload,
            jws_token=self.jws.token.validated,
        )
        return self.token.compact

    def detach_payload(self) -> bytes:
        """Declare payload detached from JWT compact.
            The encoded payload part will be b""

        Returns:
            bytes: the compact JWT token with an empty payload bytes instead
        """
        if not self.jws.token.validated:
            raise JWTError("JWT token has not been encoded yet")
        self.jws.detach_payload()
        return self.token.compact

    def prepare_claims(
        self,
        claims: JWTClaims | dict[str, Any] | None,
        disable_claims_validation: bool = False,
    ) -> JWTClaims:
        if claims is None:
            return JWTClaims(iat=None)
        if isinstance(claims, dict):
            claims_dict = claims.copy()
            try:
                JWTClaims(**claims_dict)
            except ValidationError as e:
                if not disable_claims_validation:
                    raise ClaimsValidationError(validation_errors=e.errors()) from e
                logger.info(f"Validation error during encoding: {e}")
            return JWTClaims.model_construct(**claims_dict)
        if isinstance(claims, JWTClaims):
            # set custom pydantic model if needed
            self.JWTEffectiveClaims = claims.__class__
            return claims
        raise TypeError("claims must be a JWTClaims instance or a dict")

    def prepare_headers(
        self, headers: JOSEHeader | dict[str, Any] | None, algorithm: Algorithm
    ) -> JOSEHeader:
        if headers is None:
            return JOSEHeader.make_default(algorithm)
        if isinstance(headers, dict):
            try:
                return JOSEHeader(**headers)
            except ValidationError as e:
                raise HeaderValidationError(validation_errors=e.errors()) from e
        if isinstance(headers, JOSEHeader):
            return headers
        raise TypeError("headers must be a JOSEHeader instance or a dict")

    def decode(
        self,
        token: str | bytes,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        with_detached_payload: JWTClaims | dict[str, Any] | None = None,
        disable_claims_validation: bool = False,
    ) -> dict[str, Any]:
        """Decode the JWT token with signature verification.

        Args:
            token (str | bytes): The JWT token to decode.
            key (str | bytes | BaseKey): The key instance to verify the JWT signature.
            algorithm (Algorithm): The algorithm to use for verifying the JWT.
            with_detached_payload (JWTClaims | dict[str, Any] | None, optional):
                Detached payload to use for verification, if any.
            disable_claims_validation (bool, opt.): If True, disables claims validation.
                Signature verification is still performed.

        Returns:
            dict[str, Any]: The decoded and verified JWT claims as a dictionary.
        """

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        # prepare detached claims
        detached_claims = None
        if with_detached_payload:
            detached_claims = self.prepare_claims(with_detached_payload)

        # decode from JWS
        self.jws = JWS(algorithm)
        self.jws.decode(token, key, with_detached_payload=detached_claims)

        # validate claims
        claims_dict = self.jws.token.validated.decoded.payload
        try:
            self.JWTEffectiveClaims(**claims_dict)
        except ValidationError as e:
            if not disable_claims_validation:
                raise ClaimsValidationError(validation_errors=e.errors()) from e
            logger.info(f"Validation error during decoding: {e}")

        self.token = JWTContent(
            claims=self.jws.token.validated.decoded.payload,
            jws_token=self.jws.token.validated,
        )
        return self.token.claims

    def inspect(
        self,
        token: str | bytes,
    ) -> JWSToken:
        """Decode the JWT token without signature verification.
        For debugging purposes only. Never to be used in production.

        Args:
            token (str | bytes): The JWT token to decode.

        Returns:
            JWSToken: The unsafe/not validated decoded JWT token as a raw JWSToken instance.
        """
        self.jws = JWS(algorithm="none")
        self.jws.allow_none_algorithm = True
        self.jws.decode(token=token, key=NoneKey(), disable_headers_validation=True)
        self.jws.allow_none_algorithm = False
        return self.jws.token.unsafe
