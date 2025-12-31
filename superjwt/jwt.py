import logging
from typing import Any

from pydantic import ValidationError

from superjwt.definitions import (
    Algorithm,
    JOSEHeader,
    JWSToken,
    JWTBaseModel,
    JWTClaims,
    JWTClaimsValidationDefault,
    JWTHeadersValidationDefault,
    get_effective_data_model,
    get_effective_data_validation_model,
    make_key,
    prepare_and_validate_data,
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
        headers: JOSEHeader | dict[str, Any] | None = None,
        validation_claims: type[JWTBaseModel] | None = JWTClaimsValidationDefault,
        validation_headers: type[JOSEHeader] | None = JWTHeadersValidationDefault,
    ) -> bytes:
        """Encode and sign the claims as a JWT token

        Args:
            claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
            key (str | bytes | BaseKey): The key instance to sign the JWT with.
            algorithm (Algorithm): The algorithm to use for signing the JWT.
                Will default to 'HS256' (HMAC with SHA-256).
            headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
                in the JWT. Will use default JWS headers if not provided.
            validation_claims (type[JWTBaseModel] | None, opt.): the pydantic model
                to use for claims validation. If None, claims validation is disabled.
                If 'claims' is a pydantic instance, defaults to its pydantic model.
                Otherwise, defaults to JWTBaseModel (i.e. no validation).
            validation_headers (type[JOSEHeader] | None, opt.): the pydantic model
                to use for headers validation. If None, headers validation is disabled.
                If 'headers' is a pydantic instance, defaults to its pydantic model.
                Otherwise, defaults to JOSEHeader (standard JOSE Header).

        Returns:
            bytes: the encoded compact JWT token
        """

        # reset session
        self.reset_token()

        # prepare claims data and perform validation
        if claims is None:
            claims = JWTBaseModel()
        validation_claims = get_effective_data_validation_model(
            claims, validation_claims, default=JWTBaseModel
        )
        try:
            claims_dict = prepare_and_validate_data(
                data=claims,
                validation_model=validation_claims,
                type_err_msg="claims must be a JWTBaseModel instance or a dict",
            )
        except ValidationError as e:
            raise ClaimsValidationError(validation_errors=e.errors()) from e

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        # encode as JWS
        self.jws = JWS(algorithm)
        self.jws.encode(
            headers=headers,
            payload=claims_dict,
            key=key,
            validation_headers=validation_headers,
        )

        # set claims model data
        claims_model = get_effective_data_model(
            claims, validation_claims, default=JWTBaseModel
        )
        self.jws.token.validated.model.claims = claims_model.model_construct(
            **claims_dict
        )

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

    def decode(
        self,
        token: str | bytes,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        with_detached_payload: JWTClaims | dict[str, Any] | None = None,
        validation_claims: type[JWTBaseModel] | None = None,
        validation_headers: type[JOSEHeader] | None = JWTHeadersValidationDefault,
    ) -> dict[str, Any]:
        """Decode the JWT token with signature verification.

        Args:
            token (str | bytes): The JWT token to decode.
            key (str | bytes | BaseKey): The key instance to verify the JWT signature.
            algorithm (Algorithm): The algorithm to use for verifying the JWT.
            with_detached_payload (JWTClaims | dict[str, Any] | None, opt.):
                Detached payload to use for signature verification, if any.
            validation_claims (type[JWTBaseModel] | None, opt.): the pydantic model
                to use for claims validation. If None, claims validation is disabled.
            validation_headers (type[JOSEHeader] | None, opt.): the pydantic model
                to use for headers validation. If None, headers validation is disabled.
                Defaults to JOSEHeader (standard JOSE Header).

        Returns:
            dict[str, Any]: The decoded and verified JWT claims as a dictionary.
        """

        # reset session
        self.reset_token()
        self.jws = JWS(algorithm)

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        # CASE 1: detached payload mode
        if with_detached_payload is not None:
            self.jws.enable_detached_payload()

            # prepare detached claims data and perform validation
            try:
                claims_dict = prepare_and_validate_data(
                    data=with_detached_payload,
                    validation_model=validation_claims,
                )
            except ValidationError as e:
                raise ClaimsValidationError(validation_errors=e.errors()) from e

            # set claims model data
            claims_model = get_effective_data_model(
                claims_dict, validation_claims, default=JWTBaseModel
            )
            self.jws.token.unsafe.model.claims = claims_model.model_construct(
                **claims_dict
            )

            # JWS decode
            self.jws.decode(
                token,
                key,
                with_detached_payload=claims_dict,
                validation_headers=validation_headers,
            )

        # CASE 2: normal mode
        else:
            # JWS decode
            self.jws.decode(
                token,
                key,
                validation_headers=validation_headers,
            )
            claims_dict = self.jws.token.validated.decoded.payload

            # validate claims
            try:
                prepare_and_validate_data(
                    data=claims_dict,
                    validation_model=validation_claims,
                )
            except ValidationError as e:
                raise ClaimsValidationError(validation_errors=e.errors()) from e

            # set claims model data
            claims_model = get_effective_data_model(
                claims_dict, validation_claims, default=JWTBaseModel
            )
            self.jws.token.validated.model.claims = claims_model.model_construct(
                **claims_dict
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
        self.jws.decode(token=token, key=NoneKey(), validation_headers=None)
        self.jws._allow_none_algorithm = False

        self.token = self.jws.token.unsafe

        return self.jws.token.unsafe
