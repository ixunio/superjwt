import logging
from collections.abc import Callable
from inspect import isclass
from typing import Any, cast

from pydantic import BaseModel, ValidationError

from superjwt.definitions import (
    Algorithm,
    JOSEHeader,
    JWSToken,
    JWTBaseModel,
    JWTClaimsDefaultValidationConfig,
    JWTHeadersDefaultValidationConfig,
    JWTValidationModelConfig,
    Validation,
    get_effective_data_model,
    get_effective_data_validation_model,
    make_key,
    prepare_and_validate_data,
)
from superjwt.exceptions import (
    ClaimsValidationError,
    SuperJWTError,
)
from superjwt.jws import JWS
from superjwt.keys import BaseKey, NoneKey


logger = logging.getLogger(__name__)


class JWT:
    def __init__(
        self,
        default_claims_validation: JWTValidationModelConfig
        | None = JWTClaimsDefaultValidationConfig,
        default_headers_validation: JWTValidationModelConfig
        | None = JWTHeadersDefaultValidationConfig,
    ) -> None:
        self.jws: JWS

        self.default_claims_validation = default_claims_validation
        self.default_headers_validation = default_headers_validation

    def encode(
        self,
        claims: JWTBaseModel | dict[str, Any] | None,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        headers: JOSEHeader | dict[str, Any] | None = None,
        claims_validation: type[BaseModel] | Validation | None = Validation.DEFAULT,
        headers_validation: type[BaseModel] | Validation | None = Validation.DEFAULT,
    ) -> JWSToken:
        """Encode and sign the claims as a JWT token

        Args:
            claims (JWTBaseModel | dict[str, Any] | None): Claims to include in the JWT payload.
            key (str | bytes | BaseKey): The key instance to sign the JWT with.
            algorithm (Algorithm): The algorithm to use for signing the JWT.
                Will default to 'HS256' (HMAC with SHA-256).
            headers (JOSEHeader | dict[str, Any] | None, opt.): Custom JWS headers to include
                in the JWT. Will use default JWS headers if not provided.
            claims_validation (type[JWTBaseModel] | None, opt.): the pydantic model
                to use for claims validation. If None, claims validation is disabled.
                If 'claims' is a pydantic instance, defaults to its pydantic model.
                Otherwise, defaults to JWTBaseModel (i.e. no validation).
            headers_validation (type[JOSEHeader] | None, opt.): the pydantic model
                to use for headers validation. If None, headers validation is disabled.
                If 'headers' is a pydantic instance, defaults to its pydantic model.
                Otherwise, defaults to JOSEHeader (standard JOSE Header).

        Returns:
            JWSToken: a JWSToken instance representing the encoded and signed JWT token.
        """

        self.jws = JWS(
            algorithm, default_headers_validation=self.default_headers_validation
        )

        # prepare claims data and perform validation
        if claims is None:
            claims = JWTBaseModel()
        try:
            claims_dict = prepare_and_validate_data(
                data=claims,
                type_err_msg="claims must be a JWTBaseModel instance or a dict",
                validation_model=self.get_claims_validation_model(
                    claims, claims_validation
                ),
            )
        except ValidationError as e:
            raise ClaimsValidationError(validation_errors=e.errors()) from e

        # prepare key
        if not isinstance(key, BaseKey):
            key = make_key(algorithm, key)

        # encode as JWS
        self.jws.encode(
            headers=headers,
            payload=claims_dict,
            key=key,
            headers_validation=headers_validation,
        )

        # set claims model data
        self.jws.token.verified.model.claims = cast(
            "JWTBaseModel",
            self.get_claims_data_model(claims, claims_validation).model_construct(
                **claims_dict
            ),
        )

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
        compact: str | bytes,
        key: str | bytes | BaseKey,
        algorithm: Algorithm = "HS256",
        *,
        with_detached_payload: JWTBaseModel | dict[str, Any] | None = None,
        claims_validation: type[BaseModel] | Validation | None = Validation.DEFAULT,
        headers_validation: type[BaseModel] | Validation | None = Validation.DEFAULT,
    ) -> JWSToken:
        """Decode the JWT token with signature verification.

        Args:
            compact (str | bytes): The JWT compact token to decode.
            key (str | bytes | BaseKey): The key instance to verify the JWT signature.
            algorithm (Algorithm): The algorithm to use for verifying the JWT.
            with_detached_payload (JWTBaseModel | dict[str, Any] | None, opt.):
                Detached payload to use for signature verification, if any.
            claims_validation (type[JWTBaseModel] | None, opt.): the pydantic model
                to use for claims validation. If None, claims validation is disabled.
                Defaults to JWTBaseModel (i.e. no validation).
            headers_validation (type[JOSEHeader] | None, opt.): the pydantic model
                to use for headers validation. If None, headers validation is disabled.
                Defaults to JOSEHeader (standard JOSE Header).

        Returns:
            JWSToken: a JWSToken instance representing the decoded and verified JWT token.
        """

        self.jws = JWS(
            algorithm, default_headers_validation=self.default_headers_validation
        )

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
                    type_err_msg="detached payload must be a dict or a JWTBaseModel instance",
                    validation_model=self.get_claims_validation_model(
                        with_detached_payload, claims_validation
                    ),
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
            self.jws.decode(
                compact,
                key,
                headers_validation=headers_validation,
            )

            # validate claims
            try:
                claims_dict = prepare_and_validate_data(
                    data=self.jws.token.verified.payload,
                    validation_model=self.get_claims_validation_model(
                        self.jws.token.verified.payload, claims_validation
                    ),
                )
            except ValidationError as e:
                raise ClaimsValidationError(validation_errors=e.errors()) from e

        # set claims model data
        self.jws.token.verified.model.claims = cast(
            "JWTBaseModel",
            self.get_claims_data_model(claims_dict, claims_validation).model_construct(
                **claims_dict
            ),
        )

        return self.jws.token.verified

    def inspect(
        self,
        compact: str | bytes,
        has_detached_payload: bool = False,
    ) -> JWSToken:
        """Decode the JWT token without signature verification.
        For debugging purposes only. Never to be used in production.

        Args:
            compact (str | bytes): The JWT compact token to decode.
            has_detached_payload (bool, opt.): If True, indicates that the token has a detached payload.

        Returns:
            JWSToken: a JWSToken instance representing the unsafe non-verified decoded JWT token.
        """

        self.jws = JWS(algorithm="none")

        if has_detached_payload:
            self.jws.enable_detached_payload()

        self.jws._allow_none_algorithm = True
        self.jws.decode(
            compact=compact, key=NoneKey(), headers_validation=Validation.DISABLE
        )
        self.jws._allow_none_algorithm = False

        return self.jws.token.unsafe

    def get_claims_data_model(
        self,
        data: JWTBaseModel | dict[str, Any],
        validation_model: type[BaseModel] | Validation | None = Validation.DEFAULT,
    ) -> type[BaseModel]:
        """Get the effective data claims pydantic model"""
        return self.get_claims_model(get_effective_data_model, data, validation_model)

    def get_claims_validation_model(
        self,
        data: JWTBaseModel | dict[str, Any],
        validation_model: type[BaseModel] | Validation | None = Validation.DEFAULT,
    ) -> type[BaseModel] | None:
        """Get the effective claims validation pydantic model"""
        return self.get_claims_model(
            get_effective_data_validation_model, data, validation_model
        )

    def get_claims_model(
        self,
        fn: Callable,
        data: JWTBaseModel | dict[str, Any],
        validation_model: type[BaseModel] | Validation | None = Validation.DEFAULT,
    ) -> Any:
        if validation_model is Validation.DISABLE or validation_model is None:
            return fn(data, None)
        elif validation_model is Validation.DEFAULT:
            return fn(data, self.default_claims_validation)
        elif isclass(validation_model) and issubclass(validation_model, BaseModel):
            return fn(data, validation_model)
        raise TypeError("Wrong validation object type")
