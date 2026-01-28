import json
from datetime import datetime, timedelta
from enum import Enum
from inspect import isclass
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    Field,
    HttpUrl,
    PlainSerializer,
    UrlConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from superjwt.exceptions import (
    TokenExpiredError,
    TokenNotYetValidError,
)
from superjwt.shared import VALID_ALGORITHMS
from superjwt.utils import delta_datetime_timestamp


try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


class JWTBaseModel(BaseModel):
    model_config = {"extra": "allow", "revalidate_instances": "always"}

    internal__now: Annotated[datetime | None, Field(exclude=True, repr=False)] = None

    def revalidate(self, context: dict[str, Any] | None = None) -> None:
        """Re-validate the pydantic instance against its own model."""
        self.model_validate(self, context=context)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)

    def to_json(self) -> str:
        return self.model_dump_json(exclude_none=True)

    def spoof_time(self, set_now: datetime | None) -> None:
        """Spoof the current time for testing purposes. Set to None to disable spoofing."""
        self.internal__now = set_now


class Operation(str, Enum):
    """Flags to indicate the operation type for validation context."""

    ENCODE = "encode"
    DECODE = "decode"


class HttpsUrl(HttpUrl):
    _constraints = UrlConstraints(max_length=2083, allowed_schemes=["https"])


class JOSEHeader(JWTBaseModel):
    alg: Annotated[
        str,
        Field(description="algorithm - the algorithm used to sign the JWT"),
    ]

    typ: Annotated[
        str | None,
        Field(description="type - the type of the payload contained in the JWT"),
    ] = "JWT"

    kid: Annotated[
        str | None,
        Field(
            description="key ID - a hint indicating which key was used to secure the JWT"
        ),
    ] = None

    crit: Annotated[
        list[str] | None,
        Field(
            description="Critical headers - a list of header parameters that must be understood and processed"
        ),
    ] = None

    @field_validator("alg")
    @classmethod
    def validate_alg(cls, value: str) -> str:
        """Validate that the algorithm is a valid algorithm name and normalize to string."""

        # Check if it's a valid algorithm
        if value not in VALID_ALGORITHMS:
            raise ValueError(f"'{value}' is not a valid algorithm")

        return value

    @field_validator("crit")
    @classmethod
    def validate_crit(cls, value: list[str] | None, info: ValidationInfo):
        if value is None:
            return value

        if value is not None and len(value) == 0:  # empty list is forbidden
            raise ValueError("'crit' header must be a non-empty list of strings")

        for el in value:
            if el not in info.data.keys():
                raise ValueError(f"'crit' header missing '{el}'")

        return value


def serialize_jwtdatetime_timestamp_to_int(value: datetime | int | float) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    else:
        return int(value.timestamp())


def serialize_jwtdatetime_timestamp_to_float(value: datetime | int | float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    else:
        return value.timestamp()


JWTDatetimeInt = Annotated[
    datetime,
    PlainSerializer(serialize_jwtdatetime_timestamp_to_int),
]
JWTDatetimeFloat = Annotated[
    datetime,
    PlainSerializer(serialize_jwtdatetime_timestamp_to_float),
]


class JWTClaimsModel(JWTBaseModel):
    iss: Annotated[
        str | None,
        Field(description="issuer - the issuer of the JWT"),
    ] = None
    sub: Annotated[
        str | None,
        Field(description="subject - the subject of the JWT (the user)"),
    ] = None
    aud: Annotated[
        str | list[str] | None,
        Field(description="audience - the recipient for which the JWT is intended"),
    ] = None
    iat: Annotated[
        JWTDatetimeInt | None,
        Field(description="issued at time - the time at which the JWT was issued"),
    ] = None
    nbf: Annotated[
        JWTDatetimeInt | None,
        Field(
            description="not before time - the time before which the JWT must not be accepted"
        ),
    ] = None
    exp: Annotated[
        JWTDatetimeInt | None,
        Field(description="expiration time - the time after which the JWT expires"),
    ] = None
    jti: Annotated[
        str | None,
        Field(description="JWT ID - a unique identifier for the JWT"),
    ] = None


DEFAULT_LEEWAY_SECONDS: float = 5.0
DEFAULT_ALLOW_FUTURE_IAT: bool = False


class JWTClaims(JWTClaimsModel):
    """
    JWT standard claims as per RFC 7519.
    """

    internal__leeway: Annotated[float, Field(exclude=True, repr=False)] = (
        DEFAULT_LEEWAY_SECONDS
    )
    internal__allow_future_iat: Annotated[bool, Field(exclude=True, repr=False)] = (
        DEFAULT_ALLOW_FUTURE_IAT
    )

    @property
    def now(self) -> datetime:
        """Get the current time."""
        if self.internal__now is None:
            return datetime.now(UTC)
        return self.internal__now

    def set_leeway(self, leeway_seconds: float) -> None:
        """Set the leeway (in seconds) for time-based claim validations."""
        if leeway_seconds < 0:
            raise ValueError("Leeway must be a non-negative float")
        self.internal__leeway = leeway_seconds

    def allow_future_iat(self) -> None:
        """Allow 'iat' claim to be in the future (disable the check)."""
        self.internal__allow_future_iat = True

    def disallow_future_iat(self) -> None:
        """Disallow 'iat' claim to be in the future (enable the check)."""
        self.internal__allow_future_iat = False

    @model_validator(mode="after")
    def validate_time_integrity(self, info: ValidationInfo) -> Self:
        operation = info.context.get("operation") if info.context else None

        # check nbf >= iat
        if self.nbf is not None and self.iat is not None:
            if self.nbf < self.iat:
                raise ValueError(
                    "'nbf' claim must be greater than or equal to 'iat' claim"
                )

        # check nbf < exp (token must be valid for some period)
        if self.nbf is not None and self.exp is not None:
            if self.nbf >= self.exp:
                raise ValueError("'nbf' claim must be less than or equal to 'exp' claim")

        # check iat <= now, modulo leeway
        if self.iat is not None and not self.internal__allow_future_iat:
            if delta_datetime_timestamp(self.iat, self.now) > self.internal__leeway:
                raise ValueError("'iat' claim must not be in the future")

        # check nbf <= now, modulo leeway
        if operation == Operation.DECODE:
            if self.nbf is not None:
                if delta_datetime_timestamp(self.nbf, self.now) > self.internal__leeway:
                    raise TokenNotYetValidError()

        # check exp > now, modulo leeway
        if self.exp is not None:
            if delta_datetime_timestamp(self.now, self.exp) >= self.internal__leeway:
                raise TokenExpiredError()

        return self

    def with_issued_at(self) -> Self:
        """Return a new JWTClaims instance with the 'iat' claim set to current time."""

        # case iat AND exp were set
        iat = getattr(self, "iat", None)
        exp = getattr(self, "exp", None)
        if exp is not None and iat is not None:
            # preserve original delta between iat and exp
            delta = exp - iat
            return self.model_copy(update={"iat": self.now, "exp": self.now + delta})

        return self.model_copy(update={"iat": self.now})

    def with_expiration(
        self,
        *,
        minutes: int | None = None,
        hours: int | None = None,
        days: int | None = None,
    ) -> Self:
        """Return a new JWTClaims instance with the 'exp' claim set to current time plus the specified delta."""

        for delta in (minutes, hours, days):
            if delta is not None and not isinstance(delta, (int, float)):
                raise TypeError(
                    "Expiration minutes, hours, and days must be valid numbers"
                )
            if delta is not None and delta <= 0:
                raise ValueError(
                    "Expiration minutes, hours, and days must be positive numbers"
                )
        exp_time = self.now + timedelta(
            minutes=minutes or 0, hours=hours or 0, days=days or 0
        )

        # case iat was already set
        iat = getattr(self, "iat", None)
        if iat is not None:
            # rewrite iat value
            return self.model_copy(update={"iat": self.now, "exp": exp_time})

        return self.model_copy(update={"exp": exp_time})


class ValidationConfig:
    """JWT validation configuration (immutable from library perspective)."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        model: type[JWTBaseModel] = JWTBaseModel,
        forward_pydantic_model: bool = True,
        now: datetime | None = None,
        leeway: float | None = None,
        allow_future_iat: bool | None = None,
        **kwargs: Any,
    ) -> None:
        self.enabled = enabled
        self.model = model
        self.forward_pydantic_model = forward_pydantic_model
        self.now = now
        self.leeway = leeway
        self.allow_future_iat = allow_future_iat


class Validation:
    """Internal validation executor that performs the actual validation work."""

    # Validation flags
    class Flags(str, Enum):
        DEFAULT = "default"
        DISABLE = "disable"

    DEFAULT = Flags.DEFAULT
    DISABLE = Flags.DISABLE

    def __init__(
        self,
        enabled: bool,
        model: type[JWTBaseModel],
        now: datetime | None = None,
        leeway: float | None = None,
        allow_future_iat: bool | None = None,
    ):
        self.enabled = enabled
        self.model = model
        self.now = now
        self.leeway = leeway
        self.allow_future_iat = allow_future_iat

    def _internal_params_matrix(self) -> list[tuple[str, Any]]:
        return [
            ("now", None),
            ("leeway", DEFAULT_LEEWAY_SECONDS),
            ("allow_future_iat", DEFAULT_ALLOW_FUTURE_IAT),
        ]

    def _get_internal_cfg(self) -> dict[str, Any]:
        """Get internal config values as a dict for injection into validation."""
        internal_config = {}
        if self.enabled and issubclass(self.model, JWTClaims):
            for param, _ in self._internal_params_matrix():
                value = getattr(self, param)
                if value is not None:
                    internal_config[f"internal__{param}"] = value
        return internal_config

    def run(
        self,
        data: JWTBaseModel | dict[str, Any],
        operation: Operation | None = None,
        dump_dict: bool = False,
        dump_json: bool = False,
    ) -> tuple[JWTBaseModel, dict[str, Any], str]:
        if not isinstance(data, (JWTBaseModel, dict)):
            raise TypeError("Wrong type during data preparation and validation")

        # case pydantic model
        if isinstance(data, JWTBaseModel):
            return self.validate_from_pydantic_instance(
                data, operation, dump_dict, dump_json
            )
        # case dict
        if isinstance(data, dict):
            return self.validate_from_dict(data, operation, dump_dict, dump_json)

    def validate_from_pydantic_instance(
        self,
        data_pydantic: JWTBaseModel,
        operation: Operation | None,
        dump_dict: bool = False,
        dump_json: bool = False,
    ) -> tuple[JWTBaseModel, dict[str, Any], str]:
        """Validate data when provided as a pydantic instance."""
        data_dict = data_pydantic.to_dict()

        # Validation is disabled
        if self.enabled is False:
            return (
                data_pydantic,
                data_dict,
                data_pydantic.to_json(),
            )

        # Validation is enabled
        data_pydantic = self.model.model_validate(
            data_dict | self._get_internal_cfg(),
            context={"operation": operation},
        )
        return (
            data_pydantic,
            data_pydantic.to_dict() if dump_dict else {},
            data_pydantic.to_json() if dump_json else "{}",
        )

    def validate_from_dict(
        self,
        data: dict[str, Any],
        operation: Operation | None,
        dump_dict: bool = False,
        dump_json: bool = False,
    ) -> tuple[JWTBaseModel, dict[str, Any], str]:
        """Validate data when provided as a dict."""
        # Validation is disabled
        if self.enabled is False:
            return (
                self.model.model_construct(**data),
                data,
                json.dumps(data) if dump_json else "{}",
            )

        # Validation is enabled
        data_pydantic = self.model.model_validate(
            data | self._get_internal_cfg(),
            context={"operation": operation},
        )

        return (
            data_pydantic,
            data_pydantic.to_dict() if dump_dict else {},
            data_pydantic.to_json() if dump_json else "{}",
        )

    @classmethod
    def get(
        cls,
        data: JWTBaseModel | dict[str, Any],
        validation: type[JWTBaseModel] | ValidationConfig | str | None,
        default_validation: type[JWTBaseModel],
        fallback_model: type[JWTBaseModel] = JWTBaseModel,
    ) -> "Validation":
        ##############################
        # case validation is DISABLED
        if (
            validation is cls.DISABLE
            or validation is None
            or (isinstance(validation, ValidationConfig) and validation.enabled is False)
        ):
            return cls(enabled=False, model=fallback_model)

        ##############################
        # case validation is ENABLED

        # Start with None values
        enabled = True
        model = default_validation
        forward_pydantic_model = True
        now = None
        leeway = None
        allow_future_iat = None

        # 1. case DEFAULT/AUTOMATIC behavior
        if validation is cls.DEFAULT:
            model = default_validation
            forward_pydantic_model = True

        # 2. case CUSTOM (ValidationConfig instance sent explicitly)
        elif isinstance(validation, ValidationConfig):
            enabled = validation.enabled
            model = validation.model
            forward_pydantic_model = validation.forward_pydantic_model
            now = validation.now
            leeway = validation.leeway
            allow_future_iat = validation.allow_future_iat

        # 3 case CUSTOM (Pydantic model sent explicitly)
        #   --> we never forward the data pydantic model in the scenario where data is a pydantic instance
        elif isclass(validation) and issubclass(validation, JWTBaseModel):
            model = validation
            forward_pydantic_model = False

        else:
            raise TypeError("Wrong validation object type")

        # finalize internal config
        if isinstance(data, JWTBaseModel):
            if forward_pydantic_model is True:
                # forward data model type to validation model
                model = type(data)
            # always forward internal config from data model if it's JWTClaims
            if isinstance(data, JWTClaims) and issubclass(model, JWTClaims):
                if now is None:
                    now = data.internal__now
                if leeway is None:
                    leeway = data.internal__leeway
                if allow_future_iat is None:
                    allow_future_iat = data.internal__allow_future_iat
        else:
            # set default values for unset internal config
            # --> data is a dict and carries no config
            if issubclass(model, JWTClaims):
                if leeway is None:
                    leeway = DEFAULT_LEEWAY_SECONDS
                if allow_future_iat is None:
                    allow_future_iat = DEFAULT_ALLOW_FUTURE_IAT

        return cls(
            enabled=enabled,
            model=model,
            now=now,
            leeway=leeway,
            allow_future_iat=allow_future_iat,
        )
