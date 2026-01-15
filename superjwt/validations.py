from copy import deepcopy
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

from superjwt.algorithms import Alg
from superjwt.exceptions import (
    InvalidHeadersError,
    TokenExpiredError,
    TokenNotYetValidError,
)
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
    _strict_crit_check: bool = False

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

    @classmethod
    def make_default(cls, algorithm: Alg | str, **kwargs: Any) -> Self:
        return cls(alg=algorithm, **kwargs)

    @field_validator("alg")
    @classmethod
    def validate_alg(cls, value: Alg | str) -> str:
        """Validate that the algorithm is a valid algorithm name and normalize to string."""
        # Get the string value (works for both Algorithm enum and str)
        alg_str = value.value if isinstance(value, Alg) else value

        # Check if it's a valid algorithm (including "none")
        valid_algorithms = set(member.value for member in Alg) | {"none"}
        if alg_str not in valid_algorithms:
            raise ValueError(f"'{alg_str}' is not a valid algorithm")

        return alg_str

    @field_validator("crit")
    @classmethod
    def validate_crit(cls, value: list[str] | None, info: ValidationInfo):
        if value is None:
            return value

        if value is not None and len(value) == 0:  # empty list is forbidden
            raise ValueError("'crit' header must be a non-empty list of strings")

        missing = []
        unsupported = []
        for el in value:
            # check for missing headers declared in 'crit'
            if el not in info.data.keys():
                missing.append(el)
            # check for unsupported custom headers
            elif cls._strict_crit_check and (el not in cls.model_fields.keys()):
                unsupported.append(el)
        if missing:
            raise ValueError(f"Missing crit headers: {', '.join(missing)}")
        if unsupported:
            raise ValueError(f"Unsupported custom crit headers: {', '.join(unsupported)}")

        if "b64" in info.data.keys():
            if "b64" not in value:
                raise ValueError("'b64' header parameter must be listed in 'crit' header")

        return value

    @model_validator(mode="after")
    def unsupported_b64_false(self) -> Self:
        if hasattr(self, "b64") and self.b64 is False:  # type: ignore
            raise InvalidHeadersError(
                "'b64' header parameter is not supported in this implementation"
            )
        return self


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


class ValidationConfig(BaseModel):
    """JWT data validation object."""

    model_config = {"extra": "forbid"}

    # ------------- General validation config -------------
    """Enable or disable data validation."""
    enabled: bool = True

    """The pydantic model to use for data validation."""
    model: type[JWTBaseModel] | None = None

    """Forward the data pydantic model to validation config (and its internal config)."""
    forward_pydantic_model: bool = True

    # ------------- JWTBaseModel specific internal config -------------
    """Spoofed 'now' datetime."""
    now: datetime | None = None

    # ------------- JWTClaims specific internal config -------------
    """Leeway for time-based validations, in seconds."""
    leeway: float | None = None

    """Allow 'iat' claim to be in the future."""
    allow_future_iat: bool | None = None

    def _internal_params_matrix(self) -> list[tuple[str, type[JWTBaseModel], Any]]:
        return [
            ("now", JWTBaseModel, None),
            ("leeway", JWTClaims, DEFAULT_LEEWAY_SECONDS),
            ("allow_future_iat", JWTClaims, DEFAULT_ALLOW_FUTURE_IAT),
        ]

    def _get_internal_cfg(self) -> dict[str, Any]:
        """Get internal config values as a dict for injection into validation."""
        internal_config = {}
        for param, model_type, _ in self._internal_params_matrix():
            if self.model is not None and issubclass(self.model, model_type):
                value = getattr(self, param)
                if value is not None:
                    internal_config[f"internal__{param}"] = value
        return internal_config

    def apply_internal_cfg(self, model: JWTBaseModel | None = None) -> None:
        """Set internal config values when unset, either from a compatible data model
        or from default values."""
        for param, model_type, default in self._internal_params_matrix():
            if getattr(self, param) is None:  # only overwrite when unset
                if model is not None and isinstance(model, model_type):
                    setattr(self, param, getattr(model, f"internal__{param}"))
                elif model is None:
                    setattr(self, param, default)

    def run(
        self,
        data: JWTBaseModel | dict[str, Any],
        fallback_model: type[JWTBaseModel] = JWTBaseModel,
        operation: Operation | None = None,
    ) -> tuple[JWTBaseModel, dict[str, Any]]:
        # case pydantic model
        if isinstance(data, JWTBaseModel):
            data_dict = data.to_dict()
        # case dict
        elif isinstance(data, dict):
            data_dict = deepcopy(data)
        else:
            raise TypeError("Wrong type during data preparation and validation")

        if self.enabled is False:
            return fallback_model.model_construct(**data_dict), data_dict

        if self.model is None:
            raise ValueError("Validation model is not set in ValidationConfig")

        ##### BEGIN VALIDATION #####
        data_pydantic = self.model.model_validate(
            data_dict | self._get_internal_cfg(),
            context={"operation": operation},
        )
        ##### END VALIDATION #####

        return data_pydantic, data_pydantic.to_dict()


JWTClaimsDefaultValidation = ValidationConfig(
    model=JWTClaims,
)
JWTHeadersDefaultValidation = ValidationConfig(
    model=JOSEHeader,
)


class Validation(str, Enum):
    """Flags to control validation behavior in JWT operations."""

    DEFAULT = "default"
    DISABLE = "disable"


def get_validation_config(
    data: JWTBaseModel | dict[str, Any],
    validation: type[JWTBaseModel] | ValidationConfig | Validation | None,
    default_validation: ValidationConfig,
) -> ValidationConfig:
    ##############################
    # case validation is DISABLED
    if (
        validation is Validation.DISABLE
        or validation is None
        or (isinstance(validation, ValidationConfig) and validation.enabled is False)
    ):
        return ValidationConfig(enabled=False)

    ##############################
    # case validation is ENABLED

    # 1. case DEFAULT/AUTOMATIC behavior
    if validation is Validation.DEFAULT:
        # make a copy, mutable object!!
        validation_cfg = default_validation.model_copy(deep=True)
        if isinstance(data, JWTBaseModel):
            if validation_cfg.forward_pydantic_model is True:
                # ALWAYS forward data model to validation model in DEFAULT case
                # --> the validation model was a mere fallback for dict data
                validation_cfg.model = None  # we will forward the model below

    # 2. case CUSTOM
    elif isinstance(validation, ValidationConfig) or (
        isclass(validation) and issubclass(validation, JWTBaseModel)
    ):
        # 2.1 case ValidationConfig instance
        if isinstance(validation, ValidationConfig):
            # make a copy, mutable object!!
            validation_cfg = validation.model_copy(deep=True)

        # 2.2 case Pydantic model
        if isclass(validation) and issubclass(validation, JWTBaseModel):
            validation_cfg = ValidationConfig(model=validation)

    else:
        raise TypeError("Wrong validation object type")

    # finalize internal config
    if isinstance(data, JWTBaseModel):
        if validation_cfg.model is None:
            if validation_cfg.forward_pydantic_model is True:
                # forward data model type to validation model
                validation_cfg.model = type(data)
                # forward internal config from data model
                validation_cfg.apply_internal_cfg(data)
            else:
                # do not forward data internal config
                validation_cfg.apply_internal_cfg()
    else:
        # set default values for unset internal config
        # --> data is a dict and carries no config
        validation_cfg.apply_internal_cfg()

    return validation_cfg
