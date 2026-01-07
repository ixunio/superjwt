from datetime import datetime, timedelta
from enum import Enum
from inspect import isclass
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    Field,
    HttpUrl,
    PlainSerializer,
    UrlConstraints,
    ValidationInfo,
    computed_field,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from superjwt.algorithms import (
    BaseJWSAlgorithm,
    HS256Algorithm,
    HS384Algorithm,
    HS512Algorithm,
    NoneAlgorithm,
)
from superjwt.exceptions import (
    AlgorithmNotSupportedError,
    InvalidAlgorithmError,
    InvalidHeadersError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from superjwt.keys import BaseKey, NoneKey, OctKey
from superjwt.utils import delta_datetime_timestamp


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


MAX_TOKEN_BYTES: int = 16 * 1024  # 16 KB


class Alg(str, Enum):
    """JWS/JWT Algorithm names with associated implementation instances."""

    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    ES256 = "ES256"
    ES256K = "ES256K"
    ES384 = "ES384"
    ES512 = "ES512"
    Ed25519 = "Ed25519"
    Ed448 = "Ed448"

    def get_instance(self) -> BaseJWSAlgorithm:
        instance = ALG_INSTANCES.get(self.value)
        if instance is None:
            raise AlgorithmNotSupportedError(
                f"JWS Algorithm '{self.value}' is not yet implemented"
            )
        return instance

    @classmethod
    def get_instance_by_name(cls, name: str) -> BaseJWSAlgorithm:
        if name not in ALG_INSTANCES:
            raise InvalidAlgorithmError(
                f"Algorithm '{name}' is not a valid JWS algorithm"
            )
        instance = ALG_INSTANCES[name]
        if instance is None:
            raise AlgorithmNotSupportedError(
                f"JWS Algorithm '{name}' is not yet implemented"
            )
        return instance


ALG_INSTANCES: dict[str, BaseJWSAlgorithm | None] = {
    "none": NoneAlgorithm(),
    "HS256": HS256Algorithm(),
    "HS384": HS384Algorithm(),
    "HS512": HS512Algorithm(),
    "RS256": None,  # Placeholder
    "RS384": None,  # Placeholder
    "RS512": None,  # Placeholder
    "PS256": None,  # Placeholder
    "PS384": None,  # Placeholder
    "PS512": None,  # Placeholder
    "ES256": None,  # Placeholder
    "ES256K": None,  # Placeholder
    "ES384": None,  # Placeholder
    "ES512": None,  # Placeholder
    "Ed25519": None,  # Placeholder
    "Ed448": None,  # Placeholder
}


class Key(Enum):
    NoneKey = NoneKey()
    OctKey = OctKey()
    RSAKey = None  # Placeholder
    ECKey = None  # Placeholder
    OKPKey = None  # Placeholder


class HttpsUrl(HttpUrl):
    _constraints = UrlConstraints(max_length=2083, allowed_schemes=["https"])


DEFAULT_JWTDATETIME_FORCE_INT: bool = True
DEFAULT_LEEWAY_SECONDS: float = 5.0


class JWTBaseModel(BaseModel):
    model_config = {"extra": "allow", "revalidate_instances": "always"}

    internal__now: Annotated[datetime | None, Field(exclude=True, repr=False)] = None
    internal__jwtdatetime_force_int: Annotated[bool, Field(exclude=True, repr=False)] = (
        DEFAULT_JWTDATETIME_FORCE_INT
    )

    def revalidate(self) -> None:
        """Re-validate the pydantic instance against its own model."""
        self.model_validate(self)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(
            exclude_none=True,
            context={"jwtdatetime_force_int": self.internal__jwtdatetime_force_int},
        )

    def force_jwtdatetime_to_int(self) -> None:
        """Force JWTDatetime fields to be serialized as integers (seconds since epoch)."""
        self.internal__jwtdatetime_force_int = True

    def force_jwtdatetime_to_float(self) -> None:
        """Force JWTDatetime fields to be serialized as floats (seconds since epoch with microseconds)."""
        self.internal__jwtdatetime_force_int = False

    def spoof_time(self, set_now: datetime | None) -> None:
        """Spoof the current time for testing purposes. Set to None to disable spoofing."""
        self.internal__now = set_now


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


def serialize_jwtdatetime_timestamp(
    value: datetime | int | float, info: ValidationInfo
) -> int | float:
    jwtdatetime_force_int = getattr(info, "context", {}).get(
        "jwtdatetime_force_int", DEFAULT_JWTDATETIME_FORCE_INT
    )
    if jwtdatetime_force_int is True:
        return serialize_jwtdatetime_timestamp_to_int(value)
    elif jwtdatetime_force_int is False:
        return serialize_jwtdatetime_timestamp_to_float(value)
    raise ValueError("Invalid timestamp config type")


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


JWTDatetime = Annotated[
    datetime,
    PlainSerializer(serialize_jwtdatetime_timestamp),
]

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
        JWTDatetime | None,
        Field(description="issued at time - the time at which the JWT was issued"),
    ] = None
    nbf: Annotated[
        JWTDatetime | None,
        Field(
            description="not before time - the time before which the JWT must not be accepted"
        ),
    ] = None
    exp: Annotated[
        JWTDatetime | None,
        Field(description="expiration time - the time after which the JWT expires"),
    ] = None
    jti: Annotated[
        str | None,
        Field(description="JWT ID - a unique identifier for the JWT"),
    ] = None


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
    def validate_time_integrity(self) -> Self:
        # check nbf >= iat
        if self.nbf is not None and self.iat is not None:
            if self.nbf < self.iat:
                raise ValueError(
                    "'nbf' claim must be greater than or equal to 'iat' claim"
                )

        # check iat <= now, modulo leeway
        if self.iat is not None and not self.internal__allow_future_iat:
            if delta_datetime_timestamp(self.iat, self.now) > self.internal__leeway:
                raise ValueError("'iat' claim must not be in the future")

        # check nbf <= now, modulo leeway
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
        if self.exp is not None and self.iat is not None:
            # preserve original delta between iat and exp
            delta = self.exp - self.iat
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
        if self.iat is not None:
            # rewrite iat value
            return self.model_copy(update={"iat": self.now, "exp": exp_time})

        return self.model_copy(update={"exp": exp_time})


class JWSTokenModel(BaseModel):
    headers: JOSEHeader | None = None
    claims: JWTBaseModel | None = None


class JWSToken(BaseModel):
    headers: dict[str, Any] = {}
    payload: dict[str, Any] = {}
    signature: bytes = b""

    encoded_headers: bytes = b""
    encoded_payload: bytes = b""
    encoded_signature: bytes = b""
    has_detached_payload: bool = False

    model: JWSTokenModel = JWSTokenModel()

    @computed_field
    @property
    def signing_input(self) -> bytes:
        return b".".join((self.encoded_headers, self.encoded_payload))

    @computed_field
    @property
    def compact(self) -> bytes:
        if self.has_detached_payload:
            return b".".join((self.encoded_headers, b"", self.encoded_signature))
        return b".".join(
            (
                self.encoded_headers,
                self.encoded_payload,
                self.encoded_signature,
            )
        )


class JWSTokenLifeCycle(BaseModel):
    unsafe: JWSToken = JWSToken()
    verified: JWSToken = JWSToken()


def get_jws_algorithm(algorithm: Alg | Literal["none"] | str) -> BaseJWSAlgorithm:
    # Convert to algorithm instance
    if isinstance(algorithm, Alg):
        return algorithm.get_instance()
    else:
        # Handle string input (including "none")
        return Alg.get_instance_by_name(algorithm)


def make_key(algorithm: Alg | Literal["none"] | str, key: str | bytes) -> BaseKey:
    key_type = get_jws_algorithm(algorithm).key_type
    return key_type.import_key(key)


class JWTValidationConfig(BaseModel):
    """JWT data validation object."""

    # ------------- General validation config -------------
    """Enable or disable data validation."""
    enabled: bool = True

    """The pydantic model to use for data validation."""
    validation_model: type[JWTBaseModel] | None = None

    """Forward the data pydantic model to validation config (and its internal config)."""
    forward_pydantic_model: bool = True

    """The default pydantic model to use for data storage when data is a dict."""
    data_model: type[JWTBaseModel] = Field(
        default_factory=lambda data: data["validation_model"]
    )

    # ------------- JWTBaseModel specific internal config -------------
    """Spoofed 'now' datetime."""
    now: datetime | None = None

    """Timestamp format for JWTDatetime fields."""
    jwtdatetime_force_int: bool | None = None

    # ------------- JWTClaims specific internal config -------------
    """Leeway for time-based validations, in seconds."""
    leeway: float | None = None

    """Allow 'iat' claim to be in the future."""
    allow_future_iat: bool | None = None

    def _internal_params_matrix(self) -> list[tuple[str, type[JWTBaseModel], Any]]:
        return [
            ("now", JWTBaseModel, None),
            ("jwtdatetime_force_int", JWTBaseModel, DEFAULT_JWTDATETIME_FORCE_INT),
            ("leeway", JWTClaims, DEFAULT_LEEWAY_SECONDS),
            ("allow_future_iat", JWTClaims, DEFAULT_ALLOW_FUTURE_IAT),
        ]

    def _get_internal_cfg(self) -> dict[str, Any]:
        """Get internal config values as a dict for injection into validation."""
        internal_config = {}
        for param, model_type, _ in self._internal_params_matrix():
            if self.validation_model is not None and issubclass(
                self.validation_model, model_type
            ):
                internal_config[f"internal__{param}"] = getattr(self, param)
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

    def run(self, data: JWTBaseModel | dict[str, Any]) -> dict[str, Any]:
        if self.enabled is False:
            return data.to_dict() if isinstance(data, JWTBaseModel) else data

        if self.validation_model is None:
            raise ValueError("Validation model is not set in JWTValidationConfig")

        # case pydantic model
        if isinstance(data, JWTBaseModel):
            data_dict = data.to_dict()

        # case dict
        elif isinstance(data, dict):
            data_dict = data.copy()

        else:
            raise TypeError("Wrong type during data preparation and validation")

        ##### BEGIN VALIDATION #####
        self.validation_model.model_validate(data_dict | self._get_internal_cfg())
        ##### END VALIDATION #####

        return data_dict


JWTClaimsDefaultValidation = JWTValidationConfig(
    validation_model=JWTBaseModel,
)
JWTClaimsStrictValidation = JWTValidationConfig(
    validation_model=JWTClaims,
)
JWTHeadersDefaultValidation = JWTValidationConfig(
    validation_model=JOSEHeader,
)


class Validation(Enum):
    """Flags to control validation behavior in JWT operations."""

    DEFAULT = "default"
    DISABLE = "disable"


def get_data_model(
    data: JWTBaseModel | dict[str, Any],
    validation: type[JWTBaseModel] | JWTValidationConfig | Validation | None,
    default_validation: JWTValidationConfig,
    fallback_model: type[JWTBaseModel],
) -> type[JWTBaseModel]:
    if validation is Validation.DEFAULT and isinstance(data, dict):
        return default_validation.data_model
    elif isinstance(validation, JWTValidationConfig):
        if validation.data_model is None:
            return fallback_model
        return validation.data_model
    elif (
        isclass(validation)
        and issubclass(validation, JWTBaseModel)
        and isinstance(data, dict)
    ):
        return validation
    elif isinstance(data, JWTBaseModel):
        return type(data)
    return fallback_model


def get_validation_config(
    data: JWTBaseModel | dict[str, Any],
    validation: type[JWTBaseModel] | JWTValidationConfig | Validation | None,
    default_validation: JWTValidationConfig,
) -> JWTValidationConfig:
    # case DISABLE
    if (
        validation is Validation.DISABLE
        or validation is None
        or (isinstance(validation, JWTValidationConfig) and validation.enabled is False)
    ):
        return JWTValidationConfig(enabled=False)

    # case DEFAULT (no information was specified)
    if validation is Validation.DEFAULT:
        # make a copy, mutable object!!
        validation_cfg = default_validation.model_copy(deep=True)
        if isinstance(data, JWTBaseModel):
            # forward internal cfg from data model and overwrite when unset
            validation_cfg.apply_internal_cfg(data)
            # (maybe) set validation model to data model
            if validation_cfg.forward_pydantic_model is True:
                validation_cfg.validation_model = type(data)
        else:
            # set default values for unset internal config
            validation_cfg.apply_internal_cfg()
        return validation_cfg

    # case JWTValidationCfg instance
    if isinstance(validation, JWTValidationConfig):
        # make a copy, mutable object!!
        validation_cfg = validation.model_copy(deep=True)

    # case Pydantic model
    elif isclass(validation) and issubclass(validation, JWTBaseModel):
        validation_cfg = JWTValidationConfig(validation_model=validation)

    else:
        raise TypeError("Wrong validation object type")

    if isinstance(data, JWTBaseModel):
        # forward internal cfg from data model and overwrite when unset
        validation_cfg.apply_internal_cfg(data)
    else:
        # set default values for unset internal config
        validation_cfg.apply_internal_cfg()

    return validation_cfg
