from datetime import datetime, timedelta
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
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


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


MAX_TOKEN_BYTES: int = 16 * 1024  # 16 KB

Algorithm = Literal[
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "Ed25519",
    "Ed448",
]


class AlgorithmInstance(Enum):
    none = NoneAlgorithm()
    HS256 = HS256Algorithm()
    HS384 = HS384Algorithm()
    HS512 = HS512Algorithm()
    RS256 = None  # Placeholder
    RS384 = None  # Placeholder
    RS512 = None  # Placeholder
    PS256 = None  # Placeholder
    PS384 = None  # Placeholder
    PS512 = None  # Placeholder
    ES256 = None  # Placeholder
    ES256K = None  # Placeholder
    ES384 = None  # Placeholder
    ES512 = None  # Placeholder
    Ed25519 = None  # Placeholder
    Ed448 = None  # Placeholder


class Key(Enum):
    NoneKey = NoneKey()
    OctKey = OctKey()
    RSAKey = None  # Placeholder
    ECKey = None  # Placeholder
    OKPKey = None  # Placeholder


class HttpsUrl(HttpUrl):
    _constraints = UrlConstraints(max_length=2083, allowed_schemes=["https"])


DEFAULT_JWTDATETIME_FORCE_INT: bool = True


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
        Algorithm | Literal["none"],
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
    def make_default(cls, algorithm: Algorithm) -> Self:
        return cls(alg=algorithm, typ="JWT")

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


def check_future_dates(value: datetime | None, info: ValidationInfo) -> datetime | None:
    iat = info.data.get("iat")
    if value is None or iat is None:
        return value
    if not isinstance(iat, datetime) or not isinstance(value, datetime):
        raise TypeError("Invalid type for datetime comparison")
    if value <= iat:
        raise ValueError(
            f"'{info.field_name}' claim must be strictly greater than 'iat' claim"
        )
    return value


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
        AfterValidator(check_future_dates),
    ] = None
    exp: Annotated[
        JWTDatetime | None,
        Field(description="expiration time - the time after which the JWT expires"),
        AfterValidator(check_future_dates),
    ] = None
    jti: Annotated[
        str | None,
        Field(description="JWT ID - a unique identifier for the JWT"),
    ] = None


class JWTClaims(JWTClaimsModel):
    """
    JWT standard claims as per RFC 7519.
    """

    @property
    def now(self) -> datetime:
        """Get the current time."""
        if self.internal__now is None:
            return datetime.now(UTC)
        return self.internal__now

    @staticmethod
    def get_now(info: ValidationInfo) -> datetime:
        now = info.data["internal__now"]
        if now is None:
            return datetime.now(UTC)
        return now

    @model_validator(mode="after")
    def check_exp_after_nbf(self) -> Self:
        if self.exp is not None and self.nbf is not None:
            if self.nbf >= self.exp:
                raise ValueError("'nbf' claim must be strictly less than 'exp' claim")
        return self

    @field_validator("exp")
    @classmethod
    def validate_exp(
        cls, value: datetime | None, info: ValidationInfo
    ) -> datetime | None:
        if value is None:
            return value
        if value <= cls.get_now(info):
            raise TokenExpiredError()
        return value

    @field_validator("nbf")
    @classmethod
    def validate_nbf(
        cls, value: datetime | None, info: ValidationInfo
    ) -> datetime | None:
        if value is None:
            return value
        if value > cls.get_now(info):
            raise TokenNotYetValidError()
        return value

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
        minutes: int = 0,
        hours: int = 0,
        days: int = 0,
    ) -> Self:
        """Return a new JWTClaims instance with the 'exp' claim set to current time plus the specified delta."""
        if minutes < 0 or hours < 0 or days < 0:
            raise ValueError(
                "Expiration minutes, hours, and days must be non-negative integers"
            )
        exp_time = self.now + timedelta(minutes=minutes, hours=hours, days=days)

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


def get_jws_algorithm(algorithm: Algorithm | Literal["none"]) -> BaseJWSAlgorithm:
    if algorithm not in AlgorithmInstance.__members__:
        raise InvalidAlgorithmError(
            f"Algorithm '{algorithm}' is not a valid JWS algorithm"
        )
    if (algo_jws := getattr(AlgorithmInstance, algorithm).value) is None:
        raise AlgorithmNotSupportedError(
            f"JWS Algorithm '{algorithm}' is not yet implemented"
        )
    return algo_jws


def make_key(algorithm: Algorithm | Literal["none"], key: str | bytes) -> BaseKey:
    key_type = get_jws_algorithm(algorithm).key_type
    return key_type.import_key(key)


class JWTValidationModelConfig(BaseModel):
    enabled: bool = True

    # validation
    default_validation_model: type[BaseModel] = JWTBaseModel
    force_validation_on_pydantic_model: bool = True

    # data storage
    default_data_model: type[BaseModel] = JWTBaseModel


JWTDisabledValidationConfig = JWTValidationModelConfig(enabled=False)

JWTClaimsDefaultValidationConfig = JWTValidationModelConfig(
    default_validation_model=JWTBaseModel,
    force_validation_on_pydantic_model=True,
    default_data_model=JWTBaseModel,
)
JWTHeadersDefaultValidationConfig = JWTValidationModelConfig(
    default_validation_model=JOSEHeader,
    force_validation_on_pydantic_model=True,
    default_data_model=JOSEHeader,
)


class Validation(Enum):
    """Flags to control validation behavior in JWT operations."""

    DEFAULT = "default"
    DISABLE = "disable"


def get_effective_data_model(
    data: JWTBaseModel | dict[str, Any],
    validation_model: type[BaseModel] | JWTValidationModelConfig | None,
) -> type[BaseModel]:
    """Determine the effective pydantic model to use for internal data storage."""

    # 1. case validation is disabled (use generic)
    if validation_model is None:
        return JWTBaseModel

    # 2. case when data is not a pydantic model (a dict)
    if not isinstance(data, BaseModel):
        # 2.1 validation model was specified (use it)
        if not isinstance(validation_model, JWTValidationModelConfig):
            return validation_model
        # 2.2 no validation model was specified (use default data model)
        return validation_model.default_data_model

    # 3. case when data is already a pydantic model (use it)
    return type(data)


def get_effective_data_validation_model(
    data: JWTBaseModel | dict[str, Any],
    validation_model: type[BaseModel] | JWTValidationModelConfig | None,
) -> type[BaseModel] | None:
    """Determine the effective pydantic model to use for internal data validation."""

    # 1. case validation is disabled
    if validation_model is None:
        return None

    # 2. case validation model was specified (use it)
    if not isinstance(validation_model, JWTValidationModelConfig):
        return validation_model

    # 3. case validation model was not specified (is a JWTValidationModelConfig)
    # 3.1 case data is not a pydantic model (a dict)
    if not isinstance(data, BaseModel):
        return validation_model.default_validation_model
    # 3.2 case data is already a pydantic model
    else:
        # 3.2.1 override default behavior to use data pydantic model itself
        if validation_model.force_validation_on_pydantic_model:
            return type(data)
        # 3.2.2 use default behavior
        else:
            return validation_model.default_validation_model


def prepare_and_validate_data(
    data: JWTBaseModel | dict[str, Any],
    validation_model: type[BaseModel] | None,
    type_err_msg: str | None = None,
) -> dict[str, Any]:
    """Prepare data as dict and perform pydantic validation if required."""

    # --> case data is a dict
    if isinstance(data, dict):
        data_dict = data.copy()
        if validation_model is not None:
            validation_model.model_validate(data_dict)
        return data_dict

    # --> case data is a pydantic model
    elif isinstance(data, JWTBaseModel):
        data_dict = data.to_dict()
        if validation_model is not None:
            validation_model.model_validate(data)
        return data_dict

    else:
        raise TypeError(
            "Wrong type during data preparation and validation"
            if type_err_msg is None
            else f": {type_err_msg}"
        )
