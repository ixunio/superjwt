from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    HttpUrl,
    PlainSerializer,
    SecretBytes,
    UrlConstraints,
    ValidationInfo,
    computed_field,
    field_validator,
    model_validator,
)

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
)
from superjwt.keys import BaseKey, NoneKey, OctetKey


Algorithm = Literal[
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
]


class AlgorithmInstance(Enum):
    none = NoneAlgorithm()
    HS256 = HS256Algorithm()
    HS384 = HS384Algorithm()
    HS512 = HS512Algorithm()
    RS256 = None  # Placeholder
    RS384 = None  # Placeholder
    RS512 = None  # Placeholder
    ES256 = None  # Placeholder
    ES384 = None  # Placeholder
    ES512 = None  # Placeholder
    EdDSA = None  # Placeholder
    ES256K = None  # Placeholder


class Key(Enum):
    NoneKey = NoneKey()
    OctetKey = OctetKey()
    RSAKey = None  # Placeholder
    ECKey = None  # Placeholder
    OKPKey = None  # Placeholder


class HttpsUrl(HttpUrl):
    _constraints = UrlConstraints(max_length=2083, allowed_schemes=["https"])


class DataModel(BaseModel):
    model_config = {"extra": "allow"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class JOSEHeader(DataModel):
    model_config = {"extra": "allow"}

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

        crit_headers_strict_check: bool = info.context  # type: ignore
        if value is not None and len(value) == 0:  # empty list is forbidden
            raise ValueError("'crit' header must be a non-empty list of strings")

        missing = []
        unsupported = []
        for el in value:
            # check for missing headers declared in 'crit'
            if el not in info.data.keys():
                missing.append(el)
            # check for unsupported custom headers
            elif crit_headers_strict_check and (el not in cls.model_fields.keys()):
                unsupported.append(el)
        if missing:
            raise ValueError(f"Missing crit headers: {', '.join(missing)}")
        if unsupported:
            raise ValueError(f"Unsupported custom crit headers: {', '.join(unsupported)}")

        if "b64" in info.data.keys():
            if "b64" not in value:
                raise ValueError("'b64' header parameter must be listed in 'crit' header")

        return value


def remove_subsecond(dt: datetime | None) -> datetime | None:
    if dt is None:
        return dt
    return dt.replace(microsecond=0)


def serialize_second_timestamps(value: datetime | int | float | None) -> int | None:
    if value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, datetime):
        return int(value.timestamp())
    raise TypeError("Invalid type for datetime serialization")


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


SecondDatetime = Annotated[
    datetime,
    AfterValidator(remove_subsecond),
    AfterValidator(check_future_dates),
    PlainSerializer(serialize_second_timestamps),
]


class JWTClaims(DataModel):
    model_config = {"extra": "allow"}

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
    iat: SecondDatetime | None = Field(
        description="issued at time - the time at which the JWT was issued",
        default_factory=lambda: datetime.now(UTC).replace(microsecond=0),
    )  # this field does not use Annotated to avoid pylance issues with default_factory
    nbf: Annotated[
        SecondDatetime | None,
        Field(
            description="not before time - the time before which the JWT must not be accepted"
        ),
    ] = None
    exp: Annotated[
        SecondDatetime | None,
        Field(description="expiration time - the time after which the JWT expires"),
    ] = None
    jti: Annotated[
        str | None,
        Field(description="JWT ID - a unique identifier for the JWT"),
    ] = None

    @model_validator(mode="after")
    def check_exp_after_nbf(self) -> Self:
        if self.exp is not None and self.nbf is not None:
            if self.nbf >= self.exp:
                raise ValueError("'nbf' claim must be strictly less than 'exp' claim")
        return self

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
        now = datetime.now(UTC).replace(microsecond=0) if self.iat is None else self.iat
        exp_time = now + timedelta(minutes=minutes, hours=hours, days=days)
        return self.model_copy(update={"exp": exp_time})


class JWSTokenEncoded(BaseModel):
    header: bytes
    payload: bytes
    signature: SecretBytes
    has_detached_payload: bool = False

    @computed_field
    @property
    def signing_input(self) -> bytes:
        return b".".join((self.header, self.payload))

    @computed_field
    @property
    def compact(self) -> bytes:
        if self.has_detached_payload:
            return b".".join((self.header, b"", self.signature.get_secret_value()))
        return b".".join(
            (
                self.header,
                self.payload,
                self.signature.get_secret_value(),
            )
        )


class JWSTokenDecoded(BaseModel):
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: SecretBytes


MAX_TOKEN_LENGTH: int = 16 * 1024  # 16 KB


class JWSToken(BaseModel):
    encoded: JWSTokenEncoded = JWSTokenEncoded(
        header=b"", payload=b"", signature=SecretBytes(b"")
    )
    decoded: JWSTokenDecoded = JWSTokenDecoded(
        header={}, payload={}, signature=SecretBytes(b"")
    )


class JWSTokenLifeCycle(BaseModel):
    unsafe: JWSToken = JWSToken()
    validated: JWSToken = JWSToken()


class JWTContent(BaseModel):
    claims: dict[str, Any]
    jws_token: JWSToken

    @computed_field
    @property
    def compact(self) -> bytes:
        return self.jws_token.encoded.compact


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
