# Global algorithm instance cache for performance optimization
from enum import Enum

from typing_extensions import Self

from superjwt.algorithms import (
    BaseJWSAlgorithm,
    Ed448Algorithm,
    Ed25519Algorithm,
    ES256Algorithm,
    ES256KAlgorithm,
    ES384Algorithm,
    ES512Algorithm,
    HS256Algorithm,
    HS384Algorithm,
    HS512Algorithm,
    PS256Algorithm,
    PS384Algorithm,
    PS512Algorithm,
    RS256Algorithm,
    RS384Algorithm,
    RS512Algorithm,
)
from superjwt.exceptions import AlgorithmNotSupportedError, InvalidAlgorithmError


MAX_TOKEN_BYTES: int = 16 * 1024  # 16 KB


def set_max_token_bytes(max_bytes: int) -> None:
    """Set the maximum allowed size for JWT tokens in bytes."""
    global MAX_TOKEN_BYTES
    MAX_TOKEN_BYTES = max_bytes


def get_max_token_bytes() -> int:
    """Get the maximum allowed size for JWT tokens in bytes."""
    return MAX_TOKEN_BYTES


_ALGORITHM_INSTANCES: dict[str, BaseJWSAlgorithm] = {}


ALGORITHMS: dict[str, type[BaseJWSAlgorithm] | None] = {
    # frequently used
    "HS256": HS256Algorithm,
    "Ed25519": Ed25519Algorithm,
    "RS256": RS256Algorithm,
    "PS256": PS256Algorithm,
    # less frequently used
    "HS384": HS384Algorithm,
    "HS512": HS512Algorithm,
    "RS384": RS384Algorithm,
    "RS512": RS512Algorithm,
    "PS384": PS384Algorithm,
    "PS512": PS512Algorithm,
    "ES256": ES256Algorithm,
    "ES256K": ES256KAlgorithm,
    "ES384": ES384Algorithm,
    "ES512": ES512Algorithm,
    "EdDSA": None,  # Deprecated and not supported
    "Ed448": Ed448Algorithm,
}


def preload_algorithm_headers() -> dict[bytes, str]:
    """Preload encoded headers for all supported algorithms and create reverse lookup."""
    reverse_lookup: dict[bytes, str] = {}

    for alg_name, alg_class in ALGORITHMS.items():
        if alg_class is not None:
            headers_with_typ = alg_class.default_encoded_headers
            headers_without_typ = alg_class.default_encoded_headers_without_typ

            reverse_lookup[headers_with_typ] = alg_name
            reverse_lookup[headers_without_typ] = alg_name

    return reverse_lookup


_PRELOADED_HEADERS_TO_ALGORITHM = preload_algorithm_headers()


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
    EdDSA = "EdDSA"
    Ed25519 = "Ed25519"
    Ed448 = "Ed448"

    def get_instance(self) -> BaseJWSAlgorithm:
        return get_cached_algorithm(self.value)

    @staticmethod
    def get_instance_by_name(name: str) -> BaseJWSAlgorithm:
        if name not in ALGORITHMS:
            raise InvalidAlgorithmError(
                f"Algorithm '{name}' is not a valid JWS algorithm"
            )
        return getattr(Alg, name).get_instance()

    @classmethod
    def get_algorithm(cls, algorithm: Self | str) -> BaseJWSAlgorithm:
        if isinstance(algorithm, cls):
            instance = algorithm.get_instance()
            return instance
        else:
            return get_cached_algorithm(algorithm)

    @staticmethod
    def find_from_encoded_headers(encoded_headers: bytes) -> str | None:
        return _PRELOADED_HEADERS_TO_ALGORITHM.get(encoded_headers)


SUPPORTED_ALGORITHMS = Alg.__members__.keys()


def _initialize_algorithm_cache() -> None:
    """Initialize the global algorithm instance cache."""
    global _ALGORITHM_INSTANCES

    for alg_name in ALGORITHMS.keys():
        alg_class = ALGORITHMS.get(alg_name)
        if alg_class is not None:
            _ALGORITHM_INSTANCES[alg_name] = alg_class()


# Initialize the cache when the module is imported
_initialize_algorithm_cache()


def get_cached_algorithm(algorithm_name: str) -> BaseJWSAlgorithm:
    """Get a cached algorithm instance by name."""
    if algorithm_name not in _ALGORITHM_INSTANCES:
        if algorithm_name not in ALGORITHMS:
            raise InvalidAlgorithmError(
                f"Algorithm '{algorithm_name}' is not a valid JWS algorithm"
            )
        # Check if algorithm is explicitly marked as not implemented
        if ALGORITHMS[algorithm_name] is None:
            raise AlgorithmNotSupportedError(
                f"JWS Algorithm '{algorithm_name}' is not yet implemented"
            )

    return _ALGORITHM_INSTANCES[algorithm_name]
