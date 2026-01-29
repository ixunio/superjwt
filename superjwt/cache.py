"""Caching infrastructure for JWT decoding operations.

Provides optional caching for JSON deserialization and Pydantic validation
to improve performance when decoding the same JWT multiple times.
"""

import hashlib
import json
import time
from typing import TYPE_CHECKING, Any, TypeVar

from superjwt.keys import Key
from superjwt.shared import Alg
from superjwt.utils import as_bytes
from superjwt.validations import (
    JOSEHeader,
    JWTBaseModel,
    Validation,
    ValidationConfig,
)


if TYPE_CHECKING:
    from cachetools import TTLCache

T = TypeVar("T")


class CacheConfig:
    """Configuration for JWT decoding caches.

    Attributes:
        enabled (bool): Whether caching is enabled.
        max_size (int): Maximum number of items in each cache.
        default_ttl (int): Default TTL in seconds when no exp claim is present.
        max_ttl (int): Maximum TTL in seconds even if exp is further in the future.
    """

    def __init__(
        self,
        enabled: bool = True,
        max_size: int = 1000,
        default_ttl: int = 60,
        max_ttl: int = 300,
    ):
        from cachetools import TTLCache

        self.enabled = enabled
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.max_ttl = max_ttl

        # Create cache instances
        self._segment_cache: TTLCache[bytes, Any] | None = None
        self._validation_cache: TTLCache[bytes, Any] | None = None
        self._jwt_cache: TTLCache[bytes, Any] | None = None

        if enabled:
            # Cache for complete JWT decode results
            self._jwt_cache = TTLCache(maxsize=max_size, ttl=default_ttl)

    @property
    def jwt_cache(self) -> "TTLCache[bytes, Any] | None":
        """Get the complete JWT decode cache."""
        return self._jwt_cache


def calculate_ttl(
    exp: int | float | None,
    nbf: int | float | None,
    default_ttl: int,
    max_ttl: int,
) -> int:
    """Calculate the TTL for caching based on JWT exp and nbf claims.

    Args:
        exp: The exp (expiration) claim from the JWT payload.
        nbf: The nbf (not before) claim from the JWT payload.
        default_ttl: Default TTL to use if no exp claim is present.
        max_ttl: Maximum TTL to enforce.

    Returns:
        int: The calculated TTL in seconds (minimum 1 second).
    """
    now = int(time.time())

    # Handle nbf (not before) claim
    if nbf is not None and isinstance(nbf, (int, float)):
        nbf_int = int(nbf)
        if nbf_int > now:
            # Token not yet valid, use minimal TTL or don't cache
            time_until_valid = nbf_int - now
            if time_until_valid > max_ttl:
                # Too far in the future, use minimal cache
                return 1
            # Cache until it becomes valid
            return max(1, time_until_valid)

    # Handle exp (expiration) claim
    if exp is not None and isinstance(exp, (int, float)):
        exp_int = int(exp)
        ttl = exp_int - now

        # If already expired, use minimal TTL (1 second)
        if ttl <= 0:
            return 1

        # Apply max_ttl cap
        return min(ttl, max_ttl)

    # No exp claim, use default TTL
    return default_ttl


def decode_from_cache_or_compute(
    cache: "CacheConfig | None",
    compact: bytes | str,
    key: Key | bytes | str,
    algorithm: Alg | str,
    validation: type[JWTBaseModel] | ValidationConfig | Validation.Flags | None,
    headers_validation: type[JOSEHeader] | ValidationConfig | Validation.Flags | None,
    with_detached_payload: JWTBaseModel | dict[str, Any] | None = None,
) -> JWTBaseModel:
    """Get complete JWT decode result from cache or compute it.

    This caches the entire JWT decoding process: JWS decode + Pydantic validation.

    Args:
        cache: The cache config, or None to skip caching.
        compact: The JWT compact token.
        key: The key for signature verification.
        algorithm: The algorithm to use.
        validation: Claims validation configuration.
        headers_validation: Headers validation configuration.
        with_detached_payload: Detached payload if any.

    Returns:
        JWTBaseModel: The fully decoded and validated JWT as a Pydantic model.
    """
    if cache is None or not cache.enabled:
        from superjwt.jwt import _decode_jwt_uncached

        return _decode_jwt_uncached(
            compact, key, algorithm, validation, headers_validation, with_detached_payload
        )

    # Create cache key that includes all relevant parameters
    cache_key = _create_jwt_cache_key(
        compact, key, algorithm, validation, headers_validation, with_detached_payload
    )

    # Try to get from cache
    if cache.jwt_cache is not None and cache_key in cache.jwt_cache:
        return cache.jwt_cache[cache_key]

    # Compute result
    from superjwt.jwt import _decode_jwt_uncached

    result = _decode_jwt_uncached(
        compact, key, algorithm, validation, headers_validation, with_detached_payload
    )

    # Calculate TTL based on the decoded payload
    exp = getattr(result, "exp", None)
    nbf = getattr(result, "nbf", None)
    ttl = calculate_ttl(exp, nbf, cache.default_ttl, cache.max_ttl)

    # Only cache if TTL is positive (token hasn't expired)
    if ttl > 0 and cache.jwt_cache is not None:
        cache.jwt_cache[cache_key] = result

    return result


def _create_jwt_cache_key(
    compact: bytes | str,
    key: Key | bytes | str,
    algorithm: Alg | str,
    validation: type[JWTBaseModel] | ValidationConfig | Validation.Flags | None,
    headers_validation: type[JOSEHeader] | ValidationConfig | Validation.Flags | None,
    with_detached_payload: JWTBaseModel | dict[str, Any] | None = None,
) -> bytes:
    """Create a deterministic cache key for JWT decoding."""

    # Convert all parameters to strings for hashing
    key_parts = [
        as_bytes(compact).decode("utf-8", errors="ignore"),
        str(key),  # Key representation
        str(algorithm),
        str(validation),
        str(headers_validation),
    ]

    if with_detached_payload is not None:
        if isinstance(with_detached_payload, dict):
            key_parts.append(json.dumps(with_detached_payload, sort_keys=True))
        else:
            key_parts.append(str(with_detached_payload))

    # Create hash of all parameters
    key_string = "|".join(key_parts)
    return hashlib.sha256(key_string.encode()).digest()
