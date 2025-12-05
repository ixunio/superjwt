import hashlib
import hmac
import warnings
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from superjwt.exceptions import JWTError, SecurityWarning
from superjwt.keys import BaseKey, NoneKey, OctetKey


class BaseJWSAlgorithm[KeyType: BaseKey](ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    key_type: type[KeyType]

    @abstractmethod
    def check_key(self, key: KeyType) -> None: ...

    @abstractmethod
    def sign(self, data: bytes, key: KeyType) -> bytes: ...

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, key: KeyType) -> bool: ...


class NoneAlgorithm(BaseJWSAlgorithm[NoneKey]):
    """No digital signature performed. Disabled by default for security reasons."""

    name = "none"
    description = "No digital signature"
    key_type = NoneKey

    def check_key(self, key: NoneKey) -> None:
        if not isinstance(key, NoneKey):
            raise JWTError("Key must be a NoneKey for 'none' algorithm")

    def sign(self, _: bytes, __: NoneKey) -> bytes:
        return b""

    def verify(self, _: bytes, __: bytes, ___: NoneKey) -> bool:
        warnings.warn(
            "using 'none' algorithm is a security hazard, anyone can forge claims in the token",
            SecurityWarning,
            stacklevel=3,
        )
        return True


class HMACWithSHAAlgorithm(BaseJWSAlgorithm[OctetKey]):
    """Base class for HMAC using SHA algorithms"""

    key_type = OctetKey

    def __init__(self, hash_algorithm: Any):
        self.hash_algorithm = hash_algorithm

    def check_key(self, key: OctetKey) -> None:
        if not isinstance(key, OctetKey):
            raise JWTError("Key must be an OctetKey for HMAC algorithms")

    def sign(self, data: bytes, key: OctetKey) -> bytes:
        return hmac.new(key.private_key, data, self.hash_algorithm).digest()

    def verify(self, data: bytes, signature: bytes, key: OctetKey) -> bool:
        return hmac.compare_digest(signature, self.sign(data, key))


class HS256Algorithm(HMACWithSHAAlgorithm):
    name = "HS256"
    description = "HMAC with SHA-256 signature"

    def __init__(self):
        super().__init__(hash_algorithm=hashlib.sha256)


class HS384Algorithm(HMACWithSHAAlgorithm):
    name = "HS384"
    description = "HMAC with SHA-384 signature"

    def __init__(self):
        super().__init__(hash_algorithm=hashlib.sha384)


class HS512Algorithm(HMACWithSHAAlgorithm):
    name = "HS512"
    description = "HMAC with SHA-512 signature"

    def __init__(self):
        super().__init__(hash_algorithm=hashlib.sha512)
