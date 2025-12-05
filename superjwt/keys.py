import warnings
from abc import ABC, abstractmethod
from typing import Self

from superjwt.exceptions import InvalidKeyError, SecurityWarning
from superjwt.utils import as_bytes, is_pem_format, is_ssh_key


class BaseKey(ABC):
    def __init__(self):
        self.private_key = b""

    @classmethod
    def import_key(cls, secret_key: str | bytes) -> Self:
        if cls is NoneKey:
            return cls()

        if secret_key is None or len(secret_key) == 0:
            raise ValueError("Secret key must not be empty")

        key = cls()
        key.prepare_key(as_bytes(secret_key))
        return key

    @abstractmethod
    def prepare_key(self, private_key: bytes) -> None: ...


class NoneKey(BaseKey):
    name = "none"

    def prepare_key(self, _: bytes) -> None: ...


class SymmetricKey(BaseKey): ...


class AsymmetricKey(BaseKey): ...


class OctetKey(SymmetricKey):
    """OctetKey is a symmetric key, defined by RFC7518 Section 6.4."""

    name = "oct"

    def prepare_key(self, private_key: bytes) -> None:
        if is_pem_format(private_key) or is_ssh_key(private_key):
            raise InvalidKeyError(
                "The specified key is an asymmetric key or x509 certificate and"
                " should not be used as an HMAC secret."
            )
        if len(private_key) < 14:
            # https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final
            warnings.warn("Key size should be >= 112 bits", SecurityWarning, stacklevel=3)
        self.private_key = private_key
