import hashlib
import hmac
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, ClassVar, Generic, TypeVar

from superjwt.exceptions import SuperJWTError
from superjwt.keys import BaseKey, NoneKey, OctKey, RSAKey
from superjwt.utils import check_cryptography_available


if check_cryptography_available(raise_error=False):  # pragma: no cover
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding


KeyType = TypeVar("KeyType", bound=BaseKey)


class Hash(str, Enum):
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"


class BaseJWSAlgorithm(ABC, Generic[KeyType]):
    name: ClassVar[str]
    description: ClassVar[str]
    key_type: type[KeyType]
    requires_cryptography: ClassVar[bool] = True

    @abstractmethod
    def check_key(self, key: KeyType) -> None: ...

    @abstractmethod
    def sign(self, data: bytes, key: KeyType) -> bytes: ...

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, key: KeyType) -> bool: ...


class HMACWithSHAAlgorithm(BaseJWSAlgorithm[OctKey]):
    """Base class for HMAC using SHA algorithms"""

    key_type = OctKey
    requires_cryptography = False

    def __init__(self, hash_: Hash):
        self.hash_ = hash_

    @property
    def hash_algorithm(self) -> Any:
        return getattr(hashlib, self.hash_.value.replace("-", "").lower())

    def check_key(self, key: OctKey) -> None:
        if not isinstance(key, OctKey):
            raise SuperJWTError("Key must be an OctKey for HMAC algorithms")

    def sign(self, data: bytes, key: OctKey) -> bytes:
        return hmac.new(key.private_key, data, self.hash_algorithm).digest()

    def verify(self, data: bytes, signature: bytes, key: OctKey) -> bool:
        return hmac.compare_digest(signature, self.sign(data, key))


class RSAAlgorithm(BaseJWSAlgorithm[RSAKey]):
    """Base class for RSA using SHA algorithms"""

    key_type = RSAKey

    def __init__(self, hash_: Hash):
        check_cryptography_available()
        self.hash_ = hash_
        self._padding: padding.AsymmetricPadding

    @property
    def hash_algorithm(self) -> Any:
        return getattr(hashes, self.hash_.value.replace("-", "").upper())()

    @property
    def padding(self):
        return self._padding

    def check_key(self, key: RSAKey) -> None:
        if not isinstance(key, RSAKey):
            raise SuperJWTError("Key must be an RSAKey for RSA algorithms")

    def sign(self, data: bytes, key: RSAKey) -> bytes:
        """Sign data using RSA private key."""
        private_key = key._get_private_key()
        return private_key.sign(data, self.padding, self.hash_algorithm)

    def verify(self, data: bytes, signature: bytes, key: RSAKey) -> bool:
        """Verify signature using RSA public key."""

        public_key = key._get_public_key()
        try:
            public_key.verify(signature, data, self.padding, self.hash_algorithm)
            return True
        except InvalidSignature:
            return False


class RSAPKCS1v15Algorithm(RSAAlgorithm):
    """Base class for RSA using SHA algorithms with PKCS1 v1.5 padding (RSASSA-PKCS1-v1_5)"""

    def __init__(self, hash_: Hash):
        super().__init__(hash_)

        # Use PKCS1 v1.5 padding
        self._padding = padding.PKCS1v15()


class RSAPSSAlgorithm(RSAAlgorithm):
    """Base class for RSA using SHA algorithms with PSS padding (RSASSA-PSS)"""

    def __init__(self, hash_: Hash):
        super().__init__(hash_)

        # Use PSS padding with MGF1 and salt length equal to hash digest size
        self._padding = padding.PSS(
            mgf=padding.MGF1(self.hash_algorithm),
            salt_length=self.hash_algorithm.digest_size,
        )


####################################################################


class NoneAlgorithm(BaseJWSAlgorithm[NoneKey]):
    """No digital signature performed. Disabled by default for security reasons."""

    name = "none"
    description = "No signature"
    key_type = NoneKey
    requires_cryptography = False

    def check_key(self, key: NoneKey) -> None:
        if not isinstance(key, NoneKey):
            raise SuperJWTError("Key must be a NoneKey for 'none' algorithm")

    def sign(self, _: bytes, __: NoneKey) -> bytes:
        return b"no-signature"

    def verify(self, _: bytes, __: bytes, ___: NoneKey) -> bool:
        return True


class HS256Algorithm(HMACWithSHAAlgorithm):
    name = "HS256"
    description = "HMAC with SHA-256 signature"

    def __init__(self):
        super().__init__(Hash.SHA256)


class HS384Algorithm(HMACWithSHAAlgorithm):
    name = "HS384"
    description = "HMAC with SHA-384 signature"

    def __init__(self):
        super().__init__(Hash.SHA384)


class HS512Algorithm(HMACWithSHAAlgorithm):
    name = "HS512"
    description = "HMAC with SHA-512 signature"

    def __init__(self):
        super().__init__(Hash.SHA512)


class RS256Algorithm(RSAPKCS1v15Algorithm):
    name = "RS256"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"

    def __init__(self):
        super().__init__(Hash.SHA256)


class RS384Algorithm(RSAPKCS1v15Algorithm):
    name = "RS384"
    description = "RSASSA-PKCS1-v1_5 using SHA-384"

    def __init__(self):
        super().__init__(Hash.SHA384)


class RS512Algorithm(RSAPKCS1v15Algorithm):
    name = "RS512"
    description = "RSASSA-PKCS1-v1_5 using SHA-512"

    def __init__(self):
        super().__init__(Hash.SHA512)


class PS256Algorithm(RSAPSSAlgorithm):
    name = "PS256"
    description = "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"

    def __init__(self):
        super().__init__(Hash.SHA256)


class PS384Algorithm(RSAPSSAlgorithm):
    name = "PS384"
    description = "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"

    def __init__(self):
        super().__init__(Hash.SHA384)


class PS512Algorithm(RSAPSSAlgorithm):
    name = "PS512"
    description = "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"

    def __init__(self):
        super().__init__(Hash.SHA512)
