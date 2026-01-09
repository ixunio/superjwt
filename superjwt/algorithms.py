import hashlib
import hmac
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Generic, TypeVar

from superjwt.exceptions import SuperJWTError
from superjwt.keys import BaseKey, NoneKey, OctKey, RSAKey
from superjwt.utils import check_cryptography_available


if check_cryptography_available(raise_error=False):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding


KeyType = TypeVar("KeyType", bound=BaseKey)


class BaseJWSAlgorithm(ABC, Generic[KeyType]):
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
            raise SuperJWTError("Key must be a NoneKey for 'none' algorithm")

    def sign(self, _: bytes, __: NoneKey) -> bytes:
        return b"no-signature"

    def verify(self, _: bytes, __: bytes, ___: NoneKey) -> bool:
        return True


class HMACWithSHAAlgorithm(BaseJWSAlgorithm[OctKey]):
    """Base class for HMAC using SHA algorithms"""

    key_type = OctKey

    def __init__(self, hash_algorithm: Any):
        self.hash_algorithm = hash_algorithm

    def check_key(self, key: OctKey) -> None:
        if not isinstance(key, OctKey):
            raise SuperJWTError("Key must be an OctKey for HMAC algorithms")

    def sign(self, data: bytes, key: OctKey) -> bytes:
        return hmac.new(key.private_key, data, self.hash_algorithm).digest()

    def verify(self, data: bytes, signature: bytes, key: OctKey) -> bool:
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


class RSAAlgorithm(BaseJWSAlgorithm[RSAKey]):
    """Base class for RSA using SHA algorithms (RSASSA-PKCS1-v1_5)"""

    key_type = RSAKey

    def __init__(self, hash_algorithm: Any):
        check_cryptography_available()
        self.hash_algorithm = hash_algorithm

        self.padding = padding.PKCS1v15()

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


class RS256Algorithm(RSAAlgorithm):
    name = "RS256"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"

    def __init__(self):
        super().__init__(hash_algorithm=hashes.SHA256())


class RS384Algorithm(RSAAlgorithm):
    name = "RS384"
    description = "RSASSA-PKCS1-v1_5 using SHA-384"

    def __init__(self):
        super().__init__(hash_algorithm=hashes.SHA384())


class RS512Algorithm(RSAAlgorithm):
    name = "RS512"
    description = "RSASSA-PKCS1-v1_5 using SHA-512"

    def __init__(self):
        super().__init__(hash_algorithm=hashes.SHA512())


class RSAPSSAlgorithm(RSAAlgorithm):
    """Base class for RSA using SHA algorithms with PSS padding (RSASSA-PSS)"""

    def __init__(self, hash_algorithm: Any):
        check_cryptography_available()
        self.hash_algorithm = hash_algorithm

        # Use PSS padding with MGF1 instead of PKCS1v15
        self.padding = padding.PSS(
            mgf=padding.MGF1(hash_algorithm),
            salt_length=hash_algorithm.digest_size,
        )


class PS256Algorithm(RSAPSSAlgorithm):
    name = "PS256"
    description = "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"

    def __init__(self):
        super().__init__(hash_algorithm=hashes.SHA256())


class PS384Algorithm(RSAPSSAlgorithm):
    name = "PS384"
    description = "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"

    def __init__(self):
        super().__init__(hash_algorithm=hashes.SHA384())


class PS512Algorithm(RSAPSSAlgorithm):
    name = "PS512"
    description = "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"

    def __init__(self):
        super().__init__(hash_algorithm=hashes.SHA512())
