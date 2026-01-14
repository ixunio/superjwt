from __future__ import annotations

import secrets
import warnings
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar, Generic, Literal, TypeVar, cast

from superjwt.exceptions import InvalidKeyError, KeyLengthSecurityWarning, SuperJWTError
from superjwt.utils import (
    CRYPTOGRAPHY_AVAILABLE,
    as_bytes,
    check_cryptography_available,
    is_pem_format,
    is_ssh_key,
)


if CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa


if TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import Self


class Key(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    algorithms: ClassVar[tuple[str, ...]]

    def __init__(self):
        self.private_key = b""
        self.public_key = b""

    @classmethod
    @abstractmethod
    def import_signing_key(cls, key: bytes | str) -> Self:
        """Make a Key instance from the component needed for signing the JWT.

        For symmetric keys: requires the secret key.
        For asymmetric keys: requires the private key.
        """
        raise NotImplementedError(
            f"{cls.__name__} must implement import_signing_key()"
        )  # pragma: no cover

    @classmethod
    @abstractmethod
    def import_verifying_key(cls, key: bytes | str) -> Self:
        """Make a Key instance from the component needed for JWT verification.

        For symmetric keys: requires the secret key.
        For asymmetric keys: requires the public key.
        """
        raise NotImplementedError(
            f"{cls.__name__} must implement import_verifying_key()"
        )  # pragma: no cover

    @classmethod
    @abstractmethod
    def generate(cls, *args: object) -> Self:
        """Generate a new Key instance."""
        raise NotImplementedError(
            f"{cls.__name__} must implement generate()"
        )  # pragma: no cover

    @abstractmethod
    def _prepare_key(
        self,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
        derive_public_key: bool = True,
    ) -> None:
        """Prepare the key instance by loading the provided key components."""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement _prepare_key()"
        )  # pragma: no cover

    @classmethod
    def import_key(
        cls,
        private_key: bytes | str | None = None,
        public_key: bytes | str | None = None,
        derive_public_key: bool = True,
    ) -> Self:
        """Make a Key instance by importing key(s).

        When importing an asymmetric key, if only the private key is provided,
        the public key will be derived from it unless derive_public_key is False.
        If both private_key and public_key are provided and derive_public_key is True,
        they will be checked against each other for consistency.
        """
        if cls is NoneKey:
            return cls()

        if private_key is None and public_key is None:
            raise ValueError("No key was provided")

        if private_key is not None:
            private_key = as_bytes(private_key)
            if len(private_key) == 0:
                raise ValueError("Private key must not be empty")
        if public_key is not None:
            public_key = as_bytes(public_key)
            if len(public_key) == 0:
                raise ValueError("Public key must not be empty")
        key = cls()
        key._prepare_key(private_key, public_key, derive_public_key)
        return key


class NoneKey(Key):
    name = "NoneKey"
    description = "No key (used for 'none' algorithm)"
    algorithms = ("none",)

    @classmethod
    def import_signing_key(cls, _) -> Self:
        return cls()

    @classmethod
    def import_verifying_key(cls, _) -> Self:
        return cls()

    @classmethod
    def generate(cls) -> Self:
        return cls()  # pragma: no cover

    def _prepare_key(self, *_) -> None: ...


class SymmetricKey(Key):
    @classmethod
    def import_signing_key(cls, key: bytes | str) -> Self:
        return cls.import_key(key)

    @classmethod
    def import_verifying_key(cls, key: bytes | str) -> Self:
        return cls.import_key(key)

    def _prepare_key(self, secret_key: bytes, _, __) -> None:
        if _ is not None:
            raise SuperJWTError("Symmetric key should not have a public key component")
        if is_pem_format(secret_key) or is_ssh_key(secret_key):
            raise InvalidKeyError(
                "The specified key is an asymmetric key or x509 certificate and"
                " should not be used as an HMAC secret."
            )
        if len(secret_key) < 14:
            # https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final
            warnings.warn(
                f"HMAC key size is {len(secret_key) * 8} bits. "
                "Key size should be >= 112 bits for security",
                KeyLengthSecurityWarning,
                stacklevel=3,
            )
        self.private_key = secret_key


class OctKey(SymmetricKey):
    name = "oct"
    description = "Octet sequence key for HMAC algorithms"
    algorithms = ("HS256", "HS384", "HS512")

    @classmethod
    def generate(cls, key_size: int = 32, *, human_readable: bool = True) -> Self:
        """Generate a random symmetric key.

        Args:
            key_size: The size of the key in bytes. Default is 32 bytes (256 bits).
                      Recommended values:
                      - 32 bytes (256 bits) for HS256
                      - 48 bytes (384 bits) for HS384
                      - 64 bytes (512 bits) for HS512
            human_readable: If True, returns key as hex string (default).
                           If False, returns raw bytes.

        Returns:
            A new OctKey instance with a randomly generated key.
        """
        random_key_bytes = secrets.token_bytes(key_size)
        random_key = random_key_bytes.hex() if human_readable else random_key_bytes
        return cls.import_key(random_key, None)


if TYPE_CHECKING:
    PrivateKeyType = TypeVar(
        "PrivateKeyType",
        bound=rsa.RSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey,
    )
    PublicKeyType = TypeVar(
        "PublicKeyType",
        bound=rsa.RSAPublicKey
        | ec.EllipticCurvePublicKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey,
    )
else:  # pragma: no cover
    PrivateKeyType = TypeVar("PrivateKeyType")
    PublicKeyType = TypeVar("PublicKeyType")


class AsymmetricKey(Key, Generic[PrivateKeyType, PublicKeyType]):
    """Base class for asymmetric key types (RSA, EC, OKP)."""

    def __init__(self):
        super().__init__()

        check_cryptography_available()

        self._private_key_obj: PrivateKeyType | None = None
        self._public_key_obj: PublicKeyType | None = None

    @property
    @abstractmethod
    def private_key_types(self) -> tuple[type, ...]:
        """Return tuple of valid private key types for isinstance checks."""
        ...  # pragma: no cover

    @property
    @abstractmethod
    def public_key_types(self) -> tuple[type, ...]:
        """Return tuple of valid public key types for isinstance checks."""
        ...  # pragma: no cover

    @abstractmethod
    def check_key_security(self, key: PrivateKeyType | PublicKeyType) -> None:
        """Check key for security issues and emit warnings if needed.

        Args:
            key: The key object to check (private or public)
        """  # pragma: no cover
        ...

    @abstractmethod
    def public_keys_match(self, key1: PublicKeyType, key2: PublicKeyType) -> bool:
        """Compare two public keys for equality."""
        ...  # pragma: no cover

    @classmethod
    def import_signing_key(cls, key: bytes | str) -> Self:
        return cls.import_private_key(key)

    @classmethod
    def import_verifying_key(cls, key: bytes | str) -> Self:
        return cls.import_public_key(key)

    @classmethod
    def import_private_key(cls, key: bytes | str) -> Self:
        """Make a Key instance from PEM private key."""
        return cls.import_key(key, None, derive_public_key=False)

    @classmethod
    def import_public_key(cls, key: bytes | str) -> Self:
        """Make a Key instance from PEM public key."""
        return cls.import_key(None, key)

    def _prepare_key(
        self,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
        derive_public_key: bool = True,
    ) -> None:
        # Private key loading
        if private_key is not None:
            self._private_key_obj = self._load_pem_private_key_common(private_key)
            self.private_key = private_key
            self.check_key_security(self._private_key_obj)

            # load public key from private key derivation if not provided
            if public_key is None and derive_public_key:
                derived_obj, derived_pem = self._derive_public_key_from_private()
                self._public_key_obj = derived_obj
                self.public_key = derived_pem

            if public_key is not None and derive_public_key:
                # check public key matches derived from private key
                loaded_public_key_obj = self._load_pem_public_key_common(public_key)
                derived_obj, derived_pem = self._derive_public_key_from_private()
                if not self.public_keys_match(derived_obj, loaded_public_key_obj):
                    raise InvalidKeyError(
                        "Provided public key does not match the public key derived "
                        "from the private key"
                    )
                self._public_key_obj = loaded_public_key_obj
                self.public_key = public_key

        # Public key loading
        if private_key is None and public_key is not None:
            # Load public key
            self._public_key_obj = self._load_pem_public_key_common(public_key)
            self.public_key = public_key
            self.check_key_security(self._public_key_obj)

    def _load_pem_private_key_common(self, private_key: bytes) -> PrivateKeyType:
        """Common logic for loading a PEM-encoded private key."""
        if not is_pem_format(private_key):
            raise InvalidKeyError(
                f"{self.name} private key must be in PEM format (BEGIN PRIVATE KEY)"
            )

        try:
            loaded_key = serialization.load_pem_private_key(
                private_key, password=None, backend=default_backend()
            )

            if not isinstance(loaded_key, self.private_key_types):
                raise InvalidKeyError(f"Key must be an {self.name} private key")

            return cast("PrivateKeyType", loaded_key)
        except (ValueError, TypeError) as e:
            raise InvalidKeyError(f"Unable to parse {self.name} private key: {e}") from e

    def _load_pem_public_key_common(self, public_key: bytes) -> PublicKeyType:
        """Common logic for loading a PEM-encoded public key."""
        if not is_pem_format(public_key):
            raise InvalidKeyError(
                f"{self.name} public key must be in PEM format (BEGIN PUBLIC KEY)"
            )

        try:
            loaded_key = serialization.load_pem_public_key(
                public_key, backend=default_backend()
            )

            if not isinstance(loaded_key, self.public_key_types):
                raise InvalidKeyError(f"Key must be an {self.name} public key")

            return cast("PublicKeyType", loaded_key)
        except (ValueError, TypeError) as e:
            raise InvalidKeyError(f"Unable to parse {self.name} public key: {e}") from e

    def _derive_public_key_from_private(self) -> tuple[PublicKeyType, bytes]:
        """Derive public key from the loaded private key."""
        if self._private_key_obj is None:
            raise SuperJWTError("Cannot derive public key without a private key")
        derived_public_key_obj = cast("PublicKeyType", self._private_key_obj.public_key())
        derived_public_key_pem = derived_public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return derived_public_key_obj, derived_public_key_pem

    def _get_private_key(self) -> PrivateKeyType:
        """Get the cryptography private key object for signing."""
        if self._private_key_obj is None:
            raise SuperJWTError("This key does not have a private component for signing")
        return self._private_key_obj

    def _get_public_key(self) -> PublicKeyType:
        """Get the cryptography public key object for verification."""
        if self._public_key_obj is None:
            raise SuperJWTError(
                "This key does not have a public component for verification"
            )
        return self._public_key_obj

    def export_private_key_pem(self) -> bytes:
        """Export the private key as PEM-encoded PKCS8 format.

        Returns:
            bytes: The private key in PEM format (PKCS8)
        """
        private_key_obj = self._get_private_key()
        return private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def export_public_key_pem(self) -> bytes:
        """Export the public key as PEM-encoded SubjectPublicKeyInfo format.

        If only a private key is available, derives and exports the public key from it.

        Returns:
            bytes: The public key in PEM format (SubjectPublicKeyInfo)
        """
        public_key_obj = self._get_public_key()
        return public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class RSAKey(AsymmetricKey["rsa.RSAPrivateKey", "rsa.RSAPublicKey"]):
    name = "RSA"
    description = "RSA key for RSASSA-PKCS1-v1_5 and RSASSA-PSS algorithms"
    algorithms = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")

    @classmethod
    def generate(cls, key_size: Literal[2048, 3072, 4096]) -> Self:
        """Generate a new RSA key pair.

        Args:
            key_size: The size of the key in bits.
                      Recommended values: 2048, 3072, 4096.
        """
        check_cryptography_available()
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

        private_key_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cls.import_key(private_key=private_key_pem)

    @property
    def private_key_types(self) -> tuple[type, ...]:
        return (rsa.RSAPrivateKey,)

    @property
    def public_key_types(self) -> tuple[type, ...]:
        return (rsa.RSAPublicKey,)

    def check_key_security(self, key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> None:
        if key.key_size < 2048:
            warnings.warn(
                f"RSA key size is {key.key_size} bits. "
                "Key size should be >= 2048 bits for security",
                KeyLengthSecurityWarning,
                stacklevel=5,
            )

    def public_keys_match(self, key1: rsa.RSAPublicKey, key2: rsa.RSAPublicKey) -> bool:
        key1_numbers = key1.public_numbers()
        key2_numbers = key2.public_numbers()

        return key1_numbers.n == key2_numbers.n and key1_numbers.e == key2_numbers.e


class ECKey(AsymmetricKey["ec.EllipticCurvePrivateKey", "ec.EllipticCurvePublicKey"]):
    name = "EC"
    description = (
        "Elliptic Curve key for ECDSA algorithms with curve secp256r1 (P-256), "
        "secp256k1, secp384r1 (P-384), and secp521r1 (P-521)"
    )
    algorithms = ("ES256", "ES256K", "ES384", "ES512")

    @classmethod
    def generate(
        cls,
        curve: ec.EllipticCurve
        | Literal[
            # for ES256 algorithm
            "ES256",
            "secp256r1",
            "P-256",
            # for ES256K algorithm
            "ES256K",
            "secp256k1",
            # for ES384 algorithm
            "ES384",
            "secp384r1",
            "P-384",
            # for ES512 algorithm
            "ES512",
            "secp521r1",
            "P-521",
        ],
    ) -> Self:
        """Generate a new EC key pair.

        Args:
            curve: The elliptic curve to use. Can be an EllipticCurve instance,
                   a curve name: "P-256", "P-384", "P-521", "secp256r1",
                   "secp384r1", "secp521r1", "secp256k1",
                   or an algorithm name: "ES256", "ES256K", "ES384", "ES512".
        """
        check_cryptography_available()

        # Map string names to curve instances
        if isinstance(curve, str):
            curve_map = {
                # by curve names
                "P-256": ec.SECP256R1(),
                "secp256r1": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "secp384r1": ec.SECP384R1(),
                "P-521": ec.SECP521R1(),
                "secp521r1": ec.SECP521R1(),
                "secp256k1": ec.SECP256K1(),
                # by algorithm names
                "ES256": ec.SECP256R1(),
                "ES256K": ec.SECP256K1(),
                "ES384": ec.SECP384R1(),
                "ES512": ec.SECP521R1(),
            }
            if curve not in curve_map:
                raise SuperJWTError(
                    f"Unsupported curve: {curve}. "
                    f"Supported curves: {', '.join(curve_map.keys())}"
                )
            curve = curve_map[curve]
        elif not isinstance(curve, ec.EllipticCurve):
            raise SuperJWTError(
                "curve must be an instance of EllipticCurve or a valid curve name"
            )

        private_key_obj = ec.generate_private_key(
            cast("ec.EllipticCurve", curve), default_backend()
        )

        private_key_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cls.import_key(private_key=private_key_pem)

    @property
    def private_key_types(self) -> tuple[type, ...]:
        return (ec.EllipticCurvePrivateKey,)

    @property
    def public_key_types(self) -> tuple[type, ...]:
        return (ec.EllipticCurvePublicKey,)

    @property
    def curve_name(self) -> str:
        """Return the curve name of the key."""
        if self._private_key_obj is not None:
            return self._private_key_obj.curve.name
        assert self._public_key_obj is not None
        return self._public_key_obj.curve.name

    @property
    def curve_key_size(self) -> int:
        """Return the key size in bits of the curve."""
        if self._private_key_obj is not None:
            return self._private_key_obj.curve.key_size
        assert self._public_key_obj is not None
        return self._public_key_obj.curve.key_size

    def check_key_security(
        self, key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey
    ) -> None: ...

    def public_keys_match(
        self, key1: ec.EllipticCurvePublicKey, key2: ec.EllipticCurvePublicKey
    ) -> bool:
        """Compare two EC public keys for equality."""
        key1_numbers = key1.public_numbers()
        key2_numbers = key2.public_numbers()

        return (
            key1_numbers.x == key2_numbers.x
            and key1_numbers.y == key2_numbers.y
            and key1_numbers.curve.name == key2_numbers.curve.name
        )


class OKPKey(
    AsymmetricKey[
        "ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey",
        "ed25519.Ed25519PublicKey | ed448.Ed448PublicKey",
    ]
):
    name = "OKP"
    description = "Octet Key Pair for EdDSA algorithms (Ed25519, Ed448)"
    algorithms = ("Ed25519", "Ed448")

    @classmethod
    def generate(cls, curve: Literal["Ed25519", "Ed448"]) -> Self:
        """Generate a new OKP key pair.

        Args:
            curve: The EdDSA curve to use: "Ed25519" or "Ed448".
        """
        check_cryptography_available()

        if curve == "Ed25519":
            private_key_obj = ed25519.Ed25519PrivateKey.generate()
        elif curve == "Ed448":
            private_key_obj = ed448.Ed448PrivateKey.generate()
        else:
            raise SuperJWTError(
                f"Unsupported OKP algorithm: {curve}. "
                "Supported algorithms: Ed25519, Ed448"
            )

        private_key_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cls.import_key(private_key=private_key_pem)

    @property
    def private_key_types(self) -> tuple[type, ...]:
        return (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)

    @property
    def public_key_types(self) -> tuple[type, ...]:
        return (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)

    def check_key_security(
        self,
        key: ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey,
    ) -> None: ...

    def public_keys_match(
        self,
        key1: ed25519.Ed25519PublicKey | ed448.Ed448PublicKey,
        key2: ed25519.Ed25519PublicKey | ed448.Ed448PublicKey,
    ) -> bool:
        """Compare two OKP public keys for equality."""
        # For EdDSA keys, compare the raw bytes representation
        key1_bytes = key1.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        key2_bytes = key2.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        return key1_bytes == key2_bytes
