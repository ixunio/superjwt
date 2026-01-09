from __future__ import annotations

import warnings
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar, Generic, TypeVar, cast

from superjwt.exceptions import InvalidKeyError, KeyLengthSecurityWarning
from superjwt.utils import (
    as_bytes,
    check_cryptography_available,
    is_pem_format,
    is_ssh_key,
)


if TYPE_CHECKING:
    from typing_extensions import Self


if check_cryptography_available(raise_error=False):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa


class BaseKey(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    algorithms: ClassVar[tuple[str, ...]]

    def __init__(self):
        self.private_key = b""
        self.public_key = b""

    @classmethod
    def import_key(
        cls, private_key: str | bytes | None = None, public_key: str | bytes | None = None
    ) -> Self:
        if cls is NoneKey:
            return cls()

        if private_key is None and public_key is None:
            raise ValueError("Secret key must not be empty")

        if private_key is not None:
            private_key = as_bytes(private_key)
            if len(private_key) == 0:
                raise ValueError("Secret key must not be empty")
        if public_key is not None:
            public_key = as_bytes(public_key)
            if len(public_key) == 0:
                raise ValueError("Secret key must not be empty")

        key = cls()
        key._prepare_key(private_key, public_key)
        return key

    @classmethod
    @abstractmethod
    def import_signing_key(cls, key: str | bytes) -> Self:
        """Import a key for signing/encoding operations.

        For symmetric keys: imports the secret key.
        For asymmetric keys: imports the private key.
        """
        raise NotImplementedError(
            f"{cls.__name__} must implement import_signing_key()"
        )  # pragma: no cover

    @classmethod
    @abstractmethod
    def import_verifying_key(cls, key: str | bytes) -> Self:
        """Import a key for verification/decoding operations.

        For symmetric keys: imports the secret key (same as signing key).
        For asymmetric keys: imports the public key.
        """
        raise NotImplementedError(
            f"{cls.__name__} must implement import_verifying_key()"
        )  # pragma: no cover

    @abstractmethod
    def _prepare_key(
        self,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
    ) -> None: ...  # pragma: no cover


class NoneKey(BaseKey):
    name = "NoneKey"
    description = "No key (used for 'none' algorithm)"
    algorithms = ("none",)

    @classmethod
    def import_signing_key(cls, _) -> Self:
        return cls()

    @classmethod
    def import_verifying_key(cls, _) -> Self:
        return cls()

    def _prepare_key(self, *_) -> None: ...


class SymmetricKey(BaseKey):
    @classmethod
    def import_signing_key(cls, key: str | bytes) -> Self:
        """Import key for signing."""
        return cls.import_key(key, None)

    @classmethod
    def import_verifying_key(cls, key: str | bytes) -> Self:
        """Import key for verification."""
        return cls.import_key(key, None)

    def _prepare_key(self, secret_key: bytes, _) -> None:
        if _ is not None:
            raise InvalidKeyError("Symmetric key should not have a public key component")
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


class AsymmetricKey(BaseKey, Generic[PrivateKeyType, PublicKeyType]):
    """Base class for asymmetric key types (RSA, EC, OKP)."""

    private_key_types: ClassVar[tuple[type, ...]]
    public_key_types: ClassVar[tuple[type, ...]]

    def __init__(self):
        super().__init__()
        self._private_key_obj: PrivateKeyType | None = None
        self._public_key_obj: PublicKeyType | None = None

    @classmethod
    def import_signing_key(cls, key: str | bytes) -> Self:
        """Import private key for signing."""
        return cls.import_key(key, None)

    @classmethod
    def import_verifying_key(cls, key: str | bytes) -> Self:
        """Import public key for verification."""
        return cls.import_key(None, key)

    @abstractmethod
    def check_key_security(self, key: PrivateKeyType | PublicKeyType) -> None:
        """Check key for security issues and emit warnings if needed.

        Args:
            key: The key object to check (private or public)
        """  # pragma: no cover
        ...

    @abstractmethod
    def public_keys_match(self, key1: PublicKeyType, key2: PublicKeyType) -> bool:
        """Compare two public keys for equality.

        Returns:
            True if the keys match, False otherwise
        """  # pragma: no cover
        ...

    def _prepare_key(
        self, private_key: bytes | None = None, public_key: bytes | None = None
    ) -> None:
        """
        Prepare asymmetric key from PEM-encoded data.
        Private keys contain both private and public components.
        If only private_key is provided, the public key will be extracted from it.
        If only public_key is provided, only verification operations will be available.
        """
        check_cryptography_available()

        # Load private key if provided
        if private_key is not None:
            self._load_private_key(private_key)
            assert self._private_key_obj is not None
            self.check_key_security(self._private_key_obj)

        # Load public key (either provided or derived from private key)
        self._load_public_key(public_key)

        # Check security on the loaded public key (if not already checked via private key)
        if private_key is None:
            assert self._public_key_obj is not None
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

            if not self.validate_private_key_type(loaded_key):
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

            if not self.validate_public_key_type(loaded_key):
                raise InvalidKeyError(f"Key must be an {self.name} public key")

            return cast("PublicKeyType", loaded_key)
        except (ValueError, TypeError) as e:
            raise InvalidKeyError(f"Unable to parse {self.name} public key: {e}") from e

    def _derive_public_key_from_private(self) -> tuple[PublicKeyType, bytes]:
        """Derive public key from the loaded private key.

        Returns:
            Tuple of (public_key_obj, public_key_pem)

        Raises:
            InvalidKeyError: If no private key is loaded
        """
        assert self._private_key_obj is not None
        derived_public_key_obj = cast("PublicKeyType", self._private_key_obj.public_key())
        derived_public_key_pem = derived_public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return derived_public_key_obj, derived_public_key_pem

    def _load_private_key(self, private_key: bytes) -> None:
        """Load a private key from PEM-encoded data.

        Sets self._private_key_obj and self.private_key.
        """
        loaded_key = self._load_pem_private_key_common(private_key)
        self._private_key_obj = loaded_key
        self.private_key = private_key

    def _load_public_key(self, public_key: bytes | None) -> None:
        """Load a public key from PEM-encoded data.

        If public_key is None and a private key exists, derives the public key from it.
        Sets self._public_key_obj and self.public_key.
        """
        # If no public key provided, derive from private key
        if public_key is None:
            derived_obj, derived_pem = self._derive_public_key_from_private()
            self._public_key_obj = derived_obj
            self.public_key = derived_pem
            return

        # Load provided public key
        loaded_key = self._load_pem_public_key_common(public_key)

        # If private key exists, verify public key matches
        if self._private_key_obj is not None:
            derived_obj, derived_pem = self._derive_public_key_from_private()

            if not self.public_keys_match(loaded_key, derived_obj):
                raise InvalidKeyError(
                    "Provided public key does not match the public key derived from the private key"
                )

            # Use the derived public key for consistency
            self._public_key_obj = derived_obj
            self.public_key = derived_pem
        else:
            self._public_key_obj = loaded_key
            self.public_key = public_key

    def validate_private_key_type(self, key: object) -> bool:
        """Check if the loaded key is the correct private key type."""
        return isinstance(key, self.private_key_types)

    def validate_public_key_type(self, key: object) -> bool:
        """Check if the loaded key is the correct public key type."""
        return isinstance(key, self.public_key_types)

    def _get_private_key(self) -> PrivateKeyType:
        """Get the cryptography private key object for signing."""
        if self._private_key_obj is None:
            raise InvalidKeyError(
                "This key does not have a private component for signing"
            )
        return self._private_key_obj

    def _get_public_key(self) -> PublicKeyType:
        """Get the cryptography public key object for verification."""
        if self._public_key_obj is None:
            raise InvalidKeyError(
                "This key does not have a public component for verification"
            )
        return self._public_key_obj


class RSAKey(AsymmetricKey[rsa.RSAPrivateKey, rsa.RSAPublicKey]):
    name = "RSA"
    description = "RSA key for RSASSA-PKCS1-v1_5 and RSASSA-PSS algorithms"
    algorithms = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
    private_key_types = (rsa.RSAPrivateKey,)
    public_key_types = (rsa.RSAPublicKey,)

    def check_key_security(self, key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> None:
        if key.key_size < 2048:
            warnings.warn(
                f"RSA key size is {key.key_size} bits. "
                "Key size should be >= 2048 bits for security",
                KeyLengthSecurityWarning,
                stacklevel=5,
            )

    def public_keys_match(self, key1: rsa.RSAPublicKey, key2: rsa.RSAPublicKey) -> bool:
        """Compare two RSA public keys for equality."""
        key1_numbers = key1.public_numbers()
        key2_numbers = key2.public_numbers()

        return key1_numbers.n == key2_numbers.n and key1_numbers.e == key2_numbers.e


class ECKey(AsymmetricKey[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]):
    name = "EC"
    description = (
        "Elliptic Curve key for ECDSA algorithms with curve secp256r1 (P-256), "
        "secp256k1, secp384r1 (P-384), and secp521r1 (P-521)"
    )
    algorithms = ("ES256", "ES256K", "ES384", "ES512")
    private_key_types = (ec.EllipticCurvePrivateKey,)
    public_key_types = (ec.EllipticCurvePublicKey,)

    def check_key_security(
        self, key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey
    ) -> None:
        curve_name = key.curve.name
        if curve_name in ("secp192r1", "secp224r1"):
            warnings.warn(
                f"EC curve {curve_name} has weak security. "
                "Consider using P-256, P-384, or P-521 curves",
                KeyLengthSecurityWarning,
                stacklevel=5,
            )

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
        ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey,
        ed25519.Ed25519PublicKey | ed448.Ed448PublicKey,
    ]
):
    name = "OKP"
    description = "Octet Key Pair for EdDSA algorithms (Ed25519, Ed448)"
    algorithms = ("Ed25519", "Ed448")
    private_key_types = (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)
    public_key_types = (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)

    def check_key_security(
        self,
        key: ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey,
    ) -> None:
        # OKP keys (Ed25519, Ed448) are considered secure by design
        pass

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
