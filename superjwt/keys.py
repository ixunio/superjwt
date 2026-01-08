from __future__ import annotations

import warnings
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

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
    from cryptography.hazmat.primitives.asymmetric import rsa


class BaseKey(ABC):
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
        key.prepare_key(private_key, public_key)
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
    def prepare_key(
        self,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
    ) -> None: ...  # pragma: no cover


class NoneKey(BaseKey):
    name = "none"

    @classmethod
    def import_signing_key(cls, _) -> Self:
        return cls()

    @classmethod
    def import_verifying_key(cls, _) -> Self:
        return cls()

    def prepare_key(self, *_) -> None: ...


class SymmetricKey(BaseKey):
    @classmethod
    def import_signing_key(cls, key: str | bytes) -> Self:
        """Import key for signing."""
        return cls.import_key(key, None)

    @classmethod
    def import_verifying_key(cls, key: str | bytes) -> Self:
        """Import key for verification."""
        return cls.import_key(key, None)


class AsymmetricKey(BaseKey):
    @classmethod
    def import_signing_key(cls, key: str | bytes) -> Self:
        """Import private key for signing."""
        return cls.import_key(key, None)

    @classmethod
    def import_verifying_key(cls, key: str | bytes) -> Self:
        """Import public key for verification."""
        return cls.import_key(None, key)


class OctKey(SymmetricKey):
    name = "oct"

    def prepare_key(self, secret_key: bytes, _) -> None:
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


class RSAKey(AsymmetricKey):
    name = "RSA"

    def __init__(self):
        super().__init__()
        self._private_key_obj: rsa.RSAPrivateKey | None = None
        self._public_key_obj: rsa.RSAPublicKey | None = None

    def prepare_key(
        self, private_key: bytes | None = None, public_key: bytes | None = None
    ) -> None:
        """
        Prepare RSA key from PEM-encoded data.
        Can accept either a private key or a public key, or both.
        Private keys contain both private and public components.
        If only private_key is provided, the public key will be extracted from it.
        If only public_key is provided, only verification operations will be available.
        """
        check_cryptography_available()

        # Load private key if provided
        if private_key is not None:
            self.load_private_key(private_key)

        # Load public key (either provided or derived from private key)
        self.load_public_key(public_key)

        # If only public key provided (no private key), clear private key attributes
        if private_key is None and public_key is not None:
            self._private_key_obj = None
            self.private_key = b""

    def load_private_key(self, private_key: bytes) -> None:
        """
        Load an RSA private key from PEM-encoded data.
        Sets self._private_key_obj and self.private_key.
        """
        if not is_pem_format(private_key):
            raise InvalidKeyError(
                "RSA private key must be in PEM format (BEGIN RSA PRIVATE KEY or BEGIN PRIVATE KEY)"
            )

        try:
            loaded_private_key = serialization.load_pem_private_key(
                private_key, password=None, backend=default_backend()
            )

            # Verify it's an RSA key
            if not isinstance(loaded_private_key, rsa.RSAPrivateKey):
                raise InvalidKeyError("Key must be an RSA private key")

            # Check key size for security
            if loaded_private_key.key_size < 2048:
                warnings.warn(
                    f"RSA key size is {loaded_private_key.key_size} bits. "
                    "Key size should be >= 2048 bits for security",
                    KeyLengthSecurityWarning,
                    stacklevel=4,
                )

            self._private_key_obj = loaded_private_key
            self.private_key = private_key

        except (ValueError, TypeError) as e:
            raise InvalidKeyError(f"Unable to parse RSA private key: {e}") from e

    def load_public_key(self, public_key: bytes | None) -> None:
        """
        Load an RSA public key from PEM-encoded data.
        If public_key is None and a private key exists, derives the public key from it.
        Sets self._public_key_obj and self.public_key.
        """
        # If no public key provided, derive from private key if available
        if public_key is None:
            if self._private_key_obj is None:
                raise InvalidKeyError("No public key or private key available")

            # Derive public key from private key
            derived_public_key_obj = self._private_key_obj.public_key()
            derived_public_key_pem = derived_public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self._public_key_obj = derived_public_key_obj
            self.public_key = derived_public_key_pem
            return

        # Load provided public key
        if not is_pem_format(public_key):
            raise InvalidKeyError(
                "RSA public key must be in PEM format (BEGIN RSA PUBLIC KEY or BEGIN PUBLIC KEY)"
            )

        try:
            loaded_public_key = serialization.load_pem_public_key(
                public_key, backend=default_backend()
            )

            # Verify it's an RSA key
            if not isinstance(loaded_public_key, rsa.RSAPublicKey):
                raise InvalidKeyError("Key must be an RSA public key")

            # Check key size for security
            if loaded_public_key.key_size < 2048:
                warnings.warn(
                    f"RSA key size is {loaded_public_key.key_size} bits. "
                    "Key size should be >= 2048 bits for security",
                    KeyLengthSecurityWarning,
                    stacklevel=4,
                )

            # If private key exists, verify public key matches
            if self._private_key_obj is not None:
                derived_public_key_obj = self._private_key_obj.public_key()

                if not self.public_keys_match(loaded_public_key, derived_public_key_obj):
                    raise InvalidKeyError(
                        "Provided public key does not match the public key derived from the private key"
                    )

                # Use the derived public key for consistency
                derived_public_key_pem = derived_public_key_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                self._public_key_obj = derived_public_key_obj
                self.public_key = derived_public_key_pem
            else:
                self._public_key_obj = loaded_public_key
                self.public_key = public_key

        except (ValueError, TypeError) as e:
            raise InvalidKeyError(f"Unable to parse RSA public key: {e}") from e

    def get_private_key(self) -> rsa.RSAPrivateKey:
        """Get the cryptography private key object for signing."""
        if self._private_key_obj is None:
            raise InvalidKeyError(
                "This key does not have a private component for signing"
            )
        return self._private_key_obj

    def get_public_key(self) -> rsa.RSAPublicKey:
        """Get the cryptography public key object for verification."""
        if self._public_key_obj is None:
            raise InvalidKeyError(
                "This key does not have a public component for verification"
            )
        return self._public_key_obj

    def public_keys_match(self, key1: rsa.RSAPublicKey, key2: rsa.RSAPublicKey) -> bool:
        """
        Compare two RSA public keys for equality.

        Returns:
            True if the keys match, False otherwise
        """
        key1_numbers = key1.public_numbers()
        key2_numbers = key2.public_numbers()

        return key1_numbers.n == key2_numbers.n and key1_numbers.e == key2_numbers.e
