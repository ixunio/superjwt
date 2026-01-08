"""Tests for superjwt.keys module."""

import pytest
from superjwt.exceptions import InvalidKeyError, KeyLengthSecurityWarning
from superjwt.keys import NoneKey, OctKey
from superjwt.utils import check_cryptography_available

from .conftest import CRYPTOGRAPHY_AVAILABLE, requires_cryptography


if CRYPTOGRAPHY_AVAILABLE:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from superjwt.keys import RSAKey


class TestNoneKey:
    """Test NoneKey class."""

    def test_none_key_creation(self):
        """Test creating a NoneKey."""
        key = NoneKey()
        assert key.private_key == b""
        assert key.public_key == b""

    def test_none_key_import(self):
        """Test importing a NoneKey."""
        key = NoneKey.import_key(b"anything")
        assert isinstance(key, NoneKey)
        assert key.private_key == b""
        assert key.public_key == b""

    def test_none_key_prepare_does_nothing(self):
        """Test that prepare_key does nothing for NoneKey."""
        key = NoneKey()
        key.prepare_key(b"some data")
        assert key.private_key == b""
        assert key.public_key == b""

    def test_none_key_import_signing_key(self):
        """Test importing NoneKey via import_signing_key."""
        key = NoneKey.import_signing_key(b"any data")
        assert isinstance(key, NoneKey)
        assert key.private_key == b""
        assert key.public_key == b""

    def test_none_key_import_verifying_key(self):
        """Test importing NoneKey via import_verifying_key."""
        key = NoneKey.import_verifying_key(b"any data")
        assert isinstance(key, NoneKey)
        assert key.private_key == b""
        assert key.public_key == b""


class TestOctKey:
    """Test OctKey (symmetric key) class."""

    def test_oct_key_import_bytes(self):
        """Test importing OctKey with bytes."""
        secret = b"my-secret-key-at-least-32-bytes-long"
        key = OctKey.import_key(secret)
        assert isinstance(key, OctKey)
        assert key.private_key == secret
        assert key.public_key == b""

    def test_oct_key_import_string(self):
        """Test importing OctKey with string."""
        secret = "my-secret-key-at-least-32-bytes-long"
        key = OctKey.import_key(secret)
        assert isinstance(key, OctKey)
        assert key.private_key == secret.encode()
        assert key.public_key == b""

    def test_oct_key_short_key_warning(self):
        """Test that short keys trigger a security warning."""
        with pytest.warns(
            KeyLengthSecurityWarning, match="Key size should be >= 112 bits"
        ):
            OctKey.import_key(b"short")

    def test_oct_key_empty_string_raises_error(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="Secret key must not be empty"):
            OctKey.import_key("")

    def test_oct_key_empty_bytes_raises_error(self):
        """Test that empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="Secret key must not be empty"):
            OctKey.import_key(b"")

    def test_oct_key_none_raises_error(self):
        """Test that None raises ValueError."""
        with pytest.raises(ValueError, match="Secret key must not be empty"):
            OctKey.import_key(None)  # type: ignore

    def test_oct_key_rejects_pem_format(self):
        """Test that PEM formatted keys are rejected."""
        pem_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4Z9v...
-----END RSA PRIVATE KEY-----"""
        with pytest.raises(
            InvalidKeyError,
            match=r"asymmetric key or x509 certificate.*should not be used as an HMAC secret",
        ):
            OctKey.import_key(pem_key)

    def test_oct_key_rejects_ssh_key(self):
        """Test that SSH keys are rejected."""
        ssh_key = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
        with pytest.raises(
            InvalidKeyError,
            match=r"asymmetric key or x509 certificate.*should not be used as an HMAC secret",
        ):
            OctKey.import_key(ssh_key)

    def test_oct_key_name_attribute(self):
        """Test that OctKey has correct name attribute."""
        assert OctKey.name == "oct"

    def test_oct_key_sufficient_length(self):
        """Test that sufficiently long keys don't trigger warnings."""
        import warnings

        # 14 bytes = 112 bits (minimum)
        secret = b"a" * 14
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")
            OctKey.import_key(secret)
        # Filter out any warnings that are KeyLengthSecurityWarning
        key_warnings = [
            w for w in warning_list if issubclass(w.category, KeyLengthSecurityWarning)
        ]
        assert len(key_warnings) == 0

    def test_oct_key_import_signing_key(self):
        """Test importing OctKey via import_signing_key."""
        secret = b"my-secret-key-at-least-32-bytes-long"
        key = OctKey.import_signing_key(secret)
        assert isinstance(key, OctKey)
        assert key.private_key == secret

    def test_oct_key_import_verifying_key(self):
        """Test importing OctKey via import_verifying_key."""
        secret = b"my-secret-key-at-least-32-bytes-long"
        key = OctKey.import_verifying_key(secret)
        assert isinstance(key, OctKey)
        assert key.private_key == secret

    def test_oct_key_empty_public_key_raises_error(self):
        """Test that empty public_key parameter raises ValueError."""
        with pytest.raises(ValueError, match="Secret key must not be empty"):
            OctKey.import_key(None, b"")


@requires_cryptography
class TestRSAKey:
    """Test RSAKey (asymmetric key) class."""

    @pytest.fixture
    def rsa_private_key_pkcs1(self):
        """Generate a test RSA private key in PKCS#1 format."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @pytest.fixture
    def rsa_private_key_pkcs8(self):
        """Generate a test RSA private key in PKCS#8 format."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @pytest.fixture
    def rsa_public_key_pkcs1(self, rsa_private_key_pkcs1):
        """Extract public key from private key in PKCS#1 format."""
        private_key = serialization.load_pem_private_key(
            rsa_private_key_pkcs1, password=None, backend=default_backend()
        )
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )

    @pytest.fixture
    def rsa_public_key_spki(self, rsa_private_key_pkcs1):
        """Extract public key from private key in SubjectPublicKeyInfo format."""
        private_key = serialization.load_pem_private_key(
            rsa_private_key_pkcs1, password=None, backend=default_backend()
        )
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def test_rsa_key_name_attribute(self):
        """Test that RSAKey has correct name attribute."""
        assert RSAKey.name == "RSA"

    def test_rsa_key_import_private_key_pkcs1(self, rsa_private_key_pkcs1):
        """Test importing RSA private key in PKCS#1 format."""
        key = RSAKey.import_key(rsa_private_key_pkcs1)
        assert isinstance(key, RSAKey)
        assert key.private_key == rsa_private_key_pkcs1
        assert key.public_key != b""
        assert b"BEGIN PUBLIC KEY" in key.public_key
        assert key._private_key_obj is not None
        assert key._public_key_obj is not None

    def test_rsa_key_import_private_key_pkcs8(self, rsa_private_key_pkcs8):
        """Test importing RSA private key in PKCS#8 format."""
        key = RSAKey.import_key(rsa_private_key_pkcs8)
        assert isinstance(key, RSAKey)
        assert key.private_key == rsa_private_key_pkcs8
        assert key.public_key != b""
        assert key._private_key_obj is not None
        assert key._public_key_obj is not None

    def test_rsa_key_import_public_key_pkcs1(self, rsa_public_key_pkcs1):
        """Test importing RSA public key in PKCS#1 format."""
        key = RSAKey.import_key(public_key=rsa_public_key_pkcs1)
        assert isinstance(key, RSAKey)
        assert key.private_key == b""
        assert key.public_key == rsa_public_key_pkcs1
        assert key._private_key_obj is None
        assert key._public_key_obj is not None

    def test_rsa_key_import_public_key_spki(self, rsa_public_key_spki):
        """Test importing RSA public key in SubjectPublicKeyInfo format."""
        key = RSAKey.import_key(public_key=rsa_public_key_spki)
        assert isinstance(key, RSAKey)
        assert key.private_key == b""
        assert key.public_key == rsa_public_key_spki
        assert key._private_key_obj is None
        assert key._public_key_obj is not None

    def test_rsa_key_get_private_key(self, rsa_private_key_pkcs1):
        """Test getting the private key object for signing."""
        key = RSAKey.import_key(rsa_private_key_pkcs1)
        private_key_obj = key.get_private_key()
        assert isinstance(private_key_obj, rsa.RSAPrivateKey)

    def test_rsa_key_get_public_key(self, rsa_private_key_pkcs1):
        """Test getting the public key object for verification."""
        key = RSAKey.import_key(rsa_private_key_pkcs1)
        public_key_obj = key.get_public_key()
        assert isinstance(public_key_obj, rsa.RSAPublicKey)

    def test_rsa_key_get_private_key_from_public_only_raises_error(
        self, rsa_public_key_spki
    ):
        """Test that getting private key from public-only key raises error."""
        from superjwt.keys import RSAKey

        key = RSAKey.import_key(public_key=rsa_public_key_spki)
        with pytest.raises(
            InvalidKeyError, match="does not have a private component for signing"
        ):
            key.get_private_key()

    def test_rsa_key_get_public_key_without_keys_raises_error(self):
        """Test that calling get_public_key() on an uninitialized key raises error."""
        key = RSAKey()
        with pytest.raises(
            InvalidKeyError, match="does not have a public component for verification"
        ):
            key.get_public_key()

    def test_rsa_key_invalid_pem_format_raises_error(self):
        """Test that invalid PEM format raises error for private key."""
        with pytest.raises(
            InvalidKeyError, match=r"RSA private key must be in PEM format"
        ):
            RSAKey.import_key(b"not a pem key")

    def test_rsa_key_invalid_pem_format_public_key_raises_error(self):
        """Test that invalid PEM format raises error for public key."""
        with pytest.raises(
            InvalidKeyError, match=r"RSA public key must be in PEM format"
        ):
            RSAKey.import_key(public_key=b"not a pem public key")

    def test_rsa_key_invalid_key_data_raises_error(self):
        """Test that invalid key data raises error."""
        invalid_pem = b"""-----BEGIN RSA PRIVATE KEY-----
invalid base64 data!!!
-----END RSA PRIVATE KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse RSA (private )?key"):
            RSAKey.import_key(invalid_pem)

    def test_rsa_key_public_key_extracted_from_private(self, rsa_private_key_pkcs1):
        """Test that public key is correctly extracted from private key."""
        # Import private key
        key = RSAKey.import_key(rsa_private_key_pkcs1)

        # Load the original private key to compare
        original_private = serialization.load_pem_private_key(
            rsa_private_key_pkcs1, password=None, backend=default_backend()
        )
        original_public = original_private.public_key()

        # Verify the public key matches
        key_public = serialization.load_pem_public_key(
            key.public_key, backend=default_backend()
        )

        # Compare public numbers (ensure they're RSA keys)
        assert isinstance(key_public, rsa.RSAPublicKey)
        assert isinstance(original_public, rsa.RSAPublicKey)
        assert key_public.public_numbers() == original_public.public_numbers()

    def test_rsa_key_empty_string_raises_error(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="Secret key must not be empty"):
            RSAKey.import_key("")

    def test_rsa_key_none_raises_error(self):
        """Test that None raises ValueError."""
        with pytest.raises(ValueError, match="Secret key must not be empty"):
            RSAKey.import_key(None)  # type: ignore

    def test_rsa_key_both_keys_valid_match(
        self, rsa_private_key_pkcs1, rsa_public_key_spki
    ):
        """Test that providing both private and public key works when they match."""
        # Import with both keys - should work since public key matches private key
        key = RSAKey.import_key(rsa_private_key_pkcs1, rsa_public_key_spki)
        assert isinstance(key, RSAKey)
        assert key.private_key == rsa_private_key_pkcs1
        assert key.public_key == rsa_public_key_spki
        assert key._private_key_obj is not None
        assert key._public_key_obj is not None

    def test_rsa_key_both_keys_mismatched_raises_error(self, rsa_private_key_pkcs1):
        """Test that providing mismatched private and public keys raises an error."""
        # Generate a different key pair
        different_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        different_public_pem = different_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Try to import with mismatched keys
        with pytest.raises(
            InvalidKeyError,
            match="Provided public key does not match the public key derived from the private key",
        ):
            RSAKey.import_key(rsa_private_key_pkcs1, different_public_pem)

    def test_rsa_key_import_signing_key(self, rsa_private_key_pkcs1):
        """Test importing RSAKey via import_signing_key with private key."""
        key = RSAKey.import_signing_key(rsa_private_key_pkcs1)
        assert isinstance(key, RSAKey)
        assert key.private_key == rsa_private_key_pkcs1
        assert key.public_key != b""
        assert key._private_key_obj is not None
        assert key._public_key_obj is not None

    def test_rsa_key_import_verifying_key(self, rsa_public_key_spki):
        """Test importing RSAKey via import_verifying_key with public key."""
        key = RSAKey.import_verifying_key(rsa_public_key_spki)
        assert isinstance(key, RSAKey)
        assert key.private_key == b""
        assert key.public_key == rsa_public_key_spki
        assert key._private_key_obj is None
        assert key._public_key_obj is not None

    def test_rsa_key_invalid_private_key_data_raises_error(self):
        """Test that corrupted private key data raises InvalidKeyError."""
        invalid_private_key = b"""-----BEGIN RSA PRIVATE KEY-----
CORRUPTED_DATA_HERE_NOT_VALID_BASE64!!!
-----END RSA PRIVATE KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse RSA private key"):
            RSAKey.import_key(invalid_private_key)

    def test_rsa_key_non_rsa_private_key_raises_error(self):
        """Test that providing a non-RSA private key (e.g., EC key) raises InvalidKeyError."""
        # Generate an EC private key instead of RSA
        ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ec_private_key_pem = ec_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(InvalidKeyError, match=r"Key must be an RSA private key"):
            RSAKey.import_key(ec_private_key_pem)

    def test_rsa_key_invalid_public_key_data_raises_error(self):
        """Test that corrupted public key data raises InvalidKeyError."""
        invalid_public_key = b"""-----BEGIN PUBLIC KEY-----
CORRUPTED_DATA_HERE_NOT_VALID_BASE64!!!
-----END PUBLIC KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse RSA public key"):
            RSAKey.import_key(public_key=invalid_public_key)

    def test_rsa_key_non_rsa_public_key_raises_error(self):
        """Test that providing a non-RSA public key (e.g., EC key) raises InvalidKeyError."""
        # Generate an EC public key instead of RSA
        ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ec_public_key = ec_private_key.public_key()
        ec_public_key_pem = ec_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(InvalidKeyError, match=r"Key must be an RSA public key"):
            RSAKey.import_key(public_key=ec_public_key_pem)

    def test_rsa_key_small_key_warning_private(self):
        """Test that small RSA private key triggers security warning."""
        # Generate a small 1024-bit key
        small_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024, backend=default_backend()
        )
        small_private_pem = small_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with pytest.warns(
            KeyLengthSecurityWarning,
            match=r"RSA key size is 1024 bits.*should be >= 2048 bits",
        ):
            RSAKey.import_key(small_private_pem)

    def test_rsa_key_small_key_warning_public(self):
        """Test that small RSA public key triggers security warning."""
        # Generate a small 1024-bit key
        small_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024, backend=default_backend()
        )
        small_public_pem = small_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with pytest.warns(
            KeyLengthSecurityWarning,
            match=r"RSA key size is 1024 bits.*should be >= 2048 bits",
        ):
            RSAKey.import_key(public_key=small_public_pem)

    def test_rsa_key_empty_public_key_raises_error(self):
        """Test that empty public_key parameter raises ValueError."""
        with pytest.raises(ValueError, match="Secret key must not be empty"):
            RSAKey.import_key(None, b"")

    def test_rsa_key_prepare_key_with_no_keys_raises_error(self):
        """Test that calling prepare_key directly with no keys raises InvalidKeyError."""
        key = RSAKey()
        with pytest.raises(
            InvalidKeyError, match=r"No public key or private key available"
        ):
            key.prepare_key(None, None)


@requires_cryptography
class TestCheckCryptographyAvailable:
    """Test the check_cryptography_available function."""

    def test_check_cryptography_available_when_installed(self):
        """Test that check passes when cryptography is installed."""
        # Should not raise an error
        check_cryptography_available()
