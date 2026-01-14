"""Tests for superjwt.keys module."""

import warnings

import pytest
from superjwt.exceptions import InvalidKeyError, KeyLengthSecurityWarning, SuperJWTError
from superjwt.keys import ECKey, NoneKey, OctKey, OKPKey, RSAKey
from superjwt.utils import CRYPTOGRAPHY_AVAILABLE, check_cryptography_available

from .conftest import requires_cryptography


if CRYPTOGRAPHY_AVAILABLE:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa


@requires_cryptography
class TestCheckCryptographyAvailable:
    """Test the check_cryptography_available function."""

    def test_check_cryptography_available_when_installed(self):
        """Test that check passes when cryptography is installed."""
        # Should not raise an error
        check_cryptography_available()


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
        with pytest.raises(ValueError, match="Private key must not be empty"):
            OctKey.import_key("")

    def test_oct_key_empty_bytes_raises_error(self):
        """Test that empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="Private key must not be empty"):
            OctKey.import_key(b"")

    def test_oct_key_none_raises_error(self):
        """Test that None raises ValueError."""
        with pytest.raises(ValueError, match="No key was provided"):
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
        with pytest.raises(ValueError, match="Public key must not be empty"):
            OctKey.import_key(None, b"")

    def test_oct_key_public_key_not_allowed(self):
        """Test that providing a public_key to a symmetric key raises SuperJWTError."""
        secret = b"my-secret-key-at-least-32-bytes-long"
        with pytest.raises(
            SuperJWTError, match="Symmetric key should not have a public key component"
        ):
            OctKey.import_key(secret, b"some-public-key")

    def test_oct_key_generate_default_size(self):
        """Test OctKey.generate() with default size (32 bytes as hex = 64 chars)."""
        key = OctKey.generate()
        assert isinstance(key, OctKey)
        assert len(key.private_key) == 64  # 32 bytes as hex = 64 characters

    def test_oct_key_generate_default_size_raw_bytes(self):
        """Test OctKey.generate() with default size and raw bytes."""
        key = OctKey.generate(human_readable=False)
        assert isinstance(key, OctKey)
        assert len(key.private_key) == 32  # 32 bytes raw

    def test_oct_key_generate_custom_size(self):
        """Test OctKey.generate() with custom size."""
        key = OctKey.generate(64)
        assert isinstance(key, OctKey)
        assert len(key.private_key) == 128  # 64 bytes as hex = 128 characters

    def test_oct_key_generate_custom_size_raw_bytes(self):
        """Test OctKey.generate() with custom size and raw bytes."""
        key = OctKey.generate(64, human_readable=False)
        assert isinstance(key, OctKey)
        assert len(key.private_key) == 64  # 64 bytes raw

    def test_oct_key_generate_creates_different_keys(self):
        """Test that OctKey.generate() creates different keys each time."""
        key1 = OctKey.generate(32)
        key2 = OctKey.generate(32)
        assert key1.private_key != key2.private_key

    def test_oct_key_generated_key_is_usable(self):
        """Test that generated key can be used for HMAC operations."""
        key = OctKey.generate(32)
        # Test with HMAC algorithm
        import hashlib
        import hmac

        test_data = b"test message"
        signature = hmac.new(key.private_key, test_data, hashlib.sha256).digest()
        # Verify the signature
        expected = hmac.new(key.private_key, test_data, hashlib.sha256).digest()
        assert hmac.compare_digest(signature, expected)


@requires_cryptography
class TestRSAKey:
    """Test RSAKey (asymmetric key) class."""

    @pytest.fixture
    def rsa_private_key_pkcs1(self, rsa_2048_key_pair):
        """Get RSA private key from session fixture in PKCS#1 format."""
        private_key_obj = rsa_2048_key_pair.private_key_obj
        return private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @pytest.fixture
    def rsa_private_key_pkcs8(self, rsa_2048_key_pair):
        """Get RSA private key from session fixture in PKCS#8 format."""
        return rsa_2048_key_pair.private_pem

    @pytest.fixture
    def rsa_public_key_pkcs1(self, rsa_2048_key_pair):
        """Get RSA public key from session fixture in PKCS#1 format."""
        public_key_obj = rsa_2048_key_pair.public_key_obj
        return public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )

    @pytest.fixture
    def rsa_public_key_spki(self, rsa_2048_key_pair):
        """Get RSA public key from session fixture in SubjectPublicKeyInfo format."""
        return rsa_2048_key_pair.public_pem

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
        private_key_obj = key._get_private_key()
        assert isinstance(private_key_obj, rsa.RSAPrivateKey)

    def test_rsa_key_get_public_key(self, rsa_private_key_pkcs1):
        """Test getting the public key object for verification."""
        key = RSAKey.import_key(rsa_private_key_pkcs1)
        public_key_obj = key._get_public_key()
        assert isinstance(public_key_obj, rsa.RSAPublicKey)

    def test_rsa_key_get_private_key_from_public_only_raises_error(
        self, rsa_public_key_spki
    ):
        """Test that getting private key from public-only key raises error."""
        key = RSAKey.import_key(public_key=rsa_public_key_spki)
        with pytest.raises(
            SuperJWTError, match="does not have a private component for signing"
        ):
            key._get_private_key()

    def test_rsa_key_get_public_key_without_keys_raises_error(self):
        """Test that calling get_public_key() on an uninitialized key raises error."""
        key = RSAKey()
        with pytest.raises(
            SuperJWTError, match="does not have a public component for verification"
        ):
            key._get_public_key()

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
        with pytest.raises(ValueError, match="Private key must not be empty"):
            RSAKey.import_key("")

    def test_rsa_key_none_raises_error(self):
        """Test that None raises ValueError."""
        with pytest.raises(ValueError, match="No key was provided"):
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

    def test_rsa_key_both_keys_mismatched_raises_error(
        self, rsa_private_key_pkcs1, rsa_2048_key_pair_alt
    ):
        """Test that providing mismatched private and public keys raises an error."""
        # Use different key pair from alternate session fixture
        different_public_pem = rsa_2048_key_pair_alt.public_pem

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
        assert key.public_key == b""  # No derivation with import_signing_key
        assert key._private_key_obj is not None
        assert key._public_key_obj is None  # Not derived

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

    def test_rsa_key_non_rsa_private_key_raises_error(self, ec_p256_key_pair):
        """Test that providing a non-RSA private key (e.g., EC key) raises InvalidKeyError."""
        # Use EC private key from session fixture
        ec_private_key_pem = ec_p256_key_pair.private_pem
        with pytest.raises(InvalidKeyError, match=r"Key must be an RSA private key"):
            RSAKey.import_key(ec_private_key_pem)

    def test_rsa_key_invalid_public_key_data_raises_error(self):
        """Test that corrupted public key data raises InvalidKeyError."""
        invalid_public_key = b"""-----BEGIN PUBLIC KEY-----
CORRUPTED_DATA_HERE_NOT_VALID_BASE64!!!
-----END PUBLIC KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse RSA public key"):
            RSAKey.import_key(public_key=invalid_public_key)

    def test_rsa_key_non_rsa_public_key_raises_error(self, ec_p256_key_pair):
        """Test that providing a non-RSA public key (e.g., EC key) raises InvalidKeyError."""
        # Use EC public key from session fixture
        ec_public_key_pem = ec_p256_key_pair.public_pem
        with pytest.raises(InvalidKeyError, match=r"Key must be an RSA public key"):
            RSAKey.import_key(public_key=ec_public_key_pem)

    def test_rsa_key_small_key_warning_private(self, rsa_1024_weak_key):
        """Test that small RSA private key triggers security warning."""
        with pytest.warns(
            KeyLengthSecurityWarning,
            match=r"RSA key size is 1024 bits.*should be >= 2048 bits",
        ):
            RSAKey.import_key(rsa_1024_weak_key["private_pem"])

    def test_rsa_key_small_key_warning_public(self, rsa_1024_weak_key):
        """Test that small RSA public key triggers security warning."""
        with pytest.warns(
            KeyLengthSecurityWarning,
            match=r"RSA key size is 1024 bits.*should be >= 2048 bits",
        ):
            RSAKey.import_key(public_key=rsa_1024_weak_key["public_pem"])

    def test_rsa_key_empty_public_key_raises_error(self):
        """Test that empty public_key parameter raises ValueError."""
        with pytest.raises(ValueError, match="Public key must not be empty"):
            RSAKey.import_key(None, b"")

    def test_rsa_key_public_keys_match_returns_true(self, rsa_private_key_pkcs1):
        """Test that public_keys_match returns True when keys match."""
        # Load the private key to extract its public key
        private_key_obj = serialization.load_pem_private_key(
            rsa_private_key_pkcs1, password=None, backend=default_backend()
        )
        public_key_obj = private_key_obj.public_key()

        # Create RSAKey instance and test
        key = RSAKey()
        assert isinstance(public_key_obj, rsa.RSAPublicKey)
        assert key.public_keys_match(public_key_obj, public_key_obj) is True

    def test_rsa_key_public_keys_match_returns_false(
        self, rsa_2048_key_pair, rsa_2048_key_pair_alt
    ):
        """Test that public_keys_match returns False when keys don't match."""
        # Use two different key pairs from session fixtures
        public_key_obj1 = rsa_2048_key_pair.public_key_obj
        public_key_obj2 = rsa_2048_key_pair_alt.public_key_obj

        # Test with mismatched keys
        key = RSAKey()
        assert isinstance(public_key_obj1, rsa.RSAPublicKey)
        assert isinstance(public_key_obj2, rsa.RSAPublicKey)
        assert key.public_keys_match(public_key_obj1, public_key_obj2) is False

    def test_rsa_key_export_private_key_pem(self, rsa_2048_key_pair):
        """Test exporting private key as PEM."""
        key = rsa_2048_key_pair.key_instance_from_private_pem
        pem = key.export_private_key_pem()

        assert isinstance(pem, bytes)
        assert b"BEGIN PRIVATE KEY" in pem

    def test_rsa_key_export_public_key_pem(self, rsa_2048_key_pair):
        """Test exporting public key as PEM."""
        key = RSAKey.import_key(rsa_2048_key_pair.private_pem)
        pem = key.export_public_key_pem()

        assert isinstance(pem, bytes)
        assert b"BEGIN PUBLIC KEY" in pem


@requires_cryptography
class TestECKey:
    """Test ECKey (Elliptic Curve key) class."""

    @pytest.fixture
    def ec_private_key_p256(self, ec_p256_key_pair):
        """Get EC private key from session fixture with P-256 curve."""
        return ec_p256_key_pair.private_pem

    @pytest.fixture
    def ec_private_key_p384(self, ec_p384_key_pair):
        """Get EC private key from session fixture with P-384 curve."""
        return ec_p384_key_pair.private_pem

    @pytest.fixture
    def ec_private_key_p521(self, ec_p521_key_pair):
        """Get EC private key from session fixture with P-521 curve."""
        return ec_p521_key_pair.private_pem

    @pytest.fixture
    def ec_public_key_p256(self, ec_p256_key_pair):
        """Get EC public key from session fixture with P-256."""
        return ec_p256_key_pair.public_pem

    def test_ec_key_import_private_key_p256(self, ec_private_key_p256):
        """Test importing EC private key with P-256 curve."""
        key = ECKey.import_key(ec_private_key_p256)
        assert isinstance(key, ECKey)
        assert key.private_key == ec_private_key_p256
        assert key.public_key != b""
        assert b"BEGIN PUBLIC KEY" in key.public_key
        assert key._private_key_obj is not None
        assert key._public_key_obj is not None

    def test_ec_key_import_private_key_p384(self, ec_private_key_p384):
        """Test importing EC private key with P-384 curve."""
        key = ECKey.import_key(ec_private_key_p384)
        assert isinstance(key, ECKey)
        assert key.private_key == ec_private_key_p384
        assert key.public_key != b""
        assert key._private_key_obj is not None

    def test_ec_key_import_private_key_p521(self, ec_private_key_p521):
        """Test importing EC private key with P-521 curve."""
        key = ECKey.import_key(ec_private_key_p521)
        assert isinstance(key, ECKey)
        assert key.private_key == ec_private_key_p521
        assert key.public_key != b""
        assert key._private_key_obj is not None

    def test_ec_key_import_public_key(self, ec_public_key_p256):
        """Test importing EC public key."""
        key = ECKey.import_key(public_key=ec_public_key_p256)
        assert isinstance(key, ECKey)
        assert key.private_key == b""
        assert key.public_key == ec_public_key_p256
        assert key._private_key_obj is None
        assert key._public_key_obj is not None

    def test_ec_key_get_private_key(self, ec_private_key_p256):
        """Test getting the private key object for signing."""
        key = ECKey.import_key(ec_private_key_p256)
        private_key_obj = key._get_private_key()
        assert isinstance(private_key_obj, ec.EllipticCurvePrivateKey)

    def test_ec_key_get_public_key(self, ec_private_key_p256):
        """Test getting the public key object for verification."""
        key = ECKey.import_key(ec_private_key_p256)
        public_key_obj = key._get_public_key()
        assert isinstance(public_key_obj, ec.EllipticCurvePublicKey)

    def test_ec_key_get_private_key_from_public_only_raises_error(
        self, ec_public_key_p256
    ):
        """Test that getting private key from public-only key raises error."""
        key = ECKey.import_key(public_key=ec_public_key_p256)
        with pytest.raises(
            SuperJWTError, match="does not have a private component for signing"
        ):
            key._get_private_key()

    def test_ec_key_get_public_key_without_keys_raises_error(self):
        """Test that calling get_public_key() on an uninitialized key raises error."""
        key = ECKey()
        with pytest.raises(
            SuperJWTError, match="does not have a public component for verification"
        ):
            key._get_public_key()

    def test_ec_key_invalid_pem_format_raises_error(self):
        """Test that invalid PEM format raises error for private key."""
        with pytest.raises(
            InvalidKeyError, match=r"EC private key must be in PEM format"
        ):
            ECKey.import_key(b"not a pem key")

    def test_ec_key_invalid_pem_format_public_key_raises_error(self):
        """Test that invalid PEM format raises error for public key."""
        with pytest.raises(InvalidKeyError, match=r"EC public key must be in PEM format"):
            ECKey.import_key(public_key=b"not a pem public key")

    def test_ec_key_invalid_key_data_raises_error(self):
        """Test that invalid key data raises error."""
        invalid_pem = b"""-----BEGIN PRIVATE KEY-----
invalid base64 data!!!
-----END PRIVATE KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse EC (private )?key"):
            ECKey.import_key(invalid_pem)

    def test_ec_key_public_key_extracted_from_private(self, ec_private_key_p256):
        """Test that public key is correctly extracted from private key."""
        # Import private key
        key = ECKey.import_key(ec_private_key_p256)

        # Load the original private key to compare
        original_private = serialization.load_pem_private_key(
            ec_private_key_p256, password=None, backend=default_backend()
        )
        original_public = original_private.public_key()

        # Verify the public key matches
        key_public = serialization.load_pem_public_key(
            key.public_key, backend=default_backend()
        )

        # Compare public numbers (ensure they're EC keys)
        assert isinstance(key_public, ec.EllipticCurvePublicKey)
        assert isinstance(original_public, ec.EllipticCurvePublicKey)
        assert key_public.public_numbers() == original_public.public_numbers()

    def test_ec_key_empty_string_raises_error(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="Private key must not be empty"):
            ECKey.import_key("")

    def test_ec_key_none_raises_error(self):
        """Test that None raises ValueError."""
        with pytest.raises(ValueError, match="No key was provided"):
            ECKey.import_key(None)  # type: ignore

    def test_ec_key_both_keys_valid_match(self, ec_private_key_p256, ec_public_key_p256):
        """Test that providing both private and public key works when they match."""
        # Import with both keys - should work since public key matches private key
        key = ECKey.import_key(ec_private_key_p256, ec_public_key_p256)
        assert isinstance(key, ECKey)
        assert key.private_key == ec_private_key_p256
        assert key.public_key == ec_public_key_p256
        assert key._private_key_obj is not None
        assert key._public_key_obj is not None

    def test_ec_key_both_keys_mismatched_raises_error(
        self, ec_private_key_p256, ec_p256_key_pair_alt
    ):
        """Test that providing mismatched private and public keys raises an error."""
        # Use different key pair from alternate session fixture
        different_public_pem = ec_p256_key_pair_alt.public_pem

        # Try to import with mismatched keys
        with pytest.raises(
            InvalidKeyError,
            match="Provided public key does not match the public key derived from the private key",
        ):
            ECKey.import_key(ec_private_key_p256, different_public_pem)

    def test_ec_key_import_signing_key(self, ec_private_key_p256):
        """Test importing ECKey via import_signing_key with private key."""
        key = ECKey.import_signing_key(ec_private_key_p256)
        assert isinstance(key, ECKey)
        assert key.private_key == ec_private_key_p256
        assert key.public_key == b""  # No derivation with import_signing_key
        assert key._private_key_obj is not None
        assert key._public_key_obj is None  # Not derived

    def test_ec_key_import_verifying_key(self, ec_public_key_p256):
        """Test importing ECKey via import_verifying_key with public key."""
        key = ECKey.import_verifying_key(ec_public_key_p256)
        assert isinstance(key, ECKey)
        assert key.private_key == b""
        assert key.public_key == ec_public_key_p256
        assert key._private_key_obj is None
        assert key._public_key_obj is not None

    def test_ec_key_invalid_private_key_data_raises_error(self):
        """Test that corrupted private key data raises InvalidKeyError."""
        invalid_private_key = b"""-----BEGIN PRIVATE KEY-----
CORRUPTED_DATA_HERE_NOT_VALID_BASE64!!!
-----END PRIVATE KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse EC private key"):
            ECKey.import_key(invalid_private_key)

    def test_ec_key_non_ec_private_key_raises_error(self, rsa_2048_key_pair):
        """Test that providing a non-EC private key (e.g., RSA key) raises InvalidKeyError."""
        # Use RSA private key from session fixture
        rsa_private_key_pem = rsa_2048_key_pair.private_pem
        with pytest.raises(InvalidKeyError, match=r"Key must be an EC private key"):
            ECKey.import_key(rsa_private_key_pem)

    def test_ec_key_invalid_public_key_data_raises_error(self):
        """Test that corrupted public key data raises InvalidKeyError."""
        invalid_public_key = b"""-----BEGIN PUBLIC KEY-----
CORRUPTED_DATA_HERE_NOT_VALID_BASE64!!!
-----END PUBLIC KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse EC public key"):
            ECKey.import_key(public_key=invalid_public_key)

    def test_ec_key_non_ec_public_key_raises_error(self, rsa_2048_key_pair):
        """Test that providing a non-EC public key (e.g., RSA key) raises InvalidKeyError."""
        # Use RSA public key from session fixture
        rsa_public_key_pem = rsa_2048_key_pair.public_pem
        with pytest.raises(InvalidKeyError, match=r"Key must be an EC public key"):
            ECKey.import_key(public_key=rsa_public_key_pem)

    def test_ec_key_empty_public_key_raises_error(self):
        """Test that empty public_key parameter raises ValueError."""
        with pytest.raises(ValueError, match="Public key must not be empty"):
            ECKey.import_key(None, b"")

    def test_ec_key_public_keys_match_returns_true(self, ec_private_key_p256):
        """Test that public_keys_match returns True when keys match."""
        # Load the private key to extract its public key
        private_key_obj = serialization.load_pem_private_key(
            ec_private_key_p256, password=None, backend=default_backend()
        )
        public_key_obj = private_key_obj.public_key()

        # Create ECKey instance and test
        key = ECKey()
        assert isinstance(public_key_obj, ec.EllipticCurvePublicKey)
        assert key.public_keys_match(public_key_obj, public_key_obj) is True

    def test_ec_key_public_keys_match_returns_false(
        self, ec_p256_key_pair, ec_p256_key_pair_alt
    ):
        """Test that public_keys_match returns False when keys don't match."""
        # Use two different key pairs from session fixtures
        public_key_obj1 = ec_p256_key_pair.public_key_obj
        public_key_obj2 = ec_p256_key_pair_alt.public_key_obj

        # Test with mismatched keys
        key = ECKey()
        assert isinstance(public_key_obj1, ec.EllipticCurvePublicKey)
        assert isinstance(public_key_obj2, ec.EllipticCurvePublicKey)
        assert key.public_keys_match(public_key_obj1, public_key_obj2) is False

    def test_ec_key_generate_with_invalid_curve_string(self):
        """Test that ECKey.generate() raises error for invalid curve string."""
        with pytest.raises(SuperJWTError, match="Unsupported curve"):
            ECKey.generate("INVALID-CURVE")  # type: ignore

    def test_ec_key_generate_with_invalid_type(self):
        """Test that ECKey.generate() raises error for invalid curve type."""
        with pytest.raises(SuperJWTError, match="curve must be an instance"):
            ECKey.generate(123)  # type: ignore

    def test_ec_key_export_private_key_pem(self, ec_p256_key_pair):
        """Test exporting private key as PEM."""
        key = ec_p256_key_pair.key_instance_from_private_pem
        pem = key.export_private_key_pem()

        assert isinstance(pem, bytes)
        assert b"BEGIN PRIVATE KEY" in pem

    def test_ec_key_export_public_key_pem(self, ec_p256_key_pair):
        """Test exporting public key as PEM."""
        key = ECKey.import_key(ec_p256_key_pair.private_pem)
        pem = key.export_public_key_pem()

        assert isinstance(pem, bytes)
        assert b"BEGIN PUBLIC KEY" in pem

    def test_ec_key_curve_name_from_public_only(self, ec_public_key_p256):
        """Test getting curve name from public-only key."""
        key = ECKey.import_key(public_key=ec_public_key_p256)
        assert key.curve_name == "secp256r1"

    def test_ec_key_curve_key_size_from_public_only(self, ec_public_key_p256):
        """Test getting curve key size from public-only key."""
        key = ECKey.import_key(public_key=ec_public_key_p256)
        assert key.curve_key_size == 256

    def test_ec_key_curve_name_from_private_key(self, ec_private_key_p256):
        """Test getting curve name from private key."""
        key = ECKey.import_key(ec_private_key_p256)
        assert key.curve_name == "secp256r1"

    def test_ec_key_curve_key_size_from_private_key(self, ec_private_key_p256):
        """Test getting curve key size from private key."""
        key = ECKey.import_key(ec_private_key_p256)
        assert key.curve_key_size == 256

    def test_ec_key_derive_public_key_without_private_raises_error(self):
        """Test that deriving public key without private key raises error."""
        key = ECKey()
        with pytest.raises(
            SuperJWTError, match="Cannot derive public key without a private key"
        ):
            key._derive_public_key_from_private()


@requires_cryptography
class TestOKPKey:
    """Test OKPKey (Octet Key Pair for EdDSA) class."""

    @pytest.fixture
    def okp_private_key_ed25519(self, ed25519_key_pair):
        """Get Ed25519 private key from session fixture."""
        return ed25519_key_pair.private_pem

    @pytest.fixture
    def okp_private_key_ed448(self, ed448_key_pair):
        """Get Ed448 private key from session fixture."""
        return ed448_key_pair.private_pem

    @pytest.fixture
    def okp_public_key_ed25519(self, ed25519_key_pair):
        """Get Ed25519 public key from session fixture."""
        return ed25519_key_pair.public_pem

    def test_okp_key_import_private_key_ed25519(self, okp_private_key_ed25519):
        """Test importing Ed25519 private key."""
        key = OKPKey.import_key(okp_private_key_ed25519)
        assert isinstance(key, OKPKey)
        assert key.private_key == okp_private_key_ed25519
        assert key.public_key != b""
        assert b"BEGIN PUBLIC KEY" in key.public_key
        assert key._private_key_obj is not None
        assert key._public_key_obj is not None

    def test_okp_key_import_private_key_ed448(self, okp_private_key_ed448):
        """Test importing Ed448 private key."""
        key = OKPKey.import_key(okp_private_key_ed448)
        assert isinstance(key, OKPKey)
        assert key.private_key == okp_private_key_ed448
        assert key.public_key != b""
        assert key._private_key_obj is not None
        assert isinstance(key._private_key_obj, ed448.Ed448PrivateKey)

    def test_okp_key_import_public_key(self, okp_public_key_ed25519):
        """Test importing Ed25519 public key."""
        key = OKPKey.import_key(public_key=okp_public_key_ed25519)
        assert isinstance(key, OKPKey)
        assert key.private_key == b""
        assert key.public_key == okp_public_key_ed25519
        assert key._private_key_obj is None
        assert key._public_key_obj is not None

    def test_okp_key_get_private_key(self, okp_private_key_ed25519):
        """Test getting the private key object for signing."""
        key = OKPKey.import_key(okp_private_key_ed25519)
        private_key_obj = key._get_private_key()
        assert isinstance(private_key_obj, ed25519.Ed25519PrivateKey)

    def test_okp_key_get_public_key(self, okp_private_key_ed25519):
        """Test getting the public key object for verification."""
        key = OKPKey.import_key(okp_private_key_ed25519)
        public_key_obj = key._get_public_key()
        assert isinstance(public_key_obj, ed25519.Ed25519PublicKey)

    def test_okp_key_get_private_key_from_public_only_raises_error(
        self, okp_public_key_ed25519
    ):
        """Test that getting private key from public-only key raises error."""
        key = OKPKey.import_key(public_key=okp_public_key_ed25519)
        with pytest.raises(
            SuperJWTError, match="does not have a private component for signing"
        ):
            key._get_private_key()

    def test_okp_key_get_public_key_without_keys_raises_error(self):
        """Test that calling get_public_key() on an uninitialized key raises error."""
        key = OKPKey()
        with pytest.raises(
            SuperJWTError, match="does not have a public component for verification"
        ):
            key._get_public_key()

    def test_okp_key_invalid_pem_format_raises_error(self):
        """Test that invalid PEM format raises error for private key."""
        with pytest.raises(
            InvalidKeyError, match=r"OKP private key must be in PEM format"
        ):
            OKPKey.import_key(b"not a pem key")

    def test_okp_key_invalid_pem_format_public_key_raises_error(self):
        """Test that invalid PEM format raises error for public key."""
        with pytest.raises(
            InvalidKeyError, match=r"OKP public key must be in PEM format"
        ):
            OKPKey.import_key(public_key=b"not a pem public key")

    def test_okp_key_invalid_key_data_raises_error(self):
        """Test that invalid key data raises error."""
        invalid_pem = b"""-----BEGIN PRIVATE KEY-----
invalid base64 data!!!
-----END PRIVATE KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse OKP (private )?key"):
            OKPKey.import_key(invalid_pem)

    def test_okp_key_public_key_extracted_from_private(self, okp_private_key_ed25519):
        """Test that public key is correctly extracted from private key."""
        # Import private key
        key = OKPKey.import_key(okp_private_key_ed25519)

        # Load the original private key to compare
        original_private = serialization.load_pem_private_key(
            okp_private_key_ed25519, password=None, backend=default_backend()
        )
        original_public = original_private.public_key()

        # Verify the public key matches
        key_public = serialization.load_pem_public_key(
            key.public_key, backend=default_backend()
        )

        # Compare raw bytes (ensure they're EdDSA keys)
        assert isinstance(key_public, ed25519.Ed25519PublicKey)
        assert isinstance(original_public, ed25519.Ed25519PublicKey)
        assert key_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ) == original_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def test_okp_key_empty_string_raises_error(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="Private key must not be empty"):
            OKPKey.import_key("")

    def test_okp_key_none_raises_error(self):
        """Test that None raises ValueError."""
        with pytest.raises(ValueError, match="No key was provided"):
            OKPKey.import_key(None)  # type: ignore

    def test_okp_key_both_keys_valid_match(
        self, okp_private_key_ed25519, okp_public_key_ed25519
    ):
        """Test that providing both private and public key works when they match."""
        # Import with both keys - should work since public key matches private key
        key = OKPKey.import_key(okp_private_key_ed25519, okp_public_key_ed25519)
        assert isinstance(key, OKPKey)
        assert key.private_key == okp_private_key_ed25519
        assert key.public_key == okp_public_key_ed25519
        assert key._private_key_obj is not None
        assert key._public_key_obj is not None

    def test_okp_key_both_keys_mismatched_raises_error(
        self, okp_private_key_ed25519, ed25519_key_pair_alt
    ):
        """Test that providing mismatched private and public keys raises an error."""
        # Use different key pair from alternate session fixture
        different_public_pem = ed25519_key_pair_alt.public_pem

        # Try to import with mismatched keys
        with pytest.raises(
            InvalidKeyError,
            match="Provided public key does not match the public key derived from the private key",
        ):
            OKPKey.import_key(okp_private_key_ed25519, different_public_pem)

    def test_okp_key_import_signing_key(self, okp_private_key_ed25519):
        """Test importing OKPKey via import_signing_key with private key."""
        key = OKPKey.import_signing_key(okp_private_key_ed25519)
        assert isinstance(key, OKPKey)
        assert key.private_key == okp_private_key_ed25519
        assert key.public_key == b""  # No derivation with import_signing_key
        assert key._private_key_obj is not None
        assert key._public_key_obj is None  # Not derived

    def test_okp_key_import_verifying_key(self, okp_public_key_ed25519):
        """Test importing OKPKey via import_verifying_key with public key."""
        key = OKPKey.import_verifying_key(okp_public_key_ed25519)
        assert isinstance(key, OKPKey)
        assert key.private_key == b""
        assert key.public_key == okp_public_key_ed25519
        assert key._private_key_obj is None
        assert key._public_key_obj is not None

    def test_okp_key_invalid_private_key_data_raises_error(self):
        """Test that corrupted private key data raises InvalidKeyError."""
        invalid_private_key = b"""-----BEGIN PRIVATE KEY-----
CORRUPTED_DATA_HERE_NOT_VALID_BASE64!!!
-----END PRIVATE KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse OKP private key"):
            OKPKey.import_key(invalid_private_key)

    def test_okp_key_non_okp_private_key_raises_error(self, rsa_2048_key_pair):
        """Test that providing a non-EdDSA private key (e.g., RSA key) raises InvalidKeyError."""
        # Use RSA private key from session fixture
        rsa_private_key_pem = rsa_2048_key_pair.private_pem
        with pytest.raises(InvalidKeyError, match=r"Key must be an OKP private key"):
            OKPKey.import_key(rsa_private_key_pem)

    def test_okp_key_invalid_public_key_data_raises_error(self):
        """Test that corrupted public key data raises InvalidKeyError."""
        invalid_public_key = b"""-----BEGIN PUBLIC KEY-----
CORRUPTED_DATA_HERE_NOT_VALID_BASE64!!!
-----END PUBLIC KEY-----"""
        with pytest.raises(InvalidKeyError, match=r"Unable to parse OKP public key"):
            OKPKey.import_key(public_key=invalid_public_key)

    def test_okp_key_non_okp_public_key_raises_error(self, rsa_2048_key_pair):
        """Test that providing a non-EdDSA public key (e.g., RSA key) raises InvalidKeyError."""
        # Use RSA public key from session fixture
        rsa_public_key_pem = rsa_2048_key_pair.public_pem
        with pytest.raises(InvalidKeyError, match=r"Key must be an OKP public key"):
            OKPKey.import_key(public_key=rsa_public_key_pem)

    def test_okp_key_empty_public_key_raises_error(self):
        """Test that empty public_key parameter raises ValueError."""
        with pytest.raises(ValueError, match="Public key must not be empty"):
            OKPKey.import_key(None, b"")

    def test_okp_key_public_keys_match_returns_true(self, ed25519_key_pair):
        """Test that public_keys_match returns True when keys match."""
        # Use public key from session fixture
        public_key_obj = ed25519_key_pair.public_key_obj

        # Create OKPKey instance and test
        key = OKPKey()
        assert isinstance(
            public_key_obj, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
        )
        assert key.public_keys_match(public_key_obj, public_key_obj) is True

    def test_okp_key_public_keys_match_returns_false(
        self, ed25519_key_pair, ed25519_key_pair_alt
    ):
        """Test that public_keys_match returns False when keys don't match."""
        # Use two different key pairs from session fixtures
        public_key_obj1 = ed25519_key_pair.public_key_obj
        public_key_obj2 = ed25519_key_pair_alt.public_key_obj

        # Test with mismatched keys
        key = OKPKey()
        assert isinstance(
            public_key_obj1, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
        )
        assert isinstance(
            public_key_obj2, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
        )
        assert key.public_keys_match(public_key_obj1, public_key_obj2) is False

    def test_okp_key_generate_with_invalid_algorithm(self):
        """Test that OKPKey.generate() raises error for invalid algorithm."""
        with pytest.raises(SuperJWTError, match="Unsupported OKP algorithm"):
            OKPKey.generate("Ed519")  # type: ignore

    def test_okp_key_export_private_key_pem(self, ed25519_key_pair):
        """Test exporting private key as PEM."""
        key = ed25519_key_pair.key_instance_from_private_pem
        pem = key.export_private_key_pem()

        assert isinstance(pem, bytes)
        assert b"BEGIN PRIVATE KEY" in pem

    def test_okp_key_export_public_key_pem(self, ed25519_key_pair):
        """Test exporting public key as PEM."""
        key = OKPKey.import_key(ed25519_key_pair.private_pem)
        pem = key.export_public_key_pem()

        assert isinstance(pem, bytes)
        assert b"BEGIN PUBLIC KEY" in pem
