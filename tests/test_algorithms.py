import pytest
from superjwt.algorithms import (
    HS256Algorithm,
    HS384Algorithm,
    HS512Algorithm,
    NoneAlgorithm,
)
from superjwt.exceptions import SuperJWTError
from superjwt.keys import NoneKey, OctKey

from .conftest import CRYPTOGRAPHY_AVAILABLE, requires_cryptography


if CRYPTOGRAPHY_AVAILABLE:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from superjwt.algorithms import RS256Algorithm, RS384Algorithm, RS512Algorithm
    from superjwt.keys import RSAKey


class TestNoneAlgorithm:
    """Test suite for the 'none' algorithm (no signature)."""

    @pytest.fixture
    def none_key(self):
        """Create a NoneKey."""
        return NoneKey()

    @pytest.fixture
    def test_data(self):
        """Test data to sign."""
        return b"The quick brown fox jumps over the lazy dog"

    def test_none_algorithm_sign(self, none_key, test_data):
        """Test that 'none' algorithm produces a signature."""
        algorithm = NoneAlgorithm()
        signature = algorithm.sign(test_data, none_key)

        assert isinstance(signature, bytes)
        assert signature == b"no-signature"

    def test_none_algorithm_verify(self, none_key, test_data):
        """Test that 'none' algorithm always returns True for verification."""
        algorithm = NoneAlgorithm()

        # Should verify any signature
        assert algorithm.verify(test_data, b"any-signature", none_key) is True
        assert algorithm.verify(test_data, b"", none_key) is True
        assert algorithm.verify(b"different-data", b"any-signature", none_key) is True

    def test_none_algorithm_check_key_validates_type(self, none_key):
        """Test that check_key validates key type."""
        algorithm = NoneAlgorithm()
        algorithm.check_key(none_key)  # Should not raise

        # Try with wrong key type
        oct_key = OctKey.import_key(b"test-secret")
        with pytest.raises(SuperJWTError, match="must be a NoneKey"):
            algorithm.check_key(oct_key)  # type: ignore


class TestHMACAlgorithms:
    @pytest.fixture
    def secret_key(self):
        """Create a symmetric key for HMAC."""
        return OctKey.import_key(b"my-secret-key-for-testing-hmac-algorithms")

    @pytest.fixture
    def wrong_key(self):
        """Create a different symmetric key."""
        return OctKey.import_key(b"wrong-secret-key-for-testing-purposes")

    @pytest.fixture
    def test_data(self):
        """Test data to sign."""
        return b"The quick brown fox jumps over the lazy dog"

    def test_hs256_sign_and_verify(self, secret_key, test_data):
        """Test HS256 algorithm signing and verification."""
        algorithm = HS256Algorithm()
        signature = algorithm.sign(test_data, secret_key)

        assert isinstance(signature, bytes)
        assert len(signature) == 32  # SHA-256 produces 32 bytes
        assert algorithm.verify(test_data, signature, secret_key) is True

    def test_hs384_sign_and_verify(self, secret_key, test_data):
        """Test HS384 algorithm signing and verification."""
        algorithm = HS384Algorithm()
        signature = algorithm.sign(test_data, secret_key)

        assert isinstance(signature, bytes)
        assert len(signature) == 48  # SHA-384 produces 48 bytes
        assert algorithm.verify(test_data, signature, secret_key) is True

    def test_hs512_sign_and_verify(self, secret_key, test_data):
        """Test HS512 algorithm signing and verification."""
        algorithm = HS512Algorithm()
        signature = algorithm.sign(test_data, secret_key)

        assert isinstance(signature, bytes)
        assert len(signature) == 64  # SHA-512 produces 64 bytes
        assert algorithm.verify(test_data, signature, secret_key) is True

    def test_hmac_invalid_signature(self, secret_key, test_data):
        """Test that invalid signatures are rejected."""
        algorithm = HS256Algorithm()
        signature = algorithm.sign(test_data, secret_key)

        # Tamper with the signature
        invalid_signature = b"invalid" + signature[7:]
        assert algorithm.verify(test_data, invalid_signature, secret_key) is False

    def test_hmac_wrong_key(self, secret_key, wrong_key, test_data):
        """Test that signatures fail verification with wrong key."""
        algorithm = HS256Algorithm()
        signature = algorithm.sign(test_data, secret_key)

        assert algorithm.verify(test_data, signature, wrong_key) is False

    def test_hmac_tampered_data(self, secret_key, test_data):
        """Test that tampered data fails verification."""
        algorithm = HS256Algorithm()
        signature = algorithm.sign(test_data, secret_key)

        tampered_data = test_data + b" (modified)"
        assert algorithm.verify(tampered_data, signature, secret_key) is False

    @requires_cryptography
    def test_hmac_check_key_validates_type(self, secret_key):
        """Test that check_key validates key type."""
        algorithm = HS256Algorithm()
        algorithm.check_key(secret_key)  # Should not raise

        # Try with wrong key type
        rsa_key = RSAKey()
        with pytest.raises(SuperJWTError, match="must be an OctKey"):
            algorithm.check_key(rsa_key)  # type: ignore


@requires_cryptography
class TestRSAAlgorithms:
    """Test suite for RSA algorithms (RS256, RS384, RS512)."""

    @pytest.fixture
    def rsa_key_pair(self):
        """Generate RSA key pair for testing."""
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        private_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            "private_pem": private_pem,
            "public_pem": public_pem,
            "private_key": RSAKey.import_signing_key(private_pem),
            "public_key": RSAKey.import_verifying_key(public_pem),
        }

    @pytest.fixture
    def wrong_key_pair(self):
        """Generate a different RSA key pair."""
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        private_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            "private_key": RSAKey.import_signing_key(private_pem),
            "public_key": RSAKey.import_verifying_key(public_pem),
        }

    @pytest.fixture
    def test_data(self):
        """Test data to sign."""
        return b"The quick brown fox jumps over the lazy dog"

    def test_rs256_sign_and_verify(self, rsa_key_pair, test_data):
        """Test RS256 algorithm signing and verification."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair["private_key"])

        assert isinstance(signature, bytes)
        assert len(signature) == 256  # 2048-bit RSA produces 256 bytes
        assert algorithm.verify(test_data, signature, rsa_key_pair["public_key"]) is True

    def test_rs384_sign_and_verify(self, rsa_key_pair, test_data):
        """Test RS384 algorithm signing and verification."""
        algorithm = RS384Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair["private_key"])

        assert isinstance(signature, bytes)
        assert len(signature) == 256  # 2048-bit RSA produces 256 bytes
        assert algorithm.verify(test_data, signature, rsa_key_pair["public_key"]) is True

    def test_rs512_sign_and_verify(self, rsa_key_pair, test_data):
        """Test RS512 algorithm signing and verification."""
        algorithm = RS512Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair["private_key"])

        assert isinstance(signature, bytes)
        assert len(signature) == 256  # 2048-bit RSA produces 256 bytes
        assert algorithm.verify(test_data, signature, rsa_key_pair["public_key"]) is True

    def test_rsa_verify_with_private_key(self, rsa_key_pair, test_data):
        """Test that verification works with private key (contains public component)."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair["private_key"])

        # Should be able to verify with private key
        assert algorithm.verify(test_data, signature, rsa_key_pair["private_key"]) is True

    def test_rsa_invalid_signature(self, rsa_key_pair, test_data):
        """Test that invalid signatures are rejected."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair["private_key"])

        # Tamper with the signature
        invalid_signature = b"X" * len(signature)
        assert (
            algorithm.verify(test_data, invalid_signature, rsa_key_pair["public_key"])
            is False
        )

    def test_rsa_wrong_key(self, rsa_key_pair, wrong_key_pair, test_data):
        """Test that signatures fail verification with wrong key."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair["private_key"])

        assert (
            algorithm.verify(test_data, signature, wrong_key_pair["public_key"]) is False
        )

    def test_rsa_tampered_data(self, rsa_key_pair, test_data):
        """Test that tampered data fails verification."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair["private_key"])

        tampered_data = test_data + b" (modified)"
        assert (
            algorithm.verify(tampered_data, signature, rsa_key_pair["public_key"])
            is False
        )

    def test_rsa_sign_requires_private_key(self, rsa_key_pair, test_data):
        """Test that signing requires a private key."""
        from superjwt.exceptions import InvalidKeyError

        algorithm = RS256Algorithm()

        # Try to sign with public key (should fail)
        with pytest.raises(InvalidKeyError, match="private component"):
            algorithm.sign(test_data, rsa_key_pair["public_key"])

    def test_rsa_check_key_validates_type(self, rsa_key_pair):
        """Test that check_key validates key type."""
        algorithm = RS256Algorithm()
        algorithm.check_key(rsa_key_pair["private_key"])  # Should not raise

        # Try with wrong key type
        oct_key = OctKey.import_key(b"test-secret")
        with pytest.raises(SuperJWTError, match="must be an RSAKey"):
            algorithm.check_key(oct_key)  # type: ignore

    def test_rsa_algorithm_names(self):
        """Test that algorithms have correct names and descriptions."""
        assert RS256Algorithm.name == "RS256"
        assert RS384Algorithm.name == "RS384"
        assert RS512Algorithm.name == "RS512"

        assert "RSASSA-PKCS1-v1_5" in RS256Algorithm.description
        assert "SHA-256" in RS256Algorithm.description
        assert "SHA-384" in RS384Algorithm.description
        assert "SHA-512" in RS512Algorithm.description

    def test_rsa_pkcs1_private_key_format(self, test_data):
        """Test RSA with PKCS#1 private key format (BEGIN RSA PRIVATE KEY)."""
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Export in PKCS#1 format
        pkcs1_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert b"BEGIN RSA PRIVATE KEY" in pkcs1_pem

        # Should work with PKCS#1 format
        rsa_key = RSAKey.import_signing_key(pkcs1_pem)
        algorithm = RS256Algorithm()

        signature = algorithm.sign(test_data, rsa_key)
        assert algorithm.verify(test_data, signature, rsa_key) is True

    def test_rsa_pkcs8_private_key_format(self, test_data):
        """Test RSA with PKCS#8 private key format (BEGIN PRIVATE KEY)."""
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Export in PKCS#8 format
        pkcs8_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert b"BEGIN PRIVATE KEY" in pkcs8_pem

        # Should work with PKCS#8 format
        rsa_key = RSAKey.import_signing_key(pkcs8_pem)
        algorithm = RS256Algorithm()

        signature = algorithm.sign(test_data, rsa_key)
        assert algorithm.verify(test_data, signature, rsa_key) is True

    def test_rsa_pkcs1_public_key_format(self):
        """Test RSA with PKCS#1 public key format (BEGIN RSA PUBLIC KEY)."""
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Export public key in PKCS#1 format
        pkcs1_public_pem = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )

        assert b"BEGIN RSA PUBLIC KEY" in pkcs1_public_pem

        # Should work with PKCS#1 public format
        public_key = RSAKey.import_verifying_key(pkcs1_public_pem)

        # Generate signature with private key
        private_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key = RSAKey.import_signing_key(private_pem)

        algorithm = RS256Algorithm()
        test_data = b"test data"
        signature = algorithm.sign(test_data, private_key)

        # Verify with PKCS#1 public key
        assert algorithm.verify(test_data, signature, public_key) is True

    def test_rsa_different_hash_algorithms_produce_different_signatures(
        self, rsa_key_pair, test_data
    ):
        """Test that different RSA algorithms produce different signatures."""
        rs256 = RS256Algorithm()
        rs384 = RS384Algorithm()
        rs512 = RS512Algorithm()

        sig256 = rs256.sign(test_data, rsa_key_pair["private_key"])
        sig384 = rs384.sign(test_data, rsa_key_pair["private_key"])
        sig512 = rs512.sign(test_data, rsa_key_pair["private_key"])

        # Signatures should be different
        assert sig256 != sig384
        assert sig256 != sig512
        assert sig384 != sig512

        # Each signature should only verify with its own algorithm
        assert rs256.verify(test_data, sig256, rsa_key_pair["public_key"]) is True
        assert rs256.verify(test_data, sig384, rsa_key_pair["public_key"]) is False
        assert rs256.verify(test_data, sig512, rsa_key_pair["public_key"]) is False


class TestAlgorithmKeyTypes:
    """Test that algorithms have correct key types defined."""

    def test_hmac_algorithms_key_type(self):
        """Test that HMAC algorithms specify OctKey as key type."""
        assert HS256Algorithm.key_type is OctKey
        assert HS384Algorithm.key_type is OctKey
        assert HS512Algorithm.key_type is OctKey

    @requires_cryptography
    def test_rsa_algorithms_key_type(self):
        """Test that RSA algorithms specify RSAKey as key type."""
        assert RS256Algorithm.key_type is RSAKey
        assert RS384Algorithm.key_type is RSAKey
        assert RS512Algorithm.key_type is RSAKey
