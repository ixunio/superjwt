import pytest
from superjwt.algorithms import (
    Alg,
    Ed448Algorithm,
    Ed25519Algorithm,
    ES256Algorithm,
    ES256KAlgorithm,
    ES384Algorithm,
    ES512Algorithm,
    HS256Algorithm,
    HS384Algorithm,
    HS512Algorithm,
    NoneAlgorithm,
    PS256Algorithm,
    PS384Algorithm,
    PS512Algorithm,
    RS256Algorithm,
    RS384Algorithm,
    RS512Algorithm,
)
from superjwt.exceptions import (
    AlgorithmNotSupportedError,
    InvalidAlgorithmError,
    SuperJWTError,
)
from superjwt.keys import ECKey, NoneKey, OctKey, OKPKey, RSAKey
from superjwt.utils import CRYPTOGRAPHY_AVAILABLE

from .conftest import requires_cryptography


if CRYPTOGRAPHY_AVAILABLE:
    from cryptography.hazmat.primitives import serialization


# Use session-scoped fixture from conftest.py - alias it for compatibility
@pytest.fixture
def rsa_key_pair(rsa_2048_key_pair):
    """Alias for session-scoped RSA key pair fixture."""
    return rsa_2048_key_pair


class TestAlgEnum:
    """Test suite for the Alg enum methods."""

    def test_get_instance_not_implemented(self):
        """Test that get_instance() raises AlgorithmNotSupportedError for unimplemented algorithms."""
        # EdDSA is defined but not yet implemented (ALG_INSTANCES[RS256] = None)
        with pytest.raises(
            AlgorithmNotSupportedError, match=r"EdDSA.*not yet implemented"
        ):
            Alg.EdDSA.get_instance()

    def test_get_instance_by_name_invalid_algorithm(self):
        """Test that get_instance_by_name() raises InvalidAlgorithmError for invalid algorithm names."""
        with pytest.raises(
            InvalidAlgorithmError, match=r"INVALID.*not a valid JWS algorithm"
        ):
            Alg.get_instance_by_name("INVALID")

    def test_get_instance_by_name_not_implemented(self):
        """Test that get_instance_by_name() raises AlgorithmNotSupportedError for unimplemented algorithms."""
        # EdDSA is defined but not yet implemented (ALG_INSTANCES[PS256] = None)
        with pytest.raises(
            AlgorithmNotSupportedError, match=r"EdDSA.*not yet implemented"
        ):
            Alg.get_instance_by_name("EdDSA")

    def test_get_instance_success(self):
        """Test that get_instance() successfully returns an algorithm instance for implemented algorithms."""
        instance = Alg.HS256.get_instance()
        assert instance is not None
        assert instance.__class__.__name__ == "HS256Algorithm"

    def test_get_instance_by_name_success(self):
        """Test that get_instance_by_name() successfully returns an algorithm instance for implemented algorithms."""
        instance = Alg.get_instance_by_name("HS256")
        assert instance is not None
        assert instance.__class__.__name__ == "HS256Algorithm"

    def test_get_algorithm_with_enum(self):
        """Test that get_algorithm() handles Alg enum values."""
        instance = Alg.get_algorithm(Alg.HS256)
        assert instance is not None
        assert instance.__class__.__name__ == "HS256Algorithm"

    def test_get_algorithm_with_string(self):
        """Test that get_algorithm() handles string algorithm names."""
        instance = Alg.get_algorithm("HS256")
        assert instance is not None
        assert instance.__class__.__name__ == "HS256Algorithm"

    def test_get_algorithm_with_instance(self):
        """Test that get_algorithm() passes through algorithm instances."""
        from superjwt.algorithms import HS256Algorithm

        original_instance = HS256Algorithm()
        returned_instance = Alg.get_algorithm(original_instance)
        assert returned_instance is original_instance


class TestSymmetricAlgorithmKeyTypes:
    """Test that algorithms have correct key types defined."""

    def test_hmac_algorithms_key_type(self):
        """Test that HMAC algorithms specify OctKey as key type."""
        assert HS256Algorithm.key_type is OctKey
        assert HS384Algorithm.key_type is OctKey
        assert HS512Algorithm.key_type is OctKey


@requires_cryptography
class TestAsymmetricAlgorithmKeyTypes:
    """Test that asymmetric algorithms have correct key types defined."""

    def test_rsa_algorithms_key_type(self):
        """Test that RSA algorithms specify RSAKey as key type."""
        assert RS256Algorithm.key_type is RSAKey
        assert RS384Algorithm.key_type is RSAKey
        assert RS512Algorithm.key_type is RSAKey

    def test_rsa_pss_algorithms_key_type(self):
        """Test that RSA-PSS algorithms specify RSAKey as key type."""
        assert PS256Algorithm.key_type is RSAKey
        assert PS384Algorithm.key_type is RSAKey
        assert PS512Algorithm.key_type is RSAKey

    def test_ecdsa_algorithms_key_type(self):
        """Test that ECDSA algorithms specify ECKey as key type."""
        assert ES256Algorithm.key_type is ECKey
        assert ES256KAlgorithm.key_type is ECKey
        assert ES384Algorithm.key_type is ECKey
        assert ES512Algorithm.key_type is ECKey

    def test_eddsa_algorithms_key_type(self):
        """Test that EdDSA algorithms specify OKPKey as key type."""
        assert Ed25519Algorithm.key_type is OKPKey
        assert Ed448Algorithm.key_type is OKPKey


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

    def test_none_algorithm_generate_key(self):
        """Test that generate_key returns a NoneKey."""
        algorithm = NoneAlgorithm()
        key = algorithm.generate_key()

        assert isinstance(key, NoneKey)
        assert key.private_key == b""
        assert key.public_key == b""


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
    def wrong_key_pair(self, rsa_2048_key_pair_alt):
        """Alias for session-scoped alternate RSA key pair fixture."""
        return rsa_2048_key_pair_alt

    @pytest.fixture
    def test_data(self):
        """Test data to sign."""
        return b"The quick brown fox jumps over the lazy dog"

    def test_rs256_sign_and_verify(self, rsa_key_pair, test_data):
        """Test RS256 algorithm signing and verification."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair.key_instance_from_private_pem)

        assert isinstance(signature, bytes)
        assert len(signature) == 256  # 2048-bit RSA produces 256 bytes
        assert (
            algorithm.verify(
                test_data, signature, rsa_key_pair.key_instance_from_public_pem
            )
            is True
        )

    def test_rs384_sign_and_verify(self, rsa_key_pair, test_data):
        """Test RS384 algorithm signing and verification."""
        algorithm = RS384Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair.key_instance_from_private_pem)

        assert isinstance(signature, bytes)
        assert len(signature) == 256  # 2048-bit RSA produces 256 bytes
        assert (
            algorithm.verify(
                test_data, signature, rsa_key_pair.key_instance_from_public_pem
            )
            is True
        )

    def test_rs512_sign_and_verify(self, rsa_key_pair, test_data):
        """Test RS512 algorithm signing and verification."""
        algorithm = RS512Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair.key_instance_from_private_pem)

        assert isinstance(signature, bytes)
        assert len(signature) == 256  # 2048-bit RSA produces 256 bytes
        assert (
            algorithm.verify(
                test_data, signature, rsa_key_pair.key_instance_from_public_pem
            )
            is True
        )

    def test_rsa_verify_with_private_key(self, rsa_key_pair, test_data):
        """Test that verification works with private key (contains public component)."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair.key_instance_from_private_pem)

        # Should be able to verify with private key
        assert (
            algorithm.verify(
                test_data, signature, rsa_key_pair.key_instance_from_private_pem
            )
            is True
        )

    def test_rsa_invalid_signature(self, rsa_key_pair, test_data):
        """Test that invalid signatures are rejected."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair.key_instance_from_private_pem)

        # Tamper with the signature
        invalid_signature = b"X" * len(signature)
        assert (
            algorithm.verify(
                test_data, invalid_signature, rsa_key_pair.key_instance_from_public_pem
            )
            is False
        )

    def test_rsa_wrong_key(self, rsa_key_pair, wrong_key_pair, test_data):
        """Test that signatures fail verification with wrong key."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair.key_instance_from_private_pem)

        assert (
            algorithm.verify(
                test_data, signature, wrong_key_pair.key_instance_from_public_pem
            )
            is False
        )

    def test_rsa_tampered_data(self, rsa_key_pair, test_data):
        """Test that tampered data fails verification."""
        algorithm = RS256Algorithm()
        signature = algorithm.sign(test_data, rsa_key_pair.key_instance_from_private_pem)

        tampered_data = test_data + b" (modified)"
        assert (
            algorithm.verify(
                tampered_data, signature, rsa_key_pair.key_instance_from_public_pem
            )
            is False
        )

    def test_rsa_sign_requires_private_key(self, rsa_key_pair, test_data):
        """Test that signing requires a private key."""
        algorithm = RS256Algorithm()

        # Try to sign with public key (should fail)
        with pytest.raises(SuperJWTError, match="private component"):
            algorithm.sign(test_data, rsa_key_pair.key_instance_from_public_pem)

    def test_rsa_check_key_validates_type(self, rsa_key_pair):
        """Test that check_key validates key type."""
        algorithm = RS256Algorithm()
        algorithm.check_key(
            rsa_key_pair.key_instance_from_private_pem
        )  # Should not raise

        # Try with wrong key type
        oct_key = OctKey.import_key(b"test-secret")
        with pytest.raises(SuperJWTError, match="Key must be a RSAKey for algorithm"):
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

    def test_rsa_pkcs1_private_key_format(self, rsa_2048_key_pair, test_data):
        """Test RSA with PKCS#1 private key format (BEGIN PRIVATE KEY)."""
        private_key_obj = rsa_2048_key_pair.private_key_obj

        # Export in PKCS#1 format
        pkcs1_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert b"BEGIN RSA PRIVATE KEY" in pkcs1_pem

        # Should work with PKCS#1 format
        rsa_key = RSAKey.import_key(pkcs1_pem)
        algorithm = RS256Algorithm()

        signature = algorithm.sign(test_data, rsa_key)
        assert algorithm.verify(test_data, signature, rsa_key) is True

    def test_rsa_pkcs8_private_key_format(self, rsa_2048_key_pair, test_data):
        """Test RSA with PKCS#8 private key format (BEGIN PRIVATE KEY)."""
        private_key_obj = rsa_2048_key_pair.private_key_obj

        # Export in PKCS#8 format
        pkcs8_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert b"BEGIN PRIVATE KEY" in pkcs8_pem

        # Should work with PKCS#8 format
        rsa_key = RSAKey.import_key(pkcs8_pem)
        algorithm = RS256Algorithm()

        signature = algorithm.sign(test_data, rsa_key)
        assert algorithm.verify(test_data, signature, rsa_key) is True

    def test_rsa_pkcs1_public_key_format(self, rsa_2048_key_pair):
        """Test RSA with PKCS#1 public key format (BEGIN RSA PUBLIC KEY)."""
        private_key_obj = rsa_2048_key_pair.private_key_obj

        # Export public key in PKCS#1 format
        pkcs1_public_pem = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )

        assert b"BEGIN RSA PUBLIC KEY" in pkcs1_public_pem

        # Should work with PKCS#1 public format
        public_key = RSAKey.import_public_key(pkcs1_public_pem)

        # Generate signature with private key
        private_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key = RSAKey.import_private_key(private_pem)

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

        sig256 = rs256.sign(test_data, rsa_key_pair.key_instance_from_private_pem)
        sig384 = rs384.sign(test_data, rsa_key_pair.key_instance_from_private_pem)
        sig512 = rs512.sign(test_data, rsa_key_pair.key_instance_from_private_pem)

        # Signatures should be different
        assert sig256 != sig384
        assert sig256 != sig512
        assert sig384 != sig512

        # Each signature should only verify with its own algorithm
        assert (
            rs256.verify(test_data, sig256, rsa_key_pair.key_instance_from_public_pem)
            is True
        )
        assert (
            rs256.verify(test_data, sig384, rsa_key_pair.key_instance_from_public_pem)
            is False
        )
        assert (
            rs256.verify(test_data, sig512, rsa_key_pair.key_instance_from_public_pem)
            is False
        )


@requires_cryptography
class TestRSAPSSAlgorithms:
    """Tests for RSASSA-PSS algorithms (PS256, PS384, PS512)."""

    def test_ps256_sign_and_verify(self, rsa_key_pair):
        """Test PS256 algorithm can sign and verify."""
        algo = PS256Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem

        data = b"test data"
        signature = algo.sign(data, private_key)

        assert algo.verify(data, signature, public_key)

    def test_ps384_sign_and_verify(self, rsa_key_pair):
        """Test PS384 algorithm can sign and verify."""
        algo = PS384Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem

        data = b"test data"
        signature = algo.sign(data, private_key)

        assert algo.verify(data, signature, public_key)

    def test_ps512_sign_and_verify(self, rsa_key_pair):
        """Test PS512 algorithm can sign and verify."""
        algo = PS512Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem

        data = b"test data"
        signature = algo.sign(data, private_key)

        assert algo.verify(data, signature, public_key)

    def test_ps256_invalid_signature(self, rsa_key_pair):
        """Test PS256 algorithm rejects invalid signature."""
        algo = PS256Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem

        data = b"test data"
        signature = algo.sign(data, private_key)

        # Tamper with signature
        bad_signature = signature[:-10] + b"0" * 10

        assert not algo.verify(data, bad_signature, public_key)

    def test_ps384_invalid_signature(self, rsa_key_pair):
        """Test PS384 algorithm rejects invalid signature."""
        algo = PS384Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem

        data = b"test data"
        signature = algo.sign(data, private_key)

        # Tamper with signature
        bad_signature = signature[:-10] + b"0" * 10

        assert not algo.verify(data, bad_signature, public_key)

    def test_ps512_invalid_signature(self, rsa_key_pair):
        """Test PS512 algorithm rejects invalid signature."""
        algo = PS512Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem

        data = b"test data"
        signature = algo.sign(data, private_key)

        # Tamper with signature
        bad_signature = signature[:-10] + b"0" * 10

        assert not algo.verify(data, bad_signature, public_key)

    def test_ps256_tampered_data(self, rsa_key_pair):
        """Test PS256 algorithm rejects tampered data."""
        algo = PS256Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem

        data = b"test data"
        signature = algo.sign(data, private_key)

        tampered_data = b"tampered data"

        assert not algo.verify(tampered_data, signature, public_key)

    def test_ps_algorithms_produce_different_signatures(self, rsa_key_pair):
        """Test that different PS algorithms produce different signatures."""
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem
        data = b"test data"

        algo256 = PS256Algorithm()
        algo384 = PS384Algorithm()
        algo512 = PS512Algorithm()

        sig256 = algo256.sign(data, private_key)
        sig384 = algo384.sign(data, private_key)
        sig512 = algo512.sign(data, private_key)

        # All signatures should be different due to different hash functions
        assert sig256 != sig384
        assert sig256 != sig512
        assert sig384 != sig512

        # But each should verify correctly with its own algorithm
        assert algo256.verify(data, sig256, public_key)
        assert algo384.verify(data, sig384, public_key)
        assert algo512.verify(data, sig512, public_key)

        # And fail to verify with wrong algorithms
        assert not algo256.verify(data, sig384, public_key)
        assert not algo256.verify(data, sig512, public_key)

    def test_ps_algorithms_check_key_validates_type(self):
        """Test that PS algorithms validate key types."""
        algo = PS256Algorithm()

        none_key = NoneKey()
        with pytest.raises(SuperJWTError, match="Key must be a RSAKey for algorithm"):
            algo.check_key(none_key)  # type: ignore

        oct_key = OctKey.import_key(b"test-secret")
        with pytest.raises(SuperJWTError, match="Key must be a RSAKey for algorithm"):
            algo.check_key(oct_key)  # type: ignore

    def test_ps_algorithm_names(self):
        """Test that PS algorithms have correct names."""
        assert PS256Algorithm.name == "PS256"
        assert PS384Algorithm.name == "PS384"
        assert PS512Algorithm.name == "PS512"

    def test_ps_algorithm_descriptions(self):
        """Test that PS algorithms have correct descriptions."""
        assert "RSASSA-PSS" in PS256Algorithm.description
        assert "SHA-256" in PS256Algorithm.description
        assert "MGF1" in PS256Algorithm.description

        assert "RSASSA-PSS" in PS384Algorithm.description
        assert "SHA-384" in PS384Algorithm.description
        assert "MGF1" in PS384Algorithm.description

        assert "RSASSA-PSS" in PS512Algorithm.description
        assert "SHA-512" in PS512Algorithm.description
        assert "MGF1" in PS512Algorithm.description

    def test_ps256_verify_with_private_key(self, rsa_key_pair):
        """Test PS256 can verify with private key (which contains public key)."""
        algo = PS256Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem

        data = b"test data"
        signature = algo.sign(data, private_key)

        # Should be able to verify with private key too
        assert algo.verify(data, signature, private_key)

    def test_pss_padding_randomization(self, rsa_key_pair):
        """Test that PSS padding produces different signatures each time."""
        algo = PS256Algorithm()
        private_key = rsa_key_pair.key_instance_from_private_pem
        public_key = rsa_key_pair.key_instance_from_public_pem

        data = b"test data"

        # Generate multiple signatures of the same data
        sig1 = algo.sign(data, private_key)
        sig2 = algo.sign(data, private_key)
        sig3 = algo.sign(data, private_key)

        # PSS padding includes randomness, so signatures should be different
        assert sig1 != sig2
        assert sig1 != sig3
        assert sig2 != sig3

        # But all should verify correctly
        assert algo.verify(data, sig1, public_key)
        assert algo.verify(data, sig2, public_key)
        assert algo.verify(data, sig3, public_key)


@requires_cryptography
class TestECDSAAlgorithms:
    """Test suite for ECDSA algorithms (ES256, ES256K, ES384, ES512)."""

    @pytest.fixture
    def test_data(self):
        """Test data to sign."""
        return b"The quick brown fox jumps over the lazy dog"

    def test_es256_sign_and_verify(self, ec_p256_key_pair, test_data):
        """Test ES256 (ECDSA with P-256 and SHA-256) signing and verification."""
        algorithm = ES256Algorithm()
        private_key = ec_p256_key_pair.key_instance_from_private_pem
        public_key = ec_p256_key_pair.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        assert algorithm.verify(test_data, signature, public_key)

    def test_es384_sign_and_verify(self, ec_p384_key_pair, test_data):
        """Test ES384 (ECDSA with P-384 and SHA-384) signing and verification."""
        algorithm = ES384Algorithm()
        private_key = ec_p384_key_pair.key_instance_from_private_pem
        public_key = ec_p384_key_pair.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        assert algorithm.verify(test_data, signature, public_key)

    def test_es512_sign_and_verify(self, ec_p521_key_pair, test_data):
        """Test ES512 (ECDSA with P-521 and SHA-512) signing and verification."""
        algorithm = ES512Algorithm()
        private_key = ec_p521_key_pair.key_instance_from_private_pem
        public_key = ec_p521_key_pair.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        assert algorithm.verify(test_data, signature, public_key)

    def test_es256k_algorithm_name(self):
        """Test ES256K algorithm name (secp256k1 curve)."""
        algorithm = ES256KAlgorithm()
        assert algorithm.name == "ES256K"
        assert "secp256k1" in algorithm.description

    def test_ecdsa_verify_with_private_key(self, ec_p256_key_pair, test_data):
        """Test that ECDSA verification works with private key (contains public key)."""
        algorithm = ES256Algorithm()
        private_key = ec_p256_key_pair.key_instance_from_private_pem

        signature = algorithm.sign(test_data, private_key)
        # Verify with private key (which contains public key)
        assert algorithm.verify(test_data, signature, private_key)

    def test_ecdsa_invalid_signature(self, ec_p256_key_pair, test_data):
        """Test that ECDSA verification fails with invalid signature."""
        algorithm = ES256Algorithm()
        public_key = ec_p256_key_pair.key_instance_from_public_pem

        # Create an invalid signature (wrong length for P-256)
        invalid_signature = b"invalid_signature_data"

        assert not algorithm.verify(test_data, invalid_signature, public_key)

    def test_ecdsa_wrong_key(self, ec_p256_key_pair, ec_p256_key_pair_alt, test_data):
        """Test that ECDSA verification fails with wrong key."""
        algorithm = ES256Algorithm()
        private_key = ec_p256_key_pair.key_instance_from_private_pem
        wrong_public_key = ec_p256_key_pair_alt.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)

        # Verification should fail with wrong key
        assert not algorithm.verify(test_data, signature, wrong_public_key)

    def test_ecdsa_tampered_data(self, ec_p256_key_pair, test_data):
        """Test that ECDSA verification fails with tampered data."""
        algorithm = ES256Algorithm()
        private_key = ec_p256_key_pair.key_instance_from_private_pem
        public_key = ec_p256_key_pair.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)

        # Tamper with the data
        tampered_data = test_data + b"extra"

        # Verification should fail
        assert not algorithm.verify(tampered_data, signature, public_key)

    def test_ecdsa_sign_requires_private_key(self, ec_p256_key_pair, test_data):
        """Test that ECDSA signing requires private key."""
        algorithm = ES256Algorithm()
        public_key = ec_p256_key_pair.key_instance_from_public_pem

        with pytest.raises(SuperJWTError):
            algorithm.sign(test_data, public_key)

    def test_ecdsa_check_key_validates_type(self, ec_p256_key_pair):
        """Test that ECDSA check_key validates key type."""
        algorithm = ES256Algorithm()
        ec_key = ec_p256_key_pair.key_instance_from_private_pem
        oct_key = OctKey.import_key(b"secret")

        # Should not raise for ECKey
        algorithm.check_key(ec_key)

        # Should raise for wrong key type
        with pytest.raises(SuperJWTError, match="Key must be a ECKey for algorithm"):
            algorithm.check_key(oct_key)  # type: ignore

    def test_ecdsa_algorithm_names(self):
        """Test that ECDSA algorithms have correct names."""
        assert ES256Algorithm.name == "ES256"
        assert ES384Algorithm.name == "ES384"
        assert ES512Algorithm.name == "ES512"

    def test_ecdsa_different_curves_produce_different_signatures(
        self, ec_p256_key_pair, ec_p384_key_pair, test_data
    ):
        """Test that different curves produce different signature sizes."""
        es256 = ES256Algorithm()
        es384 = ES384Algorithm()

        sig256 = es256.sign(test_data, ec_p256_key_pair.key_instance_from_private_pem)
        sig384 = es384.sign(test_data, ec_p384_key_pair.key_instance_from_private_pem)

        # Different curves should produce different signature sizes
        assert len(sig256) != len(sig384)

    def test_ecdsa_randomization(self, ec_p256_key_pair, test_data):
        """Test that ECDSA produces different signatures for the same data (due to randomness)."""
        algorithm = ES256Algorithm()
        private_key = ec_p256_key_pair.key_instance_from_private_pem
        public_key = ec_p256_key_pair.key_instance_from_public_pem

        # Generate multiple signatures of the same data
        sig1 = algorithm.sign(test_data, private_key)
        sig2 = algorithm.sign(test_data, private_key)
        sig3 = algorithm.sign(test_data, private_key)

        # ECDSA includes randomness, so signatures should be different
        assert sig1 != sig2
        assert sig1 != sig3
        assert sig2 != sig3

        # But all should verify correctly
        assert algorithm.verify(test_data, sig1, public_key)
        assert algorithm.verify(test_data, sig2, public_key)
        assert algorithm.verify(test_data, sig3, public_key)

    def test_ecdsa_curve_mismatch_p256_key_with_es384_algo(
        self, ec_p256_key_pair, test_data
    ):
        """Test that using P-256 key with ES384 algorithm raises curve mismatch error."""
        es384 = ES384Algorithm()

        # Should raise error due to curve mismatch (P-256 key with ES384 which expects P-384)
        with pytest.raises(
            SuperJWTError, match="does not match algorithm's expected curve"
        ):
            es384.sign(test_data, ec_p256_key_pair.key_instance_from_private_pem)

    def test_ecdsa_curve_mismatch_p384_key_with_es256_algo(
        self, ec_p384_key_pair, test_data
    ):
        """Test that using P-384 key with ES256 algorithm raises curve mismatch error."""
        es256 = ES256Algorithm()

        # Should raise error due to curve mismatch (P-384 key with ES256 which expects P-256)
        with pytest.raises(
            SuperJWTError, match="does not match algorithm's expected curve"
        ):
            es256.sign(test_data, ec_p384_key_pair.key_instance_from_private_pem)


@requires_cryptography
class TestEdDSAAlgorithms:
    """Test suite for EdDSA algorithms (Ed25519, Ed448)."""

    @pytest.fixture
    def test_data(self):
        """Test data to sign."""
        return b"The quick brown fox jumps over the lazy dog"

    def test_ed25519_sign_and_verify(self, ed25519_key_pair, test_data):
        """Test Ed25519 signing and verification."""
        algorithm = Ed25519Algorithm()
        private_key = ed25519_key_pair.key_instance_from_private_pem
        public_key = ed25519_key_pair.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) == 64  # Ed25519 signatures are always 64 bytes

        assert algorithm.verify(test_data, signature, public_key)

    def test_ed448_sign_and_verify(self, ed448_key_pair, test_data):
        """Test Ed448 signing and verification."""
        algorithm = Ed448Algorithm()
        private_key = ed448_key_pair.key_instance_from_private_pem
        public_key = ed448_key_pair.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) == 114  # Ed448 signatures are always 114 bytes

        assert algorithm.verify(test_data, signature, public_key)

    def test_eddsa_verify_with_private_key(self, ed25519_key_pair, test_data):
        """Test that EdDSA verification works with private key (contains public key)."""
        algorithm = Ed25519Algorithm()
        private_key = ed25519_key_pair.key_instance_from_private_pem

        signature = algorithm.sign(test_data, private_key)
        # Verify with private key (which contains public key)
        assert algorithm.verify(test_data, signature, private_key)

    def test_eddsa_invalid_signature(self, ed25519_key_pair, test_data):
        """Test that EdDSA verification fails with invalid signature."""
        algorithm = Ed25519Algorithm()
        public_key = ed25519_key_pair.key_instance_from_public_pem

        # Create an invalid signature (wrong length)
        invalid_signature = b"invalid_signature_data"

        assert not algorithm.verify(test_data, invalid_signature, public_key)

    def test_eddsa_wrong_key(self, ed25519_key_pair, ed25519_key_pair_alt, test_data):
        """Test that EdDSA verification fails with wrong key."""
        algorithm = Ed25519Algorithm()
        private_key = ed25519_key_pair.key_instance_from_private_pem
        wrong_public_key = ed25519_key_pair_alt.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)

        # Verification should fail with wrong key
        assert not algorithm.verify(test_data, signature, wrong_public_key)

    def test_eddsa_tampered_data(self, ed25519_key_pair, test_data):
        """Test that EdDSA verification fails with tampered data."""
        algorithm = Ed25519Algorithm()
        private_key = ed25519_key_pair.key_instance_from_private_pem
        public_key = ed25519_key_pair.key_instance_from_public_pem

        signature = algorithm.sign(test_data, private_key)

        # Tamper with the data
        tampered_data = test_data + b"extra"

        # Verification should fail
        assert not algorithm.verify(tampered_data, signature, public_key)

    def test_eddsa_sign_requires_private_key(self, ed25519_key_pair, test_data):
        """Test that EdDSA signing requires private key."""
        algorithm = Ed25519Algorithm()
        public_key = ed25519_key_pair.key_instance_from_public_pem

        with pytest.raises(SuperJWTError):
            algorithm.sign(test_data, public_key)

    def test_eddsa_check_key_validates_type(self, ed25519_key_pair):
        """Test that EdDSA check_key validates key type."""
        algorithm = Ed25519Algorithm()
        okp_key = ed25519_key_pair.key_instance_from_private_pem
        oct_key = OctKey.import_key(b"secret")

        # Should not raise for OKPKey
        algorithm.check_key(okp_key)

        # Should raise for wrong key type
        with pytest.raises(SuperJWTError, match="Key must be a OKPKey for algorithm"):
            algorithm.check_key(oct_key)  # type: ignore

    def test_eddsa_algorithm_names(self):
        """Test that EdDSA algorithms have correct names."""
        assert Ed25519Algorithm.name == "Ed25519"
        assert Ed448Algorithm.name == "Ed448"

    def test_eddsa_deterministic_signatures(self, ed25519_key_pair, test_data):
        """Test that EdDSA produces deterministic signatures (same input = same signature)."""
        algorithm = Ed25519Algorithm()
        private_key = ed25519_key_pair.key_instance_from_private_pem

        # Generate multiple signatures of the same data
        sig1 = algorithm.sign(test_data, private_key)
        sig2 = algorithm.sign(test_data, private_key)
        sig3 = algorithm.sign(test_data, private_key)

        # EdDSA is deterministic, so signatures should be identical
        assert sig1 == sig2
        assert sig1 == sig3
        assert sig2 == sig3

    def test_ed25519_ed448_different_signature_sizes(
        self, ed25519_key_pair, ed448_key_pair, test_data
    ):
        """Test that Ed25519 and Ed448 produce different signature sizes."""
        ed25519_algo = Ed25519Algorithm()
        ed448_algo = Ed448Algorithm()

        sig_ed25519 = ed25519_algo.sign(
            test_data, ed25519_key_pair.key_instance_from_private_pem
        )
        sig_ed448 = ed448_algo.sign(
            test_data, ed448_key_pair.key_instance_from_private_pem
        )

        # Different signature sizes
        assert len(sig_ed25519) == 64
        assert len(sig_ed448) == 114

    def test_eddsa_curve_mismatch_ed25519_key_with_ed448_algo(
        self, ed25519_key_pair, test_data
    ):
        """Test that Ed25519 key with Ed448 algorithm raises error."""
        ed448_algo = Ed448Algorithm()
        ed25519_key = ed25519_key_pair.key_instance_from_private_pem

        # Should raise error due to curve mismatch
        with pytest.raises(
            SuperJWTError, match="does not match algorithm's expected curve"
        ):
            ed448_algo.sign(test_data, ed25519_key)

    def test_eddsa_curve_mismatch_ed448_key_with_ed25519_algo(
        self, ed448_key_pair, test_data
    ):
        """Test that Ed448 key with Ed25519 algorithm raises error."""
        ed25519_algo = Ed25519Algorithm()
        ed448_key = ed448_key_pair.key_instance_from_private_pem

        # Should raise error due to curve mismatch
        with pytest.raises(
            SuperJWTError, match="does not match algorithm's expected curve"
        ):
            ed25519_algo.sign(test_data, ed448_key)

    def test_eddsa_curve_mismatch_public_key_ed25519_with_ed448_algo(
        self, ed25519_key_pair, test_data
    ):
        """Test that Ed25519 public key with Ed448 algorithm raises error during verify."""
        ed448_algo = Ed448Algorithm()

        # Create a public-only key to test the public key validation path
        ed25519_public_only = OKPKey.import_public_key(ed25519_key_pair.public_pem)

        # Create a valid signature with Ed25519
        ed25519_algo = Ed25519Algorithm()
        signature = ed25519_algo.sign(
            test_data, ed25519_key_pair.key_instance_from_private_pem
        )

        # Should raise error when trying to verify with Ed448 algorithm (wrong curve)
        with pytest.raises(
            SuperJWTError, match="does not match algorithm's expected curve"
        ):
            ed448_algo.verify(test_data, signature, ed25519_public_only)

    def test_eddsa_curve_mismatch_public_key_ed448_with_ed25519_algo(
        self, ed448_key_pair, test_data
    ):
        """Test that Ed448 public key with Ed25519 algorithm raises error during verify."""
        ed25519_algo = Ed25519Algorithm()

        # Create a public-only key to test the public key validation path
        ed448_public_only = OKPKey.import_public_key(ed448_key_pair.public_pem)

        # Create a valid signature with Ed448
        ed448_algo = Ed448Algorithm()
        signature = ed448_algo.sign(
            test_data, ed448_key_pair.key_instance_from_private_pem
        )

        # Should raise error when trying to verify with Ed25519 algorithm (wrong curve)
        with pytest.raises(
            SuperJWTError, match="does not match algorithm's expected curve"
        ):
            ed25519_algo.verify(test_data, signature, ed448_public_only)


class TestHMACGenerateKey:
    """Test HMAC algorithm key generation."""

    def test_hs256_generate_key_default_size(self):
        """Test HS256 generates key with default size (32 bytes as hex = 64 chars)."""
        algo = HS256Algorithm()
        key = algo.generate_key()
        assert isinstance(key, OctKey)
        assert len(key.private_key) == 64  # 32 bytes as hex

    def test_hs384_generate_key_default_size(self):
        """Test HS384 generates key with default size (48 bytes as hex = 96 chars)."""
        algo = HS384Algorithm()
        key = algo.generate_key()
        assert isinstance(key, OctKey)
        assert len(key.private_key) == 96  # 48 bytes as hex

    def test_hs512_generate_key_default_size(self):
        """Test HS512 generates key with default size (64 bytes as hex = 128 chars)."""
        algo = HS512Algorithm()
        key = algo.generate_key()
        assert isinstance(key, OctKey)
        assert len(key.private_key) == 128  # 64 bytes as hex

    def test_hmac_generate_key_custom_size(self):
        """Test HMAC can generate key with custom size."""
        algo = HS256Algorithm()
        key = algo.generate_key(16)
        assert isinstance(key, OctKey)
        assert len(key.private_key) == 32  # 16 bytes as hex

    def test_hmac_generated_key_works_for_signing(self):
        """Test that generated key can be used for signing and verification."""
        algo = HS256Algorithm()
        key = algo.generate_key()
        test_data = b"test message"

        signature = algo.sign(test_data, key)
        assert algo.verify(test_data, signature, key)

    def test_hmac_generated_keys_are_different(self):
        """Test that multiple generated keys are different."""
        algo = HS256Algorithm()
        key1 = algo.generate_key()
        key2 = algo.generate_key()
        assert key1.private_key != key2.private_key


@requires_cryptography
class TestRSAGenerateKey:
    """Test RSA algorithm key generation."""

    def test_rs256_generate_key_2048(self):
        """Test RS256 can generate 2048-bit key."""
        algo = RS256Algorithm()
        key = algo.generate_key(2048)
        assert isinstance(key, RSAKey)
        private_key = key._get_private_key()
        assert private_key.key_size == 2048

    def test_rs384_generate_key_3072(self):
        """Test RS384 can generate 3072-bit key."""
        algo = RS384Algorithm()
        key = algo.generate_key(3072)
        assert isinstance(key, RSAKey)
        private_key = key._get_private_key()
        assert private_key.key_size == 3072

    def test_rs512_generate_key_4096(self):
        """Test RS512 can generate 4096-bit key."""
        algo = RS512Algorithm()
        key = algo.generate_key(4096)
        assert isinstance(key, RSAKey)
        private_key = key._get_private_key()
        assert private_key.key_size == 4096

    def test_rsa_generated_key_works_for_signing(self):
        """Test that generated RSA key can be used for signing and verification."""
        algo = RS256Algorithm()
        key = algo.generate_key(2048)
        test_data = b"test message"

        signature = algo.sign(test_data, key)
        assert algo.verify(test_data, signature, key)


@requires_cryptography
class TestRSAPSSGenerateKey:
    """Test RSA-PSS algorithm key generation."""

    def test_ps256_generate_key(self):
        """Test PS256 can generate key."""
        algo = PS256Algorithm()
        key = algo.generate_key(2048)
        assert isinstance(key, RSAKey)
        private_key = key._get_private_key()
        assert private_key.key_size == 2048

    def test_ps384_generate_key(self):
        """Test PS384 can generate key."""
        algo = PS384Algorithm()
        key = algo.generate_key(2048)
        assert isinstance(key, RSAKey)

    def test_ps512_generate_key(self):
        """Test PS512 can generate key."""
        algo = PS512Algorithm()
        key = algo.generate_key(2048)
        assert isinstance(key, RSAKey)

    def test_pss_generated_key_works_for_signing(self):
        """Test that generated RSA-PSS key can be used for signing and verification."""
        algo = PS256Algorithm()
        key = algo.generate_key(2048)
        test_data = b"test message"

        signature = algo.sign(test_data, key)
        assert algo.verify(test_data, signature, key)


@requires_cryptography
class TestECDSAGenerateKey:
    """Test ECDSA algorithm key generation."""

    def test_es256_generate_key(self):
        """Test ES256 generates key with P-256 curve."""
        algo = ES256Algorithm()
        key = algo.generate_key()
        assert isinstance(key, ECKey)
        assert key.curve_name == "secp256r1"

    def test_es256k_generate_key(self):
        """Test ES256K generates key with secp256k1 curve."""
        algo = ES256KAlgorithm()
        key = algo.generate_key()
        assert isinstance(key, ECKey)
        assert key.curve_name == "secp256k1"

    def test_es384_generate_key(self):
        """Test ES384 generates key with P-384 curve."""
        algo = ES384Algorithm()
        key = algo.generate_key()
        assert isinstance(key, ECKey)
        assert key.curve_name == "secp384r1"

    def test_es512_generate_key(self):
        """Test ES512 generates key with P-521 curve."""
        algo = ES512Algorithm()
        key = algo.generate_key()
        assert isinstance(key, ECKey)
        assert key.curve_name == "secp521r1"

    def test_ecdsa_generated_key_works_for_signing(self):
        """Test that generated EC key can be used for signing and verification."""
        algo = ES256Algorithm()
        key = algo.generate_key()
        test_data = b"test message"

        signature = algo.sign(test_data, key)
        assert algo.verify(test_data, signature, key)

    def test_ecdsa_generated_signatures_are_different(self):
        """Test that ECDSA produces different signatures (randomization)."""
        algo = ES256Algorithm()
        key = algo.generate_key()
        test_data = b"test message"

        signature1 = algo.sign(test_data, key)
        signature2 = algo.sign(test_data, key)
        # ECDSA signatures should be different due to random nonce
        assert signature1 != signature2
        # But both should verify
        assert algo.verify(test_data, signature1, key)
        assert algo.verify(test_data, signature2, key)


@requires_cryptography
class TestEdDSAGenerateKey:
    """Test EdDSA algorithm key generation."""

    def test_ed25519_generate_key(self):
        """Test Ed25519 can generate key."""
        algo = Ed25519Algorithm()
        key = algo.generate_key()
        assert isinstance(key, OKPKey)
        # Verify it's Ed25519 by checking the key type
        private_key = key._get_private_key()
        assert type(private_key).__name__ == "Ed25519PrivateKey"

    def test_ed448_generate_key(self):
        """Test Ed448 can generate key."""
        algo = Ed448Algorithm()
        key = algo.generate_key()
        assert isinstance(key, OKPKey)
        # Verify it's Ed448 by checking the key type
        private_key = key._get_private_key()
        assert type(private_key).__name__ == "Ed448PrivateKey"

    def test_eddsa_generated_key_works_for_signing(self):
        """Test that generated EdDSA key can be used for signing and verification."""
        algo = Ed25519Algorithm()
        key = algo.generate_key()
        test_data = b"test message"

        signature = algo.sign(test_data, key)
        assert algo.verify(test_data, signature, key)

    def test_eddsa_signatures_are_deterministic(self):
        """Test that EdDSA produces deterministic signatures."""
        algo = Ed25519Algorithm()
        key = algo.generate_key()
        test_data = b"test message"

        signature1 = algo.sign(test_data, key)
        signature2 = algo.sign(test_data, key)
        # EdDSA signatures should be identical (deterministic)
        assert signature1 == signature2
