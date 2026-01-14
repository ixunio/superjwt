import secrets
from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import BaseModel, Field
from superjwt.algorithms import Alg
from superjwt.jws import JWS
from superjwt.jwt import JWT
from superjwt.keys import AsymmetricKey, ECKey, OKPKey, RSAKey
from superjwt.utils import CRYPTOGRAPHY_AVAILABLE
from superjwt.validations import JWTClaims, JWTDatetimeFloat, JWTDatetimeInt


try:
    from datetime import UTC
except ImportError:
    # Python 3.10 compatibility
    from datetime import timezone

    UTC = timezone.utc


# ============================================================================
# Claims Fixtures
# ============================================================================


class JWTCustomClaims(JWTClaims):
    # override sub as a mandatory field
    # sub: str --> this syntax triggers a Pylance[reportGeneralTypeIssues] error
    sub: str = Field(default=...)

    # add new custom claims
    user_id: str
    optional_id: int | None = None
    past_date: JWTDatetimeInt | None = None
    future_date: JWTDatetimeFloat | None = None


def check_claims_instance(
    claim_before: JWTCustomClaims,
    claim_after: JWTCustomClaims,
) -> None:
    """Check that two JWTCustomClaims instances match."""
    assert claim_after.iss == claim_before.iss
    assert claim_after.sub == claim_before.sub
    assert claim_after.aud is None

    # Standard timestamp fields (JWTDatetimeInt by default in JWTClaims)
    # Compare at second-level precision (microseconds truncated)
    if claim_after.iat is not None and claim_before.iat is not None:
        assert int(claim_after.iat.timestamp()) == int(claim_before.iat.timestamp())
    if claim_after.nbf is not None and claim_before.nbf is not None:
        assert int(claim_after.nbf.timestamp()) == int(claim_before.nbf.timestamp())
    if claim_after.exp is not None and claim_before.exp is not None:
        assert int(claim_after.exp.timestamp()) == int(claim_before.exp.timestamp())

    # Custom fields
    assert claim_after.jti is None
    assert claim_after.user_id == claim_before.user_id
    assert claim_after.optional_id is None

    # past_date is JWTDatetimeInt - compare at second precision
    if claim_after.past_date is not None and claim_before.past_date is not None:
        assert int(claim_after.past_date.timestamp()) == int(
            claim_before.past_date.timestamp()
        )

    # future_date is JWTDatetimeFloat - compare with float precision
    if claim_after.future_date is not None and claim_before.future_date is not None:
        assert (
            abs(
                claim_after.future_date.timestamp() - claim_before.future_date.timestamp()
            )
            < 1e-6
        )


@pytest.fixture
def jwt() -> JWT:
    return JWT()


@pytest.fixture
def jws_HS256() -> JWS:  # noqa: N802
    return JWS(algorithm=Alg.HS256)


@pytest.fixture
def secret_key_random() -> str:
    return secrets.token_hex(32)


@pytest.fixture
def secret_key() -> str:
    return "test-secret-key-32-bytes-long!!"


@pytest.fixture
def sub() -> str:
    return "user123"


@pytest.fixture
def iss() -> str:
    return "issuer"


@pytest.fixture
def iat() -> float:
    return datetime.now(UTC).timestamp()


@pytest.fixture
def nbf() -> None: ...


@pytest.fixture
def exp() -> float:
    return datetime.strptime(
        "2042-04-02T00:42:42.123456+0000", "%Y-%m-%dT%H:%M:%S.%f%z"
    ).timestamp()


@pytest.fixture
def claims_dict(sub: str, iss: str, iat: float, nbf: float, exp: float) -> dict[str, Any]:
    return {
        "iss": iss,
        "sub": sub,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "user_id": "value",
        "past_date": (datetime.fromtimestamp(iat) - timedelta(days=1)).timestamp(),
        "future_date": (datetime.fromtimestamp(exp) + timedelta(days=1)).timestamp(),
    }


@pytest.fixture
def claims(claims_dict) -> JWTCustomClaims:
    return JWTCustomClaims(**claims_dict)


@pytest.fixture
def claims_fixed_dt() -> JWTCustomClaims:
    return JWTCustomClaims(user_id="123", iss="myapp", sub="someone").with_expiration(
        minutes=30
    )


# ============================================================================
# Asymmetric Key Fixtures (session-scoped for performance)
# ============================================================================

# Mark to skip tests that require cryptography
requires_cryptography = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE, reason="cryptography library not installed"
)

if CRYPTOGRAPHY_AVAILABLE:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPair(BaseModel):
    """Model for asymmetric key pair fixture data.

    Attributes:
        private_key_obj: RSA/EC/Ed25519/Ed448 private key object from cryptography
        public_key_obj: RSA/EC/Ed25519/Ed448 public key object from cryptography
        private_pem: Private key in PEM format (PKCS#8)
        public_pem: Public key in PEM format (SubjectPublicKeyInfo)
        private_key: RSAKey/ECKey/OKPKey instance for signing
        public_key: RSAKey/ECKey/OKPKey instance for verification
    """

    model_config = {"arbitrary_types_allowed": True}

    private_pem: bytes
    public_pem: bytes

    # Cryptography key objects
    # (rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey)
    private_key_obj: Any

    # Cryptography key objects
    # (rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey)
    public_key_obj: Any

    # SuperJWT key instances
    # (RSAKey | ECKey | OKPKey)
    key_instance_from_private_pem: Any

    # SuperJWT key instances
    # (RSAKey | ECKey | OKPKey)
    key_instance_from_public_pem: Any

    @classmethod
    def make_obj(cls, key: AsymmetricKey):
        return KeyPair(
            private_key_obj=key._private_key_obj,
            public_key_obj=key._public_key_obj,
            private_pem=key.private_key,
            public_pem=key.public_key,
            key_instance_from_private_pem=type(key).import_key(key.private_key),
            key_instance_from_public_pem=type(key).import_public_key(key.public_key),
        )


@pytest.fixture(scope="session")
def rsa_2048_key_pair():
    """Generate RSA-2048 key pair once per session for all RSA tests."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(RSAKey.generate(2048))


@pytest.fixture(scope="session")
def rsa_2048_key_pair_alt():
    """Generate a second RSA-2048 key pair for wrong key tests."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(RSAKey.generate(2048))


@pytest.fixture(scope="session")
def ec_p256_key_pair():
    """Generate EC P-256 (SECP256R1) key pair once per session."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(ECKey.generate("P-256"))


@pytest.fixture(scope="session")
def ec_p256_key_pair_alt():
    """Generate a second EC P-256 key pair for wrong key tests."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(ECKey.generate("P-256"))


@pytest.fixture(scope="session")
def ec_p384_key_pair():
    """Generate EC P-384 (SECP384R1) key pair once per session."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(ECKey.generate("P-384"))


@pytest.fixture(scope="session")
def ec_p521_key_pair():
    """Generate EC P-521 (SECP521R1) key pair once per session."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(ECKey.generate("P-521"))


@pytest.fixture(scope="session")
def ed25519_key_pair():
    """Generate Ed25519 key pair once per session."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(OKPKey.generate("Ed25519"))


@pytest.fixture(scope="session")
def ed25519_key_pair_alt():
    """Generate a second Ed25519 key pair for wrong key tests."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(OKPKey.generate("Ed25519"))


@pytest.fixture(scope="session")
def ed448_key_pair():
    """Generate Ed448 key pair once per session."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(OKPKey.generate("Ed448"))


# Additional RSA key sizes for testing
@pytest.fixture(scope="session")
def rsa_3072_key_pair():
    """Generate RSA-3072 key pair once per session."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(RSAKey.generate(3072))


@pytest.fixture(scope="session")
def rsa_4096_key_pair():
    """Generate RSA-4096 key pair once per session."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")
    return KeyPair.make_obj(RSAKey.generate(4096))


# Weak keys for security warning tests (session-scoped for performance)
@pytest.fixture(scope="session")
def rsa_1024_weak_key():
    """Generate weak RSA-1024 key pair once per session for warning tests."""
    if not CRYPTOGRAPHY_AVAILABLE:
        pytest.skip("cryptography not available")

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=1024, backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"private_pem": private_pem, "public_pem": public_pem}
