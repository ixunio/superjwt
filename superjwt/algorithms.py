import hashlib
import hmac
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, Generic, Literal, TypeVar, cast

from typing_extensions import Self

from superjwt.exceptions import (
    AlgorithmNotSupportedError,
    InvalidAlgorithmError,
    SuperJWTError,
)
from superjwt.keys import ECKey, Key, NoneKey, OctKey, OKPKey, RSAKey
from superjwt.utils import (
    CRYPTOGRAPHY_AVAILABLE,
    check_cryptography_available,
    decode_integer,
    encode_integer,
)


if CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

if TYPE_CHECKING:  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PrivateKey,
        Ed448PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
    from cryptography.hazmat.primitives.hashes import HashAlgorithm


KeyType = TypeVar("KeyType", bound=Key)
AsymmetricKeyType = TypeVar("AsymmetricKeyType", RSAKey, ECKey, OKPKey)


class BaseJWSAlgorithm(ABC, Generic[KeyType]):
    name: ClassVar[str]
    description: ClassVar[str]
    key_type: type[KeyType]
    requires_cryptography: ClassVar[bool] = True

    @abstractmethod
    def generate_key(self, *args: Any, **kwargs: Any) -> KeyType: ...

    @abstractmethod
    def check_key(self, key: KeyType) -> None: ...

    @abstractmethod
    def sign(self, data: bytes, key: KeyType) -> bytes: ...

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, key: KeyType) -> bool: ...


class NoneAlgorithm(BaseJWSAlgorithm[NoneKey]):
    """No digital signature performed. Disabled by default for security reasons."""

    name = "none"
    description = "No signature"
    key_type = NoneKey
    requires_cryptography = False

    def generate_key(self) -> NoneKey:
        return self.key_type()

    def check_key(self, key: NoneKey) -> None:
        if not isinstance(key, NoneKey):
            raise SuperJWTError("Key must be a NoneKey for 'none' algorithm")

    def sign(self, _: bytes, __: NoneKey) -> bytes:
        return b"no-signature"

    def verify(self, _: bytes, __: bytes, ___: NoneKey) -> bool:
        return True


class HMACAlgorithm(BaseJWSAlgorithm[OctKey]):
    """Base class for HMAC using SHA algorithms"""

    key_type = OctKey
    requires_cryptography = False

    def __init__(self, hash_algorithm: Any):
        self.hash_algorithm = hash_algorithm

    def generate_key(self, key_size: int | None = None) -> OctKey:
        """Generate a random symmetric key for HMAC.

        Args:
            key_size: The size of the key in bytes. If None, uses the hash output size.
                      For HS256: defaults to 32 bytes (256 bits)
                      For HS384: defaults to 48 bytes (384 bits)
                      For HS512: defaults to 64 bytes (512 bits)

        Returns:
            A new OctKey instance with a randomly generated key.
        """
        final_key_size = (
            key_size if key_size is not None else self.hash_algorithm().digest_size
        )
        return self.key_type.generate(final_key_size)

    def check_key(self, key: OctKey) -> None:
        if not isinstance(key, OctKey):
            raise SuperJWTError("Key must be an OctKey for HMAC algorithms")

    def sign(self, data: bytes, key: OctKey) -> bytes:
        return hmac.new(key.private_key, data, self.hash_algorithm).digest()

    def verify(self, data: bytes, signature: bytes, key: OctKey) -> bool:
        return hmac.compare_digest(signature, self.sign(data, key))


class AsymmetricJWSAlgorithm(BaseJWSAlgorithm[AsymmetricKeyType], ABC):
    """Base class for asymmetric JWS algorithms"""

    def check_key(self, key: AsymmetricKeyType) -> None:
        if not isinstance(key, self.key_type):
            raise SuperJWTError(
                f"Key must be a {self.key_type.__name__} for algorithm {self.name}"
            )


class RSAAlgorithm(AsymmetricJWSAlgorithm[RSAKey]):
    """Base class for RSA using SHA algorithms"""

    key_type = RSAKey

    def __init__(self, hash_algorithm: "HashAlgorithm", padding: "AsymmetricPadding"):
        check_cryptography_available()
        self.hash_algorithm = hash_algorithm
        self.padding = padding

    def generate_key(self, key_size: Literal[2048, 3072, 4096] = 2048) -> RSAKey:
        """Generate a new RSA key pair.

        Args:
            key_size: The size of the key in bits. Default is 2048.
                      Recommended values: 2048, 3072, 4096.
        """

        return self.key_type.generate(key_size)

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

    def __init__(self, hash_algorithm: "HashAlgorithm"):
        super().__init__(hash_algorithm, padding.PKCS1v15())


class RSAPSSAlgorithm(RSAAlgorithm):
    """Base class for RSA using SHA algorithms with PSS padding and MGF1 (RSASSA-PSS)"""

    def __init__(self, hash_algorithm: "HashAlgorithm"):
        super().__init__(
            hash_algorithm,
            padding.PSS(
                mgf=padding.MGF1(hash_algorithm),
                salt_length=hash_algorithm.digest_size,
            ),
        )


class ECDSAAlgorithm(AsymmetricJWSAlgorithm[ECKey]):
    """Base class for ECDSA (Elliptic Curve Digital Signature Algorithm)"""

    key_type = ECKey

    def __init__(self, hash_algorithm: "HashAlgorithm", curve: "type[EllipticCurve]"):
        check_cryptography_available()
        self.hash_algorithm = hash_algorithm
        self.curve = curve
        self.curve_name = curve.name

    def generate_key(self) -> ECKey:
        """Generate a new EC key pair for this algorithm's curve."""
        return self.key_type.generate(self.curve())

    def check_key(self, key: ECKey) -> None:
        super().check_key(key)

        # Validate that the key's curve matches the algorithm's expected curve
        for key_obj, key_component in [
            (key._private_key_obj, "private"),
            (key._public_key_obj, "public"),
        ]:
            if key_obj is not None:
                if not isinstance(key_obj.curve, self.curve):
                    key_curve_name = key_obj.curve.name
                    expected_curve_name = self.curve.name
                    raise SuperJWTError(
                        f"Curve {key_curve_name} in {key_component} key "
                        f"does not match algorithm's expected curve "
                        f"{expected_curve_name}"
                    )

    def sign(self, data: bytes, key: ECKey) -> bytes:
        self.check_key(key)
        private_key = key._get_private_key()

        der_signature = private_key.sign(data, ec.ECDSA(self.hash_algorithm))

        # Encode r and s as raw bytes for JWT format
        r, s = decode_dss_signature(der_signature)
        size = key.curve_key_size
        return encode_integer(r, size) + encode_integer(s, size)

    def verify(self, data: bytes, signature: bytes, key: ECKey) -> bool:
        self.check_key(key)

        # Verify signature has correct length
        key_size = key.curve_key_size
        length = (key_size + 7) // 8
        if len(signature) != 2 * length:
            return False

        # Decode r and s from raw bytes
        r = decode_integer(signature[:length])
        s = decode_integer(signature[length:])

        # Encode as DER signature
        der_signature = encode_dss_signature(r, s)

        public_key = key._get_public_key()
        try:
            public_key.verify(der_signature, data, ec.ECDSA(self.hash_algorithm))
            return True
        except InvalidSignature:
            return False


class EdDSAAlgorithm(AsymmetricJWSAlgorithm[OKPKey]):
    """Base class for EdDSA (Edwards-curve Digital Signature Algorithm)"""

    key_type = OKPKey

    def __init__(
        self,
        curve_type_private: "type[Ed25519PrivateKey | Ed448PrivateKey]",
        curve_type_public: "type[Ed25519PublicKey | Ed448PublicKey]",
    ):
        check_cryptography_available()
        self.curve_type_private = curve_type_private
        self.curve_type_public = curve_type_public

    def generate_key(self) -> OKPKey:
        """Generate a new OKP key pair for this algorithm's curve."""
        return self.key_type.generate(cast("Literal['Ed25519', 'Ed448']", self.name))

    def check_key(self, key: OKPKey) -> None:
        super().check_key(key)

        # Validate that the key's curve matches the algorithm's expected curve
        for key_obj, curve in [
            (key._private_key_obj, self.curve_type_private),
            (key._public_key_obj, self.curve_type_public),
        ]:
            if key_obj is not None:
                if not isinstance(key_obj, curve):
                    key_curve_name = type(key_obj).__name__
                    expected_curve_name = curve.__name__
                    raise SuperJWTError(
                        f"Curve {key_curve_name} "
                        f"does not match algorithm's expected curve "
                        f"{expected_curve_name}"
                    )

    def sign(self, data: bytes, key: OKPKey) -> bytes:
        self.check_key(key)
        private_key = key._get_private_key()
        return private_key.sign(data)

    def verify(self, data: bytes, signature: bytes, key: OKPKey) -> bool:
        self.check_key(key)
        public_key = key._get_public_key()
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


####################################################################


class HS256Algorithm(HMACAlgorithm):
    name = "HS256"
    description = "HMAC with SHA-256 signature"

    def __init__(self):
        super().__init__(hashlib.sha256)


class HS384Algorithm(HMACAlgorithm):
    name = "HS384"
    description = "HMAC with SHA-384 signature"

    def __init__(self):
        super().__init__(hashlib.sha384)


class HS512Algorithm(HMACAlgorithm):
    name = "HS512"
    description = "HMAC with SHA-512 signature"

    def __init__(self):
        super().__init__(hashlib.sha512)


class RS256Algorithm(RSAPKCS1v15Algorithm):
    name = "RS256"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"

    def __init__(self):
        super().__init__(hashes.SHA256())


class RS384Algorithm(RSAPKCS1v15Algorithm):
    name = "RS384"
    description = "RSASSA-PKCS1-v1_5 using SHA-384"

    def __init__(self):
        super().__init__(hashes.SHA384())


class RS512Algorithm(RSAPKCS1v15Algorithm):
    name = "RS512"
    description = "RSASSA-PKCS1-v1_5 using SHA-512"

    def __init__(self):
        super().__init__(hashes.SHA512())


class PS256Algorithm(RSAPSSAlgorithm):
    name = "PS256"
    description = "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"

    def __init__(self):
        super().__init__(hashes.SHA256())


class PS384Algorithm(RSAPSSAlgorithm):
    name = "PS384"
    description = "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"

    def __init__(self):
        super().__init__(hashes.SHA384())


class PS512Algorithm(RSAPSSAlgorithm):
    name = "PS512"
    description = "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"

    def __init__(self):
        super().__init__(hashes.SHA512())


class ES256Algorithm(ECDSAAlgorithm):
    name = "ES256"
    description = "ECDSA using secp256r1 (NIST P-256) curve and SHA-256"

    def __init__(self):
        super().__init__(hashes.SHA256(), ec.SECP256R1)


class ES256KAlgorithm(ECDSAAlgorithm):
    name = "ES256K"
    description = "ECDSA using secp256k1 curve and SHA-256"

    def __init__(self):
        super().__init__(hashes.SHA256(), ec.SECP256K1)


class ES384Algorithm(ECDSAAlgorithm):
    name = "ES384"
    description = "ECDSA using secp384r1 (NIST P-384) curve and SHA-384"

    def __init__(self):
        super().__init__(hashes.SHA384(), ec.SECP384R1)


class ES512Algorithm(ECDSAAlgorithm):
    name = "ES512"
    description = "ECDSA using secp521r1 (NIST P-521) curve and SHA-512"

    def __init__(self):
        super().__init__(hashes.SHA512(), ec.SECP521R1)


class Ed25519Algorithm(EdDSAAlgorithm):
    name = "Ed25519"
    description = "EdDSA signature algorithm using Ed25519 curve"

    def __init__(self):
        super().__init__(ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)


class Ed448Algorithm(EdDSAAlgorithm):
    name = "Ed448"
    description = "EdDSA signature algorithm using Ed448 curve"

    def __init__(self):
        super().__init__(ed448.Ed448PrivateKey, ed448.Ed448PublicKey)


class Alg(str, Enum):
    """JWS/JWT Algorithm names with associated implementation instances."""

    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    ES256 = "ES256"
    ES256K = "ES256K"
    ES384 = "ES384"
    ES512 = "ES512"
    EdDSA = "EdDSA"
    Ed25519 = "Ed25519"
    Ed448 = "Ed448"

    def get_instance(self) -> BaseJWSAlgorithm:
        class_ = ALGORITHMS.get(self.value)
        if class_ is None:
            raise AlgorithmNotSupportedError(
                f"JWS Algorithm '{self.value}' is not yet implemented"
            )
        if class_.requires_cryptography:
            check_cryptography_available()
        return class_()

    @staticmethod
    def get_instance_by_name(name: str) -> BaseJWSAlgorithm:
        if name not in ALGORITHMS:
            raise InvalidAlgorithmError(
                f"Algorithm '{name}' is not a valid JWS algorithm"
            )
        return getattr(Alg, name).get_instance()

    @classmethod
    def get_algorithm(cls, algorithm: Self | BaseJWSAlgorithm | str) -> BaseJWSAlgorithm:
        if isinstance(algorithm, cls):
            return algorithm.get_instance()
        elif isinstance(algorithm, BaseJWSAlgorithm):
            return algorithm
        else:
            return cls.get_instance_by_name(algorithm)


ALGORITHMS: dict[str, type[BaseJWSAlgorithm] | None] = {
    "none": NoneAlgorithm,
    "HS256": HS256Algorithm,
    "HS384": HS384Algorithm,
    "HS512": HS512Algorithm,
    "RS256": RS256Algorithm,
    "RS384": RS384Algorithm,
    "RS512": RS512Algorithm,
    "PS256": PS256Algorithm,
    "PS384": PS384Algorithm,
    "PS512": PS512Algorithm,
    "ES256": ES256Algorithm,
    "ES256K": ES256KAlgorithm,
    "ES384": ES384Algorithm,
    "ES512": ES512Algorithm,
    "EdDSA": None,  # Deprecated and not supported
    "Ed25519": Ed25519Algorithm,
    "Ed448": Ed448Algorithm,
}
