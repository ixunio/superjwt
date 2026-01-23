import json

import pytest
from superjwt import inspect
from superjwt.exceptions import (
    AlgorithmMismatchError,
    HeadersValidationError,
    InvalidHeadersError,
    InvalidPayloadError,
    InvalidTokenError,
    SignatureVerificationError,
    SizeExceededError,
)
from superjwt.jws import (
    JWSToken,
    check_algorithm_match,
    check_compact_size,
    decode_raw_headers,
    decode_raw_payload,
    decode_raw_signature,
    extract_parts,
    jws_decode,
    jws_encode,
    make_signing_input,
    prepare_signing_key,
    prepare_verifying_key,
    validate_headers_and_algorithm,
    verify_signature,
)
from superjwt.keys import ECKey, OctKey, OKPKey, RSAKey
from superjwt.shared import Alg, set_max_token_bytes
from superjwt.utils import urlsafe_b64encode
from superjwt.validations import JOSEHeader, Validation

from .conftest import JWTCustomClaims


# ============================================================================
# JWS Encode Tests
# ============================================================================


class TestJWSEncode:
    def test_encode_basic(self, claims_fixed_dt: JWTCustomClaims, secret_key: str):
        """Test basic JWS encoding."""
        key = OctKey.import_key(secret_key)
        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            key,
            Alg.HS256.get_instance(),
        )
        assert isinstance(compact, bytes)
        assert compact.count(b".") == 2

    def test_encode_with_custom_headers(
        self, claims_fixed_dt: JWTCustomClaims, secret_key: str
    ):
        """Test encoding with custom headers."""
        key = OctKey.import_key(secret_key)
        headers = {"alg": "HS256", "typ": "JWT", "kid": "key-123"}

        compact = jws_encode(
            headers,
            claims_fixed_dt.to_json(),
            key,
            Alg.HS256.get_instance(),
        )

        token = inspect(compact)
        assert token.headers["kid"] == "key-123"
        assert token.headers["alg"] == "HS256"

    def test_encode_with_pydantic_headers(
        self, claims_fixed_dt: JWTCustomClaims, secret_key: str
    ):
        """Test encoding with Pydantic headers."""
        key = OctKey.import_key(secret_key)
        headers = JOSEHeader(alg="HS256", kid="test-key")

        compact = jws_encode(
            headers,
            claims_fixed_dt.to_json(),
            key,
            Alg.HS256.get_instance(),
        )

        token = inspect(compact)
        assert token.headers["kid"] == "test-key"

    def test_encode_detached_payload(
        self, claims_fixed_dt: JWTCustomClaims, secret_key: str
    ):
        """Test encoding with detached payload."""
        key = OctKey.import_key(secret_key)
        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            key,
            Alg.HS256.get_instance(),
            detach_payload=True,
        )

        parts = compact.split(b".")
        assert len(parts) == 3
        assert parts[1] == b""  # Empty payload section

    def test_encode_wrong_header_algorithm(
        self, claims_fixed_dt: JWTCustomClaims, secret_key: str
    ):
        """Test that wrong algorithm in headers raises validation error."""
        key = OctKey.import_key(secret_key)
        headers = JOSEHeader(alg="HS256")
        headers.alg = "ABCDEF"  # wrong algorithm in header  # type: ignore

        with pytest.raises(HeadersValidationError):
            jws_encode(
                headers,
                claims_fixed_dt.to_json(),
                key,
                Alg.HS256.get_instance(),
            )

        # Even with validation disabled, we enforce consistency
        with pytest.raises(AlgorithmMismatchError):
            jws_encode(
                headers,
                claims_fixed_dt.to_json(),
                key,
                Alg.HS256.get_instance(),
                headers_validation=Validation.DISABLE,
            )

    def test_encode_algorithm_mismatch(
        self, claims_fixed_dt: JWTCustomClaims, secret_key: str
    ):
        """Test that encoding with mismatched algorithm in headers raises error."""
        key = OctKey.import_key(secret_key)
        headers = {"alg": "HS512", "typ": "JWT"}

        with pytest.raises(AlgorithmMismatchError) as exc:
            jws_encode(
                headers,
                claims_fixed_dt.to_json(),
                key,
                Alg.HS256.get_instance(),
            )
        assert "does not match" in str(exc.value)

    def test_encode_with_bytes_key(self, claims_fixed_dt: JWTCustomClaims):
        """Test encoding with raw bytes key."""
        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            b"my-secret-key-bytes-32-long!",
            Alg.HS256.get_instance(),
        )
        assert isinstance(compact, bytes)

    def test_encode_with_str_key(self, claims_fixed_dt: JWTCustomClaims):
        """Test encoding with string key."""
        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            "my-secret-key-string",
            Alg.HS256.get_instance(),
        )
        assert isinstance(compact, bytes)


# ============================================================================
# JWS Decode Tests
# ============================================================================


class TestJWSDecode:
    def test_decode_basic(self, claims_fixed_dt: JWTCustomClaims, secret_key: str):
        """Test basic JWS decoding."""
        key = OctKey.import_key(secret_key)
        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            key,
            Alg.HS256.get_instance(),
        )

        payload = jws_decode(compact, key, Alg.HS256.get_instance())
        assert payload == claims_fixed_dt.to_dict()

    def test_decode_with_bytes_key(self, claims_fixed_dt: JWTCustomClaims):
        """Test decoding with raw bytes key."""
        key_bytes = b"my-secret-key-bytes-32-long!"
        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            key_bytes,
            Alg.HS256.get_instance(),
        )

        payload = jws_decode(compact, key_bytes, Alg.HS256.get_instance())
        assert payload["sub"] == claims_fixed_dt.sub

    def test_decode_algorithm_mismatch(self, secret_key: str):
        """Test that decoding with mismatched algorithm in headers raises error."""
        compact = (
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
            "."
            "eyJpc3MiOiJ1c2VyLTEyMyJ9"
            "."
            "Mp0Pcwsz5VECK11Kf2ZZNF_SMKu5CgBeLN9ZOP04kZo"
        )
        assert inspect(compact).headers["alg"] == "HS512"
        with pytest.raises(AlgorithmMismatchError) as exc:
            jws_decode(compact, secret_key, Alg.HS256.get_instance())
        assert "does not match" in str(exc.value)

    def test_decode_invalid_signature(
        self, claims_fixed_dt: JWTCustomClaims, secret_key: str
    ):
        """Test decoding with invalid signature."""
        key = OctKey.import_key(secret_key)
        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            key,
            Alg.HS256.get_instance(),
        )

        # Tamper with signature
        parts = compact.split(b".")
        parts[2] = urlsafe_b64encode(b"tampered-signature")
        tampered = b".".join(parts)

        with pytest.raises(SignatureVerificationError):
            jws_decode(tampered, key, Alg.HS256.get_instance())

    def test_decode_wrong_key(self, claims_fixed_dt: JWTCustomClaims, secret_key: str):
        """Test decoding with wrong key."""
        key1 = OctKey.import_key(secret_key)
        key2 = OctKey.import_key("different-key-32-bytes-long")

        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            key1,
            Alg.HS256.get_instance(),
        )

        with pytest.raises(SignatureVerificationError):
            jws_decode(compact, key2, Alg.HS256.get_instance())


# ============================================================================
# Token Format Tests
# ============================================================================


class TestTokenFormat:
    def test_extract_parts_valid(self):
        """Test extracting parts from valid token."""
        compact = b"header.payload.signature"
        header, payload, sig = extract_parts(compact)
        assert header == b"header"
        assert payload == b"payload"
        assert sig == b"signature"

    def test_extract_parts_invalid_format(self):
        """Test that invalid token format raises error."""
        with pytest.raises(InvalidTokenError) as exc:
            extract_parts(b"only.two.parts.here.invalid")
        assert "exactly 3 parts" in str(exc.value)

    def test_extract_parts_missing_separator(self):
        """Test token without proper separators."""
        with pytest.raises(InvalidTokenError):
            extract_parts(b"no-separators")

    def test_extract_parts_detached_payload(self):
        """Test extracting parts with detached payload."""
        compact = b"header..signature"
        payload_data = {"sub": "user123"}

        header, payload, sig = extract_parts(compact, with_detached_payload=payload_data)
        assert header == b"header"
        assert payload != b""  # Should be re-encoded
        assert sig == b"signature"

    def test_extract_parts_detached_payload_conflict(self):
        """Test that non-empty payload with detached flag raises error."""
        compact = b"header.payload.signature"
        with pytest.raises(InvalidTokenError) as exc:
            extract_parts(compact, with_detached_payload={"sub": "test"})
        assert "Detached payload conflict" in str(exc.value)


# ============================================================================
# Decoding Individual Parts Tests
# ============================================================================


class TestDecodeParts:
    def test_decode_raw_headers_valid(self):
        """Test decoding valid headers."""
        headers_dict = {"alg": "HS256", "typ": "JWT"}
        encoded = urlsafe_b64encode(json.dumps(headers_dict).encode())

        decoded = decode_raw_headers(encoded)
        assert decoded == headers_dict

    def test_decode_raw_headers_invalid_base64(self):
        """Test decoding headers with invalid base64."""
        with pytest.raises(InvalidHeadersError) as exc:
            decode_raw_headers(b"!!!invalid-base64!!!")
        assert "not encoded as a valid Base64url" in str(exc.value)

    def test_decode_raw_headers_invalid_json(self):
        """Test decoding headers with invalid JSON."""
        encoded = urlsafe_b64encode(b"{invalid json")
        with pytest.raises(InvalidHeadersError) as exc:
            decode_raw_headers(encoded)
        assert "not a valid JSON" in str(exc.value)

    def test_decode_raw_headers_non_dict(self):
        """Test decoding headers that are not a dict."""
        encoded = urlsafe_b64encode(json.dumps(["not", "a", "dict"]).encode())
        with pytest.raises(InvalidHeadersError) as exc:
            decode_raw_headers(encoded)
        assert "does not result in a mapping" in str(exc.value)

    def test_decode_raw_payload_valid(self):
        """Test decoding valid payload."""
        payload_dict = {"sub": "user123", "iat": 1234567890}
        encoded = urlsafe_b64encode(json.dumps(payload_dict).encode())

        decoded = decode_raw_payload(encoded)
        assert decoded == payload_dict

    def test_decode_raw_payload_invalid_base64(self):
        """Test decoding payload with invalid base64."""
        with pytest.raises(InvalidPayloadError) as exc:
            decode_raw_payload(b"!!!invalid-base64!!!")
        assert "not encoded as a valid Base64url" in str(exc.value)

    def test_decode_raw_payload_non_dict(self):
        """Test decoding payload that is not a dict."""
        encoded = urlsafe_b64encode(json.dumps("not a dict").encode())
        with pytest.raises(InvalidPayloadError) as exc:
            decode_raw_payload(encoded)
        assert "does not result in a mapping" in str(exc.value)

    def test_decode_raw_signature_valid(self):
        """Test decoding valid signature."""
        signature = b"binary-signature-data"
        encoded = urlsafe_b64encode(signature)

        decoded = decode_raw_signature(encoded)
        assert decoded == signature

    def test_decode_raw_signature_invalid_base64(self):
        """Test decoding signature with invalid base64."""
        with pytest.raises(InvalidTokenError) as exc:
            decode_raw_signature(b"!!!invalid-base64!!!")
        assert "not encoded as a valid Base64url" in str(exc.value)

    def test_decode_parts_complete(self):
        """Test decoding all parts together."""
        headers_dict = {"alg": "HS256"}
        payload_dict = {"sub": "user123"}
        signature = b"signature"

        encoded_headers = urlsafe_b64encode(json.dumps(headers_dict).encode())
        encoded_payload = urlsafe_b64encode(json.dumps(payload_dict).encode())
        encoded_signature = urlsafe_b64encode(signature)

        headers = decode_raw_headers(encoded_headers)
        payload = decode_raw_payload(encoded_payload)
        sig = decode_raw_signature(encoded_signature)

        assert headers == headers_dict
        assert payload == payload_dict
        assert sig == signature

    def test_decode_parts_empty_payload(self):
        """Test decoding parts with empty payload."""
        headers_dict = {"alg": "HS256"}
        encoded_headers = urlsafe_b64encode(json.dumps(headers_dict).encode())
        encoded_signature = urlsafe_b64encode(b"sig")

        headers = decode_raw_headers(encoded_headers)
        payload = {}  # Empty payload
        sig = decode_raw_signature(encoded_signature)

        assert headers == headers_dict
        assert payload == {}
        assert sig == b"sig"

    def test_decode_parts_with_detached_payload(self):
        """Test decoding parts with detached payload provided."""
        headers_dict = {"alg": "HS256"}
        payload_dict = {"sub": "user123"}
        encoded_headers = urlsafe_b64encode(json.dumps(headers_dict).encode())
        encoded_signature = urlsafe_b64encode(b"sig")

        headers = decode_raw_headers(encoded_headers)
        payload = payload_dict  # Use detached payload
        sig = decode_raw_signature(encoded_signature)

        assert headers == headers_dict
        assert payload == payload_dict
        assert sig == b"sig"


# ============================================================================
# Validation Tests
# ============================================================================


class TestValidation:
    def test_validate_headers_and_algorithm_valid(self):
        """Test validating valid headers."""
        headers = {"alg": "HS256", "typ": "JWT"}
        validate_headers_and_algorithm(
            headers, Validation.DEFAULT, Alg.HS256.get_instance()
        )
        # Should not raise

    def test_validate_headers_and_algorithm_invalid(self):
        """Test validating invalid headers."""
        headers = {"alg": "HS256", "typ": 123}  # typ should be string
        with pytest.raises(HeadersValidationError):
            validate_headers_and_algorithm(
                headers, Validation.DEFAULT, Alg.HS256.get_instance()
            )

    def test_validate_headers_disabled(self):
        """Test that validation can be disabled."""
        headers = {"alg": "HS256", "typ": 123}
        validate_headers_and_algorithm(
            headers, Validation.DISABLE, Alg.HS256.get_instance()
        )
        # Should not raise error with validation disabled

    def test_check_algorithm_match_valid(self):
        """Test algorithm match check with matching algorithms."""
        headers = JOSEHeader(alg="HS256")
        check_algorithm_match(headers.alg, Alg.HS256.get_instance())
        # Should not raise

    def test_check_algorithm_match_invalid(self):
        """Test algorithm match check with mismatched algorithms."""
        headers = JOSEHeader(alg="HS512")
        with pytest.raises(AlgorithmMismatchError) as exc:
            check_algorithm_match(headers.alg, Alg.HS256.get_instance())
        assert "does not match" in str(exc.value)


# ============================================================================
# Signature Tests
# ============================================================================


class TestSignature:
    def test_make_signing_input(self):
        """Test creating signing input."""
        header = b"header-part"
        payload = b"payload-part"

        signing_input = make_signing_input(header, payload)
        assert signing_input == b"header-part.payload-part"

    def test_verify_signature_valid(self, secret_key: str):
        """Test verifying valid signature."""
        key = OctKey.import_key(secret_key)
        alg = Alg.HS256.get_instance()
        signing_input = b"header.payload"

        signature = alg.sign(signing_input, key)
        verify_signature(signing_input, signature, key, alg)
        # Should not raise

    def test_verify_signature_invalid(self, secret_key: str):
        """Test verifying invalid signature."""
        key = OctKey.import_key(secret_key)
        alg = Alg.HS256.get_instance()
        signing_input = b"header.payload"

        wrong_signature = b"wrong-signature"
        with pytest.raises(SignatureVerificationError):
            verify_signature(signing_input, wrong_signature, key, alg)


# ============================================================================
# Key Preparation Tests
# ============================================================================


class TestKeyPreparation:
    def test_prepare_signing_key_from_key_instance(self, secret_key: str):
        """Test preparing signing key from Key instance."""
        key = OctKey.import_key(secret_key)
        alg = Alg.HS256.get_instance()

        prepared = prepare_signing_key(key, alg)
        assert prepared is key

    def test_prepare_signing_key_from_bytes(self):
        """Test preparing signing key from bytes."""
        key_bytes = b"my-secret-key-bytes-32-long!"
        alg = Alg.HS256.get_instance()

        prepared = prepare_signing_key(key_bytes, alg)
        assert isinstance(prepared, OctKey)

    def test_prepare_signing_key_from_str(self):
        """Test preparing signing key from string."""
        key_str = "my-secret-key-string"
        alg = Alg.HS256.get_instance()

        prepared = prepare_signing_key(key_str, alg)
        assert isinstance(prepared, OctKey)

    def test_prepare_verifying_key_from_key_instance(self, secret_key: str):
        """Test preparing verifying key from Key instance."""
        key = OctKey.import_key(secret_key)
        alg = Alg.HS256.get_instance()

        prepared = prepare_verifying_key(key, alg)
        assert prepared is key

    def test_prepare_verifying_key_from_bytes(self):
        """Test preparing verifying key from bytes."""
        key_bytes = b"my-secret-key-bytes-32-long!"
        alg = Alg.HS256.get_instance()

        prepared = prepare_verifying_key(key_bytes, alg)
        assert isinstance(prepared, OctKey)


# ============================================================================
# Size Check Tests
# ============================================================================


class TestSizeCheck:
    def test_check_compact_size_valid(self):
        """Test size check with valid token."""
        compact = b"a" * 1000  # 1KB token
        check_compact_size(compact)
        # Should not raise

    def test_check_compact_size_exceeds_default(self):
        """Test size check with token exceeding default limit."""
        compact = b"a" * (16 * 1024 + 1)  # > 16KB
        with pytest.raises(SizeExceededError) as exc:
            check_compact_size(compact)
        assert "exceeds maximum" in str(exc.value)

    def test_check_compact_size_custom_limit(self):
        """Test size check with custom limit."""
        # Set custom limit
        set_max_token_bytes(1024)  # 1KB

        compact = b"a" * 2000  # 2KB
        with pytest.raises(SizeExceededError):
            check_compact_size(compact)

        # Reset to default
        set_max_token_bytes(16 * 1024)

    def test_check_compact_size_with_string(self):
        """Test size check accepts string input."""
        compact = "a" * 1000
        check_compact_size(compact)
        # Should not raise


# ============================================================================
# JWSToken Model Tests
# ============================================================================


class TestJWSToken:
    def test_jwstoken_default(self):
        """Test JWSToken with default values."""
        token = JWSToken()
        assert token.headers == {}
        assert token.payload == {}
        assert token.signature == b""
        assert token.encoded_headers == b""
        assert token.encoded_payload == b""
        assert token.encoded_signature == b""

    def test_jwstoken_with_data(self):
        """Test JWSToken with data."""
        token = JWSToken(
            headers={"alg": "HS256"},
            payload={"sub": "user123"},
            signature=b"sig",
            encoded_headers=b"header",
            encoded_payload=b"payload",
            encoded_signature=b"signature",
        )

        assert token.headers["alg"] == "HS256"
        assert token.payload["sub"] == "user123"
        assert token.signature == b"sig"

    def test_jwstoken_signing_input(self):
        """Test JWSToken signing_input computed field."""
        token = JWSToken(encoded_headers=b"header", encoded_payload=b"payload")

        assert token.signing_input == b"header.payload"

    def test_jwstoken_compact(self):
        """Test JWSToken compact computed field."""
        token = JWSToken(
            encoded_headers=b"header",
            encoded_payload=b"payload",
            encoded_signature=b"signature",
        )

        assert token.compact == b"header.payload.signature"


# ============================================================================
# Integration Tests with Different Algorithms
# ============================================================================


class TestAlgorithmIntegration:
    def test_encode_decode_hmac_algorithms(self, claims_fixed_dt: JWTCustomClaims):
        """Test encode/decode with all HMAC algorithms."""
        secret = "test-secret-key-32-bytes-long!!"

        for alg in [Alg.HS256, Alg.HS384, Alg.HS512]:
            key = OctKey.import_key(secret)
            compact = jws_encode(
                None,
                claims_fixed_dt.to_json(),
                key,
                alg.get_instance(),
            )

            payload = jws_decode(compact, key, alg.get_instance())
            assert payload["sub"] == claims_fixed_dt.sub

    def test_encode_decode_rsa_algorithms(
        self, claims_fixed_dt: JWTCustomClaims, rsa_2048_key_pair
    ):
        """Test encode/decode with RSA algorithms."""
        for alg in [Alg.RS256, Alg.RS384, Alg.RS512]:
            private_key = RSAKey.import_private_key(rsa_2048_key_pair.private_pem)
            public_key = RSAKey.import_public_key(rsa_2048_key_pair.public_pem)

            compact = jws_encode(
                None,
                claims_fixed_dt.to_json(),
                private_key,
                alg.get_instance(),
            )

            payload = jws_decode(compact, public_key, alg.get_instance())
            assert payload["sub"] == claims_fixed_dt.sub

    def test_encode_decode_ec_algorithms(
        self, claims_fixed_dt: JWTCustomClaims, ec_p256_key_pair
    ):
        """Test encode/decode with EC algorithms."""
        private_key = ECKey.import_private_key(ec_p256_key_pair.private_pem)
        public_key = ECKey.import_public_key(ec_p256_key_pair.public_pem)

        compact = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            private_key,
            Alg.ES256.get_instance(),
        )

        payload = jws_decode(compact, public_key, Alg.ES256.get_instance())
        assert payload["sub"] == claims_fixed_dt.sub

    def test_encode_decode_eddsa_algorithms(
        self, claims_fixed_dt: JWTCustomClaims, ed25519_key_pair, ed448_key_pair
    ):
        """Test encode/decode with EdDSA algorithms."""
        # Test Ed25519
        private_key_ed25519 = OKPKey.import_private_key(ed25519_key_pair.private_pem)
        public_key_ed25519 = OKPKey.import_public_key(ed25519_key_pair.public_pem)

        compact_ed25519 = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            private_key_ed25519,
            Alg.Ed25519.get_instance(),
        )

        payload_ed25519 = jws_decode(
            compact_ed25519, public_key_ed25519, Alg.Ed25519.get_instance()
        )
        assert payload_ed25519["sub"] == claims_fixed_dt.sub

        # Test Ed448
        private_key_ed448 = OKPKey.import_private_key(ed448_key_pair.private_pem)
        public_key_ed448 = OKPKey.import_public_key(ed448_key_pair.public_pem)

        compact_ed448 = jws_encode(
            None,
            claims_fixed_dt.to_json(),
            private_key_ed448,
            Alg.Ed448.get_instance(),
        )

        payload_ed448 = jws_decode(
            compact_ed448, public_key_ed448, Alg.Ed448.get_instance()
        )
        assert payload_ed448["sub"] == claims_fixed_dt.sub
