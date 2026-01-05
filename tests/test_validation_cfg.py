"""Tests for custom JWTValidationCfg usage in JWT operations."""

from datetime import datetime, timedelta

import pytest
from superjwt.definitions import (
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    JWTValidationCfg,
    Validation,
)
from superjwt.exceptions import ClaimsValidationError, TokenExpiredError
from superjwt.jwt import JWT


try:
    from datetime import UTC
except ImportError:
    from datetime import timezone

    UTC = timezone.utc


class CustomClaims(JWTClaims):
    """Custom claims with required fields for testing."""

    user_id: str
    role: str = "user"


class CustomHeader(JOSEHeader):
    """Custom header with additional fields for testing."""

    custom_field: str | None = None
    version: int = 1


# ============================================================================
# JWT Claims Validation Config Tests
# ============================================================================


def test_jwt_custom_validation_config_with_dict_data():
    """Test JWT encoding/decoding with custom validation config using dict data."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create custom validation config
    custom_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        enabled=True,
        jwtdatetime_force_int=False,  # Use float timestamps
    )

    # Test with dict data
    claims_dict = {
        "sub": "user123",
        "iat": datetime.now(UTC).timestamp(),
        "exp": (datetime.now(UTC) + timedelta(hours=1)).timestamp(),
    }

    # Encode with custom validation config
    token = jwt.encode(
        claims_dict, secret_key, "HS256", claims_validation=custom_validation
    )

    # Verify timestamps are floats (from custom config)
    decoded = jwt.decode(token.compact, secret_key, "HS256")
    assert isinstance(decoded.payload["iat"], float)
    assert isinstance(decoded.payload["exp"], float)


def test_jwt_custom_validation_config_with_pydantic_model():
    """Test JWT encoding/decoding with custom validation config using pydantic model."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create custom validation config with auto_validate disabled
    custom_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        auto_validate_pydantic_model=False,  # Don't auto-use the data's type
        enabled=True,
    )

    # Create CustomClaims instance
    claims = CustomClaims.model_construct(
        sub="user123",
        user_id="uid123",
        iat=datetime.now(UTC),
        exp=datetime.now(UTC) + timedelta(hours=1),
    )

    # Should validate against JWTClaims (not CustomClaims) because auto_validate is False
    token = jwt.encode(claims, secret_key, "HS256", claims_validation=custom_validation)
    assert token.compact is not None

    # Verify decoding works
    decoded = jwt.decode(token.compact, secret_key, "HS256")
    assert decoded.payload["sub"] == "user123"
    assert decoded.payload["user_id"] == "uid123"


def test_jwt_validation_config_disabled():
    """Test JWT with validation disabled via custom config."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create validation config with validation disabled
    no_validation = JWTValidationCfg(enabled=False)

    # Create invalid claims (invalid type for sub)
    invalid_claims = {"sub": 12345, "aud": ["audience1"]}  # sub should be string

    # Should succeed because validation is disabled
    token = jwt.encode(
        invalid_claims, secret_key, "HS256", claims_validation=no_validation
    )
    assert token.compact is not None

    # Decode also succeeds with validation disabled
    decoded = jwt.decode(
        token.compact, secret_key, "HS256", claims_validation=no_validation
    )
    assert decoded.payload["sub"] == 12345


def test_jwt_validation_config_with_custom_now():
    """Test JWT validation config with spoofed 'now' time."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create claims that are expired (beyond default leeway of 5 seconds)
    past_time = datetime.now(UTC) - timedelta(hours=2)
    claims = {
        "sub": "user123",
        "iat": past_time.timestamp(),
        "exp": (past_time + timedelta(hours=1)).timestamp(),  # Expired 1 hour ago
    }

    # Encode with validation disabled to create the token
    token = jwt.encode(claims, secret_key, "HS256", claims_validation=Validation.DISABLE)

    # Create validation config with spoofed 'now' set to past
    spoofed_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        now=past_time + timedelta(minutes=30),  # Within the validity period
    )

    # Should succeed because we spoofed the time to be within validity
    decoded = jwt.decode(
        token.compact, secret_key, "HS256", claims_validation=spoofed_validation
    )
    assert decoded.payload["sub"] == "user123"

    # Without spoofed time, should fail with strict validation (JWTClaims)
    strict_validation = JWTValidationCfg(validation_model=JWTClaims)
    with pytest.raises(TokenExpiredError):
        jwt.decode(
            token.compact, secret_key, "HS256", claims_validation=strict_validation
        )


def test_jwt_validation_config_with_custom_leeway():
    """Test JWT validation config with custom leeway."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create claims that are expired but within extended leeway
    now = datetime.now(UTC)
    claims = {
        "sub": "user123",
        "iat": (now - timedelta(seconds=25)).timestamp(),
        "exp": (now - timedelta(seconds=8)).timestamp(),  # Expired 8 seconds ago
    }

    # Encode with validation disabled
    token = jwt.encode(claims, secret_key, "HS256", claims_validation=Validation.DISABLE)

    # Default leeway (5 seconds) with JWTClaims validation should fail
    default_leeway_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        leeway=5.0,  # Default leeway - should NOT cover 8s expiration
    )
    with pytest.raises(TokenExpiredError):
        jwt.decode(
            token.compact,
            secret_key,
            "HS256",
            claims_validation=default_leeway_validation,
        )

    # Custom validation with larger leeway should succeed
    large_leeway_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        leeway=10.0,  # 10 seconds leeway - should cover 8s expiration
    )

    decoded = jwt.decode(
        token.compact, secret_key, "HS256", claims_validation=large_leeway_validation
    )
    assert decoded.payload["sub"] == "user123"


def test_jwt_validation_config_allow_future_iat():
    """Test JWT validation config with allow_future_iat parameter."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create claims with future iat (beyond default 5s leeway)
    now = datetime.now(UTC)
    future_time = now + timedelta(minutes=10)
    claims = {
        "sub": "user123",
        "iat": future_time.timestamp(),
        "exp": (future_time + timedelta(hours=1)).timestamp(),
    }

    # With allow_future_iat=True, encoding should succeed
    encode_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        allow_future_iat=True,  # Allow future iat
    )
    token = jwt.encode(claims, secret_key, "HS256", claims_validation=encode_validation)

    # Decoding with allow_future_iat=True should also succeed
    decoded = jwt.decode(
        token.compact, secret_key, "HS256", claims_validation=encode_validation
    )
    assert decoded.payload["sub"] == "user123"

    # Default validation (allow_future_iat=False) should fail
    strict_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        allow_future_iat=False,  # Disallow future iat (default)
    )

    with pytest.raises(ClaimsValidationError):  # ValidationError for future iat
        jwt.decode(
            token.compact, secret_key, "HS256", claims_validation=strict_validation
        )


def test_jwt_validation_config_combine_multiple_params():
    """Test JWT validation config with multiple custom parameters combined."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create claims in the past with float timestamps
    past_time = datetime.now(UTC) - timedelta(hours=1)
    claims_dict = {
        "sub": "user123",
        "iat": past_time.timestamp(),
        "exp": (past_time + timedelta(minutes=30)).timestamp(),  # Expired 30 min ago
    }

    # Encode with custom validation config (validation disabled to allow expired claims)
    encode_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        jwtdatetime_force_int=False,  # Use float timestamps
        enabled=False,  # Disable validation to allow creating expired token
    )

    token = jwt.encode(
        claims_dict, secret_key, "HS256", claims_validation=encode_validation
    )

    # Verify float timestamps
    decoded = jwt.decode(
        token.compact, secret_key, "HS256", claims_validation=Validation.DISABLE
    )
    assert isinstance(decoded.payload["iat"], float)
    assert isinstance(decoded.payload["exp"], float)

    # Decode with custom validation (spoofed time + large leeway)
    decode_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        now=past_time + timedelta(minutes=15),  # Spoof to within validity
        leeway=20.0,  # Large leeway
        allow_future_iat=False,
    )

    decoded2 = jwt.decode(
        token.compact, secret_key, "HS256", claims_validation=decode_validation
    )
    assert decoded2.payload["sub"] == "user123"


# ============================================================================
# JWT Headers Validation Config Tests (via JWT)
# ============================================================================


def test_jwt_custom_headers_validation_config_with_dict():
    """Test JWT with custom headers validation config using dict headers."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create custom validation config for headers
    custom_headers_validation = JWTValidationCfg(
        validation_model=JOSEHeader,
        enabled=True,
    )

    # Test with dict headers
    headers_dict = {"alg": "HS256", "typ": "JWT", "kid": "key-123"}
    claims = {"sub": "user123"}

    # Encode with custom headers validation config
    token = jwt.encode(
        claims,
        secret_key,
        "HS256",
        headers=headers_dict,
        headers_validation=custom_headers_validation,
    )

    # Decode and verify
    decoded = jwt.decode(
        token.compact,
        secret_key,
        "HS256",
        headers_validation=custom_headers_validation,
    )
    assert decoded.headers["kid"] == "key-123"


def test_jwt_custom_headers_validation_config_with_pydantic():
    """Test JWT with custom headers validation config using pydantic headers."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create custom validation config with auto_validate disabled
    custom_validation = JWTValidationCfg(
        validation_model=JOSEHeader,
        auto_validate_pydantic_model=False,
    )

    # Create CustomHeader instance
    headers = CustomHeader(alg="HS256", custom_field="test-value", version=2)
    claims = {"sub": "user123"}

    # Encode with custom validation (validates against JOSEHeader, not CustomHeader)
    token = jwt.encode(
        claims,
        secret_key,
        "HS256",
        headers=headers,
        headers_validation=custom_validation,
    )

    # Decode and verify custom fields are preserved
    decoded = jwt.decode(
        token.compact, secret_key, "HS256", headers_validation=Validation.DISABLE
    )
    assert decoded.headers["custom_field"] == "test-value"
    assert decoded.headers["version"] == 2


def test_jwt_headers_validation_config_disabled():
    """Test JWT with headers validation disabled via custom config."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create validation config with validation disabled
    no_validation = JWTValidationCfg(enabled=False)

    # Create headers with non-standard fields
    custom_headers = {"alg": "HS256", "typ": "JWT", "custom": "value"}
    claims = {"sub": "user123"}

    # Should succeed because validation is disabled
    token = jwt.encode(
        claims,
        secret_key,
        "HS256",
        headers=custom_headers,
        headers_validation=no_validation,
    )
    assert token.compact is not None

    # Decode also succeeds with validation disabled
    decoded = jwt.decode(
        token.compact, secret_key, "HS256", headers_validation=no_validation
    )
    assert decoded.headers["custom"] == "value"


# ============================================================================
# Integration Tests - JWT with Custom Validation Configs
# ============================================================================


def test_jwt_encode_decode_different_validation_configs():
    """Test JWT with different validation configs for encode and decode."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Encode with relaxed validation (float timestamps)
    encode_config = JWTValidationCfg(
        validation_model=JWTClaims,
        jwtdatetime_force_int=False,
        leeway=5.0,
    )

    claims = JWTClaims(
        sub="user123",
        iat=datetime.now(UTC),
        exp=datetime.now(UTC) + timedelta(hours=1),
    )

    token = jwt.encode(claims, secret_key, "HS256", claims_validation=encode_config)

    # Decode with strict validation (int timestamps, smaller leeway)
    decode_config = JWTValidationCfg(
        validation_model=JWTClaims,
        jwtdatetime_force_int=True,
        leeway=2.0,
    )

    # Should still decode successfully
    decoded = jwt.decode(
        token.compact, secret_key, "HS256", claims_validation=decode_config
    )
    assert decoded.payload["sub"] == "user123"


def test_jwt_validation_config_does_not_mutate_default():
    """Test that using custom validation config doesn't mutate JWT default config."""
    # Create JWT with specific default validation
    default_config = JWTValidationCfg(
        validation_model=JWTBaseModel,
        jwtdatetime_force_int=True,
        leeway=5.0,
    )
    jwt = JWT(default_claims_validation=default_config)
    secret_key = "test-secret-key-32-bytes-long!!"

    # Use different validation config for encoding
    custom_config = JWTValidationCfg(
        validation_model=JWTClaims,
        jwtdatetime_force_int=False,
        leeway=10.0,
    )

    claims = {"sub": "user123", "iat": datetime.now(UTC).timestamp()}
    jwt.encode(claims, secret_key, "HS256", claims_validation=custom_config)

    # Verify the default config wasn't mutated
    assert jwt.default_claims_validation.validation_model == JWTBaseModel
    assert jwt.default_claims_validation.jwtdatetime_force_int is True
    assert jwt.default_claims_validation.leeway == 5.0

    # Subsequent operations should use default config
    claims2 = JWTClaims(sub="user456", iat=datetime.now(UTC))
    token2 = jwt.encode(claims2, secret_key, "HS256")  # Uses default

    decoded = jwt.decode(
        token2.compact, secret_key, "HS256", claims_validation=Validation.DISABLE
    )
    # Should have int timestamps (from default config)
    assert isinstance(decoded.payload["iat"], int)


def test_jwt_validation_config_overrides_model_internal_values():
    """Test that validation config's internal values override model's internal values."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create a JWTClaims instance with future iat
    future_time = datetime.now(UTC) + timedelta(minutes=10)
    claims = JWTClaims.model_construct(
        sub="user123",
        iat=future_time,
        exp=future_time + timedelta(hours=1),
    )

    # Set model's internal values to allow future iat
    claims.allow_future_iat()
    claims.set_leeway(15.0)  # Large leeway

    # Create validation config that should OVERRIDE model's settings
    strict_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        allow_future_iat=False,  # Override: disallow future iat
        leeway=5.0,  # Override: smaller leeway
        auto_validate_pydantic_model=True,
    )

    # Encoding should fail because config's allow_future_iat=False overrides model's True
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, "HS256", claims_validation=strict_validation)

    # Now test with permissive config that allows future iat
    permissive_validation = JWTValidationCfg(
        validation_model=JWTClaims,
        allow_future_iat=True,  # Allow future iat
        leeway=20.0,
        auto_validate_pydantic_model=True,
    )

    # This should succeed because config overrides model
    token = jwt.encode(
        claims, secret_key, "HS256", claims_validation=permissive_validation
    )
    assert token.compact is not None
