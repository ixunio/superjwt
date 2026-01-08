"""Tests for custom JWTValidation usage in JWT operations."""

from datetime import datetime, timedelta

import pytest
from pydantic import Field
from superjwt.definitions import (
    Alg,
    JOSEHeader,
    JWTBaseModel,
    JWTClaims,
    JWTValidation,
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


class ModelA(JWTClaims):
    """First pydantic model for testing - requires field_a."""

    field_a: str = Field(default=...)  # Required field


class ModelB(JWTClaims):
    """Second pydantic model for testing - requires field_b."""

    field_b: str = Field(default=...)  # Required field


# ============================================================================
# JWT Claims Validation Config Tests
# ============================================================================


def test_jwtvalidation_all_combinations(secret_key):
    """Test all 8 combinations of data type, forward_pydantic_model, and validation_model.

    Outcomes:
    | Case | Data Type | Forward | Validation Model | Expected Validation Against |
    |------|-----------|---------|------------------|----------------------------|
    | 1    | Pydantic  | True    | None            | Data's type (forwarded)    |
    | 2    | Pydantic  | True    | Set             | Explicit model (NOT forwarded) |
    | 3    | Pydantic  | False   | None            | ERROR: No model            |
    | 4    | Pydantic  | False   | Set             | Explicit model             |
    | 5    | Dict      | True    | None            | ERROR: No model            |
    | 6    | Dict      | True    | Set             | Explicit model             |
    | 7    | Dict      | False   | None            | ERROR: No model            |
    | 8    | Dict      | False   | Set             | Explicit model             |
    """

    jwt = JWT()
    now = datetime.now(UTC)

    # ========================================================================
    # Case 1: data=pydantic (ModelA), forward=True, validation_model=None
    # ========================================================================
    # Expected: Should validate against ModelA (forwarded from data)
    # Result: field_a is required, should pass when present, fail when absent

    validation_1 = JWTValidation(
        validation_model=None,
        forward_pydantic_model=True,
    )

    data_1_valid = ModelA(field_a="value_a", iat=now, exp=now + timedelta(hours=1))
    # Should succeed - validates against ModelA which has field_a
    token_1 = jwt.encode(
        data_1_valid, secret_key, Alg.HS256, claims_validation=validation_1
    )
    assert token_1.model.claims is not None

    data_1_invalid = ModelA.model_construct(
        # field_a missing (required by ModelA)
        iat=now,
        exp=now + timedelta(hours=1),
    )
    # Should fail - field_a is required by ModelA
    with pytest.raises(ClaimsValidationError):
        jwt.encode(data_1_invalid, secret_key, Alg.HS256, claims_validation=validation_1)

    # ========================================================================
    # Case 2: data=pydantic (ModelA), forward=True, validation_model=ModelB
    # ========================================================================
    # Expected: Should validate against ModelB (explicitly set, overrides forward)
    # Note: In the fixed implementation, explicit validation_model should NOT be
    # overridden even when forward=True

    validation_2 = JWTValidation(
        validation_model=ModelB,
        forward_pydantic_model=True,
    )

    data_2_with_field_b = ModelA.model_construct(
        field_a="value_a",
        field_b="value_b",  # ModelB requires this
        iat=now,
        exp=now + timedelta(hours=1),
    )
    # Should succeed - validates against ModelB which has field_b
    token_2 = jwt.encode(
        data_2_with_field_b, secret_key, Alg.HS256, claims_validation=validation_2
    )
    assert token_2.model.claims is not None

    data_2_without_field_b = ModelA(
        field_a="value_a",
        # field_b missing (required by ModelB)
        iat=now,
        exp=now + timedelta(hours=1),
    )
    # Should fail - field_b is required by ModelB
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            data_2_without_field_b, secret_key, Alg.HS256, claims_validation=validation_2
        )

    # ========================================================================
    # Case 3: data=pydantic (ModelA), forward=False, validation_model=None
    # ========================================================================
    # Expected: Should fail because validation_model is None and not forwarded
    # This is an invalid configuration

    validation_3 = JWTValidation(
        validation_model=None,
        forward_pydantic_model=False,
    )

    data_3 = ModelA(field_a="value_a", iat=now, exp=now + timedelta(hours=1))
    # Should fail - no validation model to use
    with pytest.raises(ValueError, match="Validation model is not set"):
        jwt.encode(data_3, secret_key, Alg.HS256, claims_validation=validation_3)

    # ========================================================================
    # Case 4: data=pydantic (ModelA), forward=False, validation_model=ModelB
    # ========================================================================
    # Expected: Should validate against ModelB (explicitly set, forward disabled)

    validation_4 = JWTValidation(
        validation_model=ModelB,
        forward_pydantic_model=False,
    )

    data_4_with_field_b = ModelA.model_construct(
        field_a="value_a",
        field_b="value_b",  # ModelB requires this
        iat=now,
        exp=now + timedelta(hours=1),
    )
    # Should succeed - validates against ModelB which has field_b
    token_4 = jwt.encode(
        data_4_with_field_b, secret_key, Alg.HS256, claims_validation=validation_4
    )
    assert token_4.model.claims is not None

    data_4_without_field_b = ModelA(
        field_a="value_a",
        # field_b missing (required by ModelB)
        iat=now,
        exp=now + timedelta(hours=1),
    )
    # Should fail - field_b is required by ModelB
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            data_4_without_field_b, secret_key, Alg.HS256, claims_validation=validation_4
        )

    # ========================================================================
    # Case 5: data=dict, forward=True, validation_model=None
    # ========================================================================
    # Expected: Should fail because validation_model is None and dict has no type to forward

    validation_5 = JWTValidation(
        validation_model=None,
        forward_pydantic_model=True,
    )

    data_5 = {
        "field_a": "value_a",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    # Should fail - no validation model to use (can't forward from dict)
    with pytest.raises(ValueError, match="Validation model is not set"):
        jwt.encode(data_5, secret_key, Alg.HS256, claims_validation=validation_5)

    # ========================================================================
    # Case 6: data=dict, forward=True, validation_model=ModelA
    # ========================================================================
    # Expected: Should validate against ModelA (explicitly set)

    validation_6 = JWTValidation(
        validation_model=ModelA,
        forward_pydantic_model=True,
    )

    data_6_with_field_a = {
        "field_a": "value_a",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    # Should succeed - validates against ModelA which has field_a
    token_6 = jwt.encode(
        data_6_with_field_a, secret_key, Alg.HS256, claims_validation=validation_6
    )
    assert token_6.model.claims is not None

    data_6_without_field_a = {
        # field_a missing (required by ModelA)
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    # Should fail - field_a is required by ModelA
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            data_6_without_field_a, secret_key, Alg.HS256, claims_validation=validation_6
        )

    # ========================================================================
    # Case 7: data=dict, forward=False, validation_model=None
    # ========================================================================
    # Expected: Should fail because validation_model is None

    validation_7 = JWTValidation(
        validation_model=None,
        forward_pydantic_model=False,
    )

    data_7 = {
        "field_a": "value_a",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    # Should fail - no validation model to use
    with pytest.raises(ValueError, match="Validation model is not set"):
        jwt.encode(data_7, secret_key, Alg.HS256, claims_validation=validation_7)

    # ========================================================================
    # Case 8: data=dict, forward=False, validation_model=ModelB
    # ========================================================================
    # Expected: Should validate against ModelB (explicitly set)

    validation_8 = JWTValidation(
        validation_model=ModelB,
        forward_pydantic_model=False,
    )

    data_8_with_field_b = {
        "field_b": "value_b",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    # Should succeed - validates against ModelB which has field_b
    token_8 = jwt.encode(
        data_8_with_field_b, secret_key, Alg.HS256, claims_validation=validation_8
    )
    assert token_8.model.claims is not None

    data_8_without_field_b = {
        # field_b missing (required by ModelB)
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    # Should fail - field_b is required by ModelB
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            data_8_without_field_b, secret_key, Alg.HS256, claims_validation=validation_8
        )


def test_no_validation_model_set(secret_key):
    """Test that JWTValidation raises error if no validation model is set."""
    cfg = JWTValidation()
    jwt = JWT()
    with pytest.raises(ValueError, match="Validation model is not set in JWTValidation"):
        jwt.encode(
            {}, secret_key, Alg.HS256, claims_validation=cfg
        )  # Should work with default config


def test_jwt_custom_validation_config_with_dict_data():
    """Test JWT encoding/decoding with custom validation config using dict data."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create custom validation config
    custom_validation = JWTValidation(
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
        claims_dict, secret_key, Alg.HS256, claims_validation=custom_validation
    )

    # Verify timestamps are floats (from custom config)
    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)
    assert isinstance(decoded.payload["iat"], float)
    assert isinstance(decoded.payload["exp"], float)


def test_jwt_custom_validation_config_with_pydantic_model():
    """Test JWT encoding/decoding with custom validation config using pydantic model."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    custom_validation = JWTValidation(
        validation_model=JWTClaims,
        enabled=True,
    )

    claims = CustomClaims.model_construct(
        sub="user123",
        user_id="uid123",
        iat=datetime.now(UTC),
        exp=datetime.now(UTC) + timedelta(hours=1),
    )

    # Should validate against JWTClaims (not CustomClaims)
    token = jwt.encode(claims, secret_key, Alg.HS256, claims_validation=custom_validation)
    assert token.compact is not None

    decoded = jwt.decode(token.compact, secret_key, Alg.HS256)
    assert decoded.payload["sub"] == "user123"
    assert decoded.payload["user_id"] == "uid123"


def test_jwt_custom_validation_config_with_no_validation_model():
    """Test JWT encoding/decoding with custom validation config using pydantic model."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    custom_validation = JWTValidation(
        validation_model=None,
    )

    claims = CustomClaims.model_construct(
        sub="user123",
        user_id=123,
        iat=datetime.now(UTC),
        exp=datetime.now(UTC) + timedelta(hours=1),
    )

    # Should validate against CustomClaims since no model is set in config
    # and forward_pydantic_model is True by default
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256, claims_validation=custom_validation)

    custom_validation = JWTValidation(
        validation_model=None,
        forward_pydantic_model=False,
    )

    # no validation model set and forwarding disabled - should fails
    with pytest.raises(ValueError, match="Validation model is not set in JWTValidation"):
        jwt.encode(claims, secret_key, Alg.HS256, claims_validation=custom_validation)


def test_jwt_validation_config_disabled():
    """Test JWT with validation disabled via custom config."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create validation config with validation disabled
    no_validation = JWTValidation(enabled=False)

    # Create invalid claims (invalid type for sub)
    invalid_claims = {"sub": 12345, "aud": ["audience1"]}  # sub should be string

    # Should succeed because validation is disabled
    token = jwt.encode(
        invalid_claims, secret_key, Alg.HS256, claims_validation=no_validation
    )
    assert token.compact is not None

    # Decode also succeeds with validation disabled
    decoded = jwt.decode(
        token.compact, secret_key, Alg.HS256, claims_validation=no_validation
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
    token = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )

    # Create validation config with spoofed 'now' set to past
    spoofed_validation = JWTValidation(
        validation_model=JWTClaims,
        now=past_time + timedelta(minutes=30),  # Within the validity period
    )

    # Should succeed because we spoofed the time to be within validity
    decoded = jwt.decode(
        token.compact, secret_key, Alg.HS256, claims_validation=spoofed_validation
    )
    assert decoded.payload["sub"] == "user123"

    # Without spoofed time, should fail with strict validation (JWTClaims)
    strict_validation = JWTValidation(validation_model=JWTClaims)
    with pytest.raises(TokenExpiredError):
        jwt.decode(
            token.compact, secret_key, Alg.HS256, claims_validation=strict_validation
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
    token = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )

    # Default leeway (5 seconds) with JWTClaims validation should fail
    default_leeway_validation = JWTValidation(
        validation_model=JWTClaims,
        leeway=5.0,  # Default leeway - should NOT cover 8s expiration
    )
    with pytest.raises(TokenExpiredError):
        jwt.decode(
            token.compact,
            secret_key,
            Alg.HS256,
            claims_validation=default_leeway_validation,
        )

    # Custom validation with larger leeway should succeed
    large_leeway_validation = JWTValidation(
        validation_model=JWTClaims,
        leeway=10.0,  # 10 seconds leeway - should cover 8s expiration
    )

    decoded = jwt.decode(
        token.compact, secret_key, Alg.HS256, claims_validation=large_leeway_validation
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
    encode_validation = JWTValidation(
        validation_model=JWTClaims,
        allow_future_iat=True,  # Allow future iat
    )
    token = jwt.encode(claims, secret_key, Alg.HS256, claims_validation=encode_validation)

    # Decoding with allow_future_iat=True should also succeed
    decoded = jwt.decode(
        token.compact, secret_key, Alg.HS256, claims_validation=encode_validation
    )
    assert decoded.payload["sub"] == "user123"

    # Default validation (allow_future_iat=False) should fail
    strict_validation = JWTValidation(
        validation_model=JWTClaims,
        allow_future_iat=False,  # Disallow future iat (default)
    )

    with pytest.raises(ClaimsValidationError):  # ValidationError for future iat
        jwt.decode(
            token.compact, secret_key, Alg.HS256, claims_validation=strict_validation
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
    encode_validation = JWTValidation(
        validation_model=JWTClaims,
        jwtdatetime_force_int=False,  # Use float timestamps
        enabled=False,  # Disable validation to allow creating expired token
    )

    token = jwt.encode(
        claims_dict, secret_key, Alg.HS256, claims_validation=encode_validation
    )

    # Verify float timestamps
    decoded = jwt.decode(
        token.compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )
    assert isinstance(decoded.payload["iat"], float)
    assert isinstance(decoded.payload["exp"], float)

    # Decode with custom validation (spoofed time + large leeway)
    decode_validation = JWTValidation(
        validation_model=JWTClaims,
        now=past_time + timedelta(minutes=15),  # Spoof to within validity
        leeway=20.0,  # Large leeway
        allow_future_iat=False,
    )

    decoded2 = jwt.decode(
        token.compact, secret_key, Alg.HS256, claims_validation=decode_validation
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
    custom_headers_validation = JWTValidation(
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
        Alg.HS256,
        headers=headers_dict,
        headers_validation=custom_headers_validation,
    )

    # Decode and verify
    decoded = jwt.decode(
        token.compact,
        secret_key,
        Alg.HS256,
        headers_validation=custom_headers_validation,
    )
    assert decoded.headers["kid"] == "key-123"


def test_jwt_custom_headers_validation_config_with_pydantic():
    """Test JWT with custom headers validation config using pydantic headers."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    custom_validation = JWTValidation(
        validation_model=JOSEHeader,
    )

    headers = CustomHeader(alg="HS256", custom_field="test-value", version=2)
    claims = {"sub": "user123"}

    # Encode with custom validation (validates against JOSEHeader, not CustomHeader)
    token = jwt.encode(
        claims,
        secret_key,
        Alg.HS256,
        headers=headers,
        headers_validation=custom_validation,
    )

    # Decode and verify custom fields are preserved
    decoded = jwt.decode(
        token.compact, secret_key, Alg.HS256, headers_validation=Validation.DISABLE
    )
    assert decoded.headers["custom_field"] == "test-value"
    assert decoded.headers["version"] == 2


def test_jwt_headers_validation_config_disabled():
    """Test JWT with headers validation disabled via custom config."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create validation config with validation disabled
    no_validation = JWTValidation(enabled=False)

    # Create headers with non-standard fields
    custom_headers = {"alg": "HS256", "typ": "JWT", "custom": "value"}
    claims = {"sub": "user123"}

    # Should succeed because validation is disabled
    token = jwt.encode(
        claims,
        secret_key,
        Alg.HS256,
        headers=custom_headers,
        headers_validation=no_validation,
    )
    assert token.compact is not None

    # Decode also succeeds with validation disabled
    decoded = jwt.decode(
        token.compact, secret_key, Alg.HS256, headers_validation=no_validation
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
    encode_config = JWTValidation(
        validation_model=JWTClaims,
        jwtdatetime_force_int=False,
        leeway=5.0,
    )

    claims = JWTClaims(
        sub="user123",
        iat=datetime.now(UTC),
        exp=datetime.now(UTC) + timedelta(hours=1),
    )

    token = jwt.encode(claims, secret_key, Alg.HS256, claims_validation=encode_config)

    # Decode with strict validation (int timestamps, smaller leeway)
    decode_config = JWTValidation(
        validation_model=JWTClaims,
        jwtdatetime_force_int=True,
        leeway=2.0,
    )

    # Should still decode successfully
    decoded = jwt.decode(
        token.compact, secret_key, Alg.HS256, claims_validation=decode_config
    )
    assert decoded.payload["sub"] == "user123"


def test_jwt_validation_config_does_not_mutate_default():
    """Test that using custom validation config doesn't mutate JWT default config."""
    # Create JWT with specific default validation
    default_config = JWTValidation(
        validation_model=JWTBaseModel,
        jwtdatetime_force_int=True,
        leeway=5.0,
    )
    jwt = JWT(default_claims_validation=default_config)
    secret_key = "test-secret-key-32-bytes-long!!"

    # Use different validation config for encoding
    custom_config = JWTValidation(
        validation_model=JWTClaims,
        jwtdatetime_force_int=False,
        leeway=10.0,
    )

    claims = {"sub": "user123", "iat": datetime.now(UTC).timestamp()}
    jwt.encode(claims, secret_key, Alg.HS256, claims_validation=custom_config)

    # Verify the default config wasn't mutated
    assert jwt.default_claims_validation.validation_model == JWTBaseModel
    assert jwt.default_claims_validation.jwtdatetime_force_int is True
    assert jwt.default_claims_validation.leeway == 5.0

    # Subsequent operations should use default config
    claims2 = JWTClaims(sub="user456", iat=datetime.now(UTC))
    token2 = jwt.encode(claims2, secret_key, Alg.HS256)  # Uses default

    decoded = jwt.decode(
        token2.compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
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

    # Create validation config that should OVERRIDE model's settings
    strict_validation = JWTValidation(
        validation_model=JWTClaims,
        allow_future_iat=False,  # Override: disallow future iat
    )

    # Encoding should fail because config's allow_future_iat=False overrides model's True
    with pytest.raises(ClaimsValidationError):
        jwt.encode(claims, secret_key, Alg.HS256, claims_validation=strict_validation)

    # Now test with permissive config that allows future iat
    permissive_validation = JWTValidation(
        validation_model=JWTClaims,
        allow_future_iat=True,  # Allow future iat
    )

    # This should succeed because config overrides model
    token = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=permissive_validation
    )
    assert token.compact is not None


def test_validation_config_inherits_none_values_from_model():
    """Test that validation config inherits values from model only when config values are None."""
    jwt = JWT()
    secret_key = "test-secret-key-32-bytes-long!!"

    # Create a JWTClaims instance with custom internal values
    past_time = datetime.now(UTC) - timedelta(hours=1)
    claims = JWTClaims.model_construct(
        sub="user123",
        iat=past_time,
        exp=past_time + timedelta(hours=1),
    )

    # Set model's internal values
    claims.set_leeway(20.0)
    claims.allow_future_iat()
    claims.force_jwtdatetime_to_float()
    custom_now = past_time + timedelta(minutes=30)
    claims.spoof_time(custom_now)

    # Create validation config with ALL values as None (should inherit from model)
    inherit_validation = JWTValidation(
        validation_model=JWTClaims,
        leeway=None,  # Should inherit 20.0 from model
        allow_future_iat=None,  # Should inherit True from model
        jwtdatetime_force_int=None,  # Should inherit False from model
        now=None,  # Should inherit custom_now from model
    )

    # Encoding should succeed using model's inherited values
    token = jwt.encode(
        claims, secret_key, Alg.HS256, claims_validation=inherit_validation
    )
    assert token.compact is not None

    # Verify that config inherited model's values by checking the config after apply_internal_cfg
    validation_copy = inherit_validation.model_copy(deep=True)
    validation_copy.apply_internal_cfg(claims)

    assert validation_copy.leeway == 20.0
    assert validation_copy.allow_future_iat is True
    assert validation_copy.jwtdatetime_force_int is False
    assert validation_copy.now == custom_now


def test_validation_config_does_not_override_set_values():
    """Test that validation config does NOT override its own set values with model values."""
    # Create a JWTClaims instance with one set of internal values
    past_time = datetime.now(UTC) - timedelta(hours=1)
    claims = JWTClaims.model_construct(
        sub="user123",
        iat=past_time,
        exp=past_time + timedelta(hours=1),
    )

    # Set model's internal values
    claims.set_leeway(100.0)  # Very large leeway
    claims.allow_future_iat()  # Allow future
    claims.force_jwtdatetime_to_float()  # Float timestamps
    model_now = past_time + timedelta(minutes=15)
    claims.spoof_time(model_now)

    # Create validation config with DIFFERENT set values (should NOT be overridden)
    override_validation = JWTValidation(
        validation_model=JWTClaims,
        leeway=4.0,  # Should NOT be overridden by model's 100.0
        allow_future_iat=False,  # Should NOT be overridden by model's True
        jwtdatetime_force_int=True,  # Should NOT be overridden by model's False
        now=past_time + timedelta(minutes=30),  # Should NOT be overridden by model's now
    )

    # Apply internal config to see what happens
    validation_copy = override_validation.model_copy(deep=True)
    validation_copy.apply_internal_cfg(claims)

    # Verify that config's values were NOT overridden by model's values
    assert validation_copy.leeway == 4.0  # NOT 100.0
    assert validation_copy.allow_future_iat is False  # NOT True
    assert validation_copy.jwtdatetime_force_int is True  # NOT False
    assert validation_copy.now == past_time + timedelta(minutes=30)  # NOT model_now


def test_validation_config_mixed_none_and_set_values():
    """Test that validation config correctly handles mix of None and set values."""
    # Create a JWTClaims instance with custom internal values
    past_time = datetime.now(UTC) - timedelta(hours=1)
    claims = JWTClaims.model_construct(
        sub="user123",
        iat=past_time,
        exp=past_time + timedelta(hours=1),
    )

    # Set model's internal values
    claims.set_leeway(50.0)
    claims.allow_future_iat()
    claims.force_jwtdatetime_to_float()
    model_now = past_time + timedelta(minutes=20)
    claims.spoof_time(model_now)

    # Create validation config with MIXED values (some None, some set)
    mixed_validation = JWTValidation(
        validation_model=JWTClaims,
        leeway=10.0,  # SET - should NOT be overridden
        allow_future_iat=None,  # NONE - should inherit True from model
        jwtdatetime_force_int=True,  # SET - should NOT be overridden
        now=None,  # NONE - should inherit model_now from model
    )

    # Apply internal config
    validation_copy = mixed_validation.model_copy(deep=True)
    validation_copy.apply_internal_cfg(claims)

    # Verify mixed behavior
    assert validation_copy.leeway == 10.0  # Used config's value (NOT model's 50.0)
    assert validation_copy.allow_future_iat is True  # Inherited from model
    assert (
        validation_copy.jwtdatetime_force_int is True
    )  # Used config's value (NOT model's False)
    assert validation_copy.now == model_now  # Inherited from model


def test_validation_config_none_values_use_defaults_when_no_model():
    """Test that validation config uses default values when values are None and no model is provided."""
    from superjwt.definitions import (
        DEFAULT_ALLOW_FUTURE_IAT,
        DEFAULT_JWTDATETIME_FORCE_INT,
        DEFAULT_LEEWAY_SECONDS,
    )

    # Create validation config with all None values
    config = JWTValidation(
        validation_model=JWTClaims,
        leeway=None,
        allow_future_iat=None,
        jwtdatetime_force_int=None,
        now=None,
    )

    # Apply internal config WITHOUT a model (should use defaults)
    config.apply_internal_cfg(model=None)

    # Verify default values were applied
    assert config.leeway == DEFAULT_LEEWAY_SECONDS  # 5.0
    assert config.allow_future_iat == DEFAULT_ALLOW_FUTURE_IAT  # False
    assert config.jwtdatetime_force_int == DEFAULT_JWTDATETIME_FORCE_INT  # True
    assert config.now is None  # Default for 'now' is None


def test_validation_config_partial_inheritance_from_incompatible_model():
    """Test that validation config only inherits values for compatible model types."""
    # Create a JWTBaseModel instance (NOT JWTClaims)
    base_claims = JWTBaseModel()
    base_claims.force_jwtdatetime_to_float()
    custom_now = datetime.now(UTC) - timedelta(hours=1)
    base_claims.spoof_time(custom_now)

    # Create validation config targeting JWTClaims with all None values
    config = JWTValidation(
        validation_model=JWTClaims,
        leeway=None,
        allow_future_iat=None,
        jwtdatetime_force_int=None,
        now=None,
    )

    # Apply internal config from JWTBaseModel
    config.apply_internal_cfg(base_claims)

    # JWTBaseModel parameters should be inherited
    assert config.jwtdatetime_force_int is False  # Inherited from base_claims
    assert config.now == custom_now  # Inherited from base_claims

    # JWTClaims-specific parameters remain None (base_claims doesn't have them
    # and model is not None, so defaults are not applied)
    assert config.leeway is None  # Stays None (not default, not from model)
    assert config.allow_future_iat is None  # Stays None (not default, not from model)


def test_default_vs_custom_validation():
    """Test the difference between Validation.DEFAULT and custom validation configs.

    Key differences:
    1. Validation.DEFAULT uses JWT's default_claims_validation
    2. Custom validation uses explicitly provided configuration
    3. DEFAULT with pydantic data forwards the model type when forward_pydantic_model=True
    """
    secret_key = "test-secret-key-32-bytes-long!!"
    now = datetime.now(UTC)

    # ========================================================================
    # Setup: Create JWT with custom default validation
    # ========================================================================
    custom_default_validation = JWTValidation(
        validation_model=JWTBaseModel,  # Very permissive
        forward_pydantic_model=True,  # Will forward pydantic model types
        leeway=10.0,  # Large leeway
        jwtdatetime_force_int=True,  # Use int timestamps
    )

    jwt = JWT(default_claims_validation=custom_default_validation)

    # ========================================================================
    # Test 1: Validation.DEFAULT forwards pydantic model type
    # ========================================================================

    # Create claims with ModelA that's missing required field_a
    invalid_claims_a = ModelA.model_construct(
        iat=now,
        exp=now + timedelta(hours=1),
        # field_a is missing - ModelA requires it
    )

    # With Validation.DEFAULT: Should validate against ModelA (forwarded) and fail
    with pytest.raises(ClaimsValidationError):
        jwt.encode(
            invalid_claims_a, secret_key, Alg.HS256, claims_validation=Validation.DEFAULT
        )

    # ========================================================================
    # Test 2: Custom validation uses explicit model, NOT forwarded type
    # ========================================================================

    # Use custom validation that explicitly sets validation_model=JWTBaseModel
    explicit_validation = JWTValidation(
        validation_model=JWTBaseModel,  # Explicit - won't be overridden
        forward_pydantic_model=True,  # This doesn't matter for explicit model
    )

    # Same invalid data, but with explicit validation against JWTBaseModel
    # Should succeed because JWTBaseModel is permissive (doesn't require field_a)
    token = jwt.encode(
        invalid_claims_a, secret_key, Alg.HS256, claims_validation=explicit_validation
    )
    assert token.compact is not None

    # ========================================================================
    # Test 3: Validation.DEFAULT uses JWT's default config values
    # ========================================================================

    # Create claims with slightly expired timestamp (within 10s leeway)
    expired_claims = {
        "sub": "user123",
        "iat": (now - timedelta(seconds=15)).timestamp(),
        "exp": (now - timedelta(seconds=7)).timestamp(),  # Expired 7 seconds ago
    }

    # Encode with validation disabled to create the token
    token_expired = jwt.encode(
        expired_claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
    )

    # Decode with Validation.DEFAULT: Should succeed because default leeway is 10.0s
    decoded = jwt.decode(
        token_expired.compact, secret_key, Alg.HS256, claims_validation=Validation.DEFAULT
    )
    assert decoded.payload["sub"] == "user123"

    # ========================================================================
    # Test 4: Custom validation uses its own config values
    # ========================================================================

    # Use custom validation with smaller leeway
    strict_validation = JWTValidation(
        validation_model=JWTClaims,
        leeway=5.0,  # Smaller leeway - won't cover 7s expiration
    )

    # Decode with custom validation: Should fail because leeway is only 5s
    with pytest.raises(TokenExpiredError):
        jwt.decode(
            token_expired.compact,
            secret_key,
            Alg.HS256,
            claims_validation=strict_validation,
        )

    # ========================================================================
    # Test 5: Validation.DEFAULT with pydantic data uses default config
    # ========================================================================

    # Use pydantic model with default validation
    claims_with_extra = JWTClaims(
        sub="user123",
        iat=now,
        exp=now + timedelta(hours=1),
    )

    # Should succeed - DEFAULT uses JWTBaseModel which is permissive
    token_default = jwt.encode(
        claims_with_extra, secret_key, Alg.HS256, claims_validation=Validation.DEFAULT
    )
    assert token_default.compact is not None

    # ========================================================================
    # Test 6: Demonstrate complete control with custom validation
    # ========================================================================

    # Create a custom JWTValidation that requires strict JWTClaims
    strict_custom_validation = JWTValidation(
        validation_model=JWTClaims,  # Strict model
        leeway=2.0,  # Tight leeway
        allow_future_iat=False,  # No future iat
    )

    # Valid claims should work
    valid_claims = JWTClaims(
        sub="user789",
        iat=now,
        exp=now + timedelta(hours=1),
    )

    token_custom = jwt.encode(
        valid_claims, secret_key, Alg.HS256, claims_validation=strict_custom_validation
    )
    assert token_custom.compact is not None

    # ========================================================================
    # Summary: Key Differences
    # ========================================================================
    # 1. Validation.DEFAULT forwards pydantic model types → validates against ModelA
    # 2. Custom validation with explicit model → validates against explicit model only
    # 3. Validation.DEFAULT uses JWT's default leeway (10.0s) → accepts expired token
    # 4. Custom validation uses its own leeway (5.0s) → rejects expired token
    # 5. Validation.DEFAULT with dict uses default validation_model (JWTBaseModel)
    # 6. Validation.DEFAULT uses default timestamp format (int)
    # 7. Custom validation can override timestamp format (float)
