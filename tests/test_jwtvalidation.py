"""Unit tests for JWTValidation configuration and get_validation_config().

These tests focus on:
- JWTValidation class: initialization, methods, parameter inheritance
- get_validation_config(): all validation modes and data type combinations

JWT encode/decode integration tests belong in test_jwt.py.
"""

from datetime import datetime, timedelta

import pytest
from superjwt.definitions import (
    DEFAULT_ALLOW_FUTURE_IAT,
    DEFAULT_JWTDATETIME_FORCE_INT,
    DEFAULT_LEEWAY_SECONDS,
    JWTBaseModel,
    JWTClaims,
    JWTValidation,
    Validation,
    get_validation_config,
)


try:
    from datetime import UTC
except ImportError:
    from datetime import timezone

    UTC = timezone.utc


# ============================================================================
# Test Fixtures
# ============================================================================


class ModelA(JWTClaims):
    """First pydantic model for testing - requires field_a."""

    field_a: str  # Required field


class ModelB(JWTClaims):
    """Second pydantic model for testing - requires field_b."""

    field_b: str  # Required field


class CustomModel(JWTClaims):
    """Custom model with additional field for testing."""

    custom_field: int


# ============================================================================
# JWTValidation Class Tests
# ============================================================================


def test_jwtvalidation_default_initialization():
    """Test JWTValidation with default initialization."""
    validation = JWTValidation()

    assert validation.enabled is True
    assert validation.validation_model is None
    assert validation.forward_pydantic_model is True
    assert validation.leeway is None
    assert validation.allow_future_iat is None
    assert validation.jwtdatetime_force_int is None
    assert validation.now is None


def test_jwtvalidation_custom_initialization():
    """Test JWTValidation with custom parameters."""
    now = datetime.now(UTC)
    validation = JWTValidation(
        enabled=False,
        validation_model=JWTClaims,
        forward_pydantic_model=False,
        leeway=10.0,
        allow_future_iat=True,
        jwtdatetime_force_int=False,
        now=now,
    )

    assert validation.enabled is False
    assert validation.validation_model == JWTClaims
    assert validation.forward_pydantic_model is False
    assert validation.leeway == 10.0
    assert validation.allow_future_iat is True
    assert validation.jwtdatetime_force_int is False
    assert validation.now == now


def test_jwtvalidation_apply_internal_cfg_with_none_model():
    """Test apply_internal_cfg uses defaults when model is None."""
    validation = JWTValidation(
        leeway=None,
        allow_future_iat=None,
        jwtdatetime_force_int=None,
        now=None,
    )

    validation.apply_internal_cfg(model=None)

    assert validation.leeway == DEFAULT_LEEWAY_SECONDS
    assert validation.allow_future_iat == DEFAULT_ALLOW_FUTURE_IAT
    assert validation.jwtdatetime_force_int == DEFAULT_JWTDATETIME_FORCE_INT
    assert validation.now is None


def test_jwtvalidation_apply_internal_cfg_inherits_from_model():
    """Test apply_internal_cfg inherits None values from model."""
    # Create model with custom internal values
    model = JWTClaims()
    model.set_leeway(20.0)
    model.allow_future_iat()
    model.force_jwtdatetime_to_float()
    custom_now = datetime.now(UTC)
    model.spoof_time(custom_now)

    # Validation with all None values should inherit
    validation = JWTValidation(
        leeway=None,
        allow_future_iat=None,
        jwtdatetime_force_int=None,
        now=None,
    )

    validation.apply_internal_cfg(model)

    assert validation.leeway == 20.0
    assert validation.allow_future_iat is True
    assert validation.jwtdatetime_force_int is False
    assert validation.now == custom_now


def test_jwtvalidation_apply_internal_cfg_does_not_override():
    """Test apply_internal_cfg does not override set values."""
    # Create model with custom internal values
    model = JWTClaims()
    model.set_leeway(100.0)
    model.allow_future_iat()
    model.force_jwtdatetime_to_float()
    model_now = datetime.now(UTC)
    model.spoof_time(model_now)

    # Validation with set values should NOT be overridden
    config_now = model_now + timedelta(hours=1)
    validation = JWTValidation(
        leeway=7.0,
        allow_future_iat=False,
        jwtdatetime_force_int=True,
        now=config_now,
    )

    validation.apply_internal_cfg(model)

    assert validation.leeway == 7.0  # NOT 100.0
    assert validation.allow_future_iat is False  # NOT True
    assert validation.jwtdatetime_force_int is True  # NOT False
    assert validation.now == config_now  # NOT model_now


def test_jwtvalidation_apply_internal_cfg_mixed():
    """Test apply_internal_cfg with mix of None and set values."""
    model = JWTClaims()
    model.set_leeway(50.0)
    model.allow_future_iat()
    model.force_jwtdatetime_to_float()
    model_now = datetime.now(UTC)
    model.spoof_time(model_now)

    validation = JWTValidation(
        leeway=10.0,  # Set - should NOT be overridden
        allow_future_iat=None,  # None - should inherit True
        jwtdatetime_force_int=True,  # Set - should NOT be overridden
        now=None,  # None - should inherit model_now
    )

    validation.apply_internal_cfg(model)

    assert validation.leeway == 10.0  # Used validation's value
    assert validation.allow_future_iat is True  # Inherited from model
    assert validation.jwtdatetime_force_int is True  # Used validation's value
    assert validation.now == model_now  # Inherited from model


def test_jwtvalidation_model_copy():
    """Test JWTValidation.model_copy creates independent copy."""
    now = datetime.now(UTC)
    original = JWTValidation(
        validation_model=JWTClaims,
        leeway=10.0,
        allow_future_iat=True,
        now=now,
    )

    copy = original.model_copy(deep=True)

    # Verify values match
    assert copy.validation_model == original.validation_model
    assert copy.leeway == original.leeway
    assert copy.allow_future_iat == original.allow_future_iat
    assert copy.now == original.now

    # Modify copy - should not affect original
    copy.leeway = 20.0
    copy.allow_future_iat = False

    assert original.leeway == 10.0
    assert original.allow_future_iat is True


def test_jwtvalidation_run_with_no_validation_model():
    """Test JWTValidation.run() raises error when validation_model is None."""
    validation = JWTValidation(
        validation_model=None,
        enabled=True,
    )

    data = {"sub": "user123"}

    # Should raise error because validation_model is None but validation is enabled
    with pytest.raises(ValueError, match="Validation model is not set in JWTValidation"):
        validation.run(data)


def test_jwtvalidation_run_with_dict_data():
    """Test JWTValidation.run() with dict data."""
    validation = JWTValidation(
        validation_model=JWTClaims,
        enabled=True,
    )

    now = datetime.now(UTC)
    data = {
        "sub": "user123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    result = validation.run(data)

    # Should return dict with validated data
    assert isinstance(result, dict)
    assert result["sub"] == "user123"


def test_jwtvalidation_run_with_pydantic_data():
    """Test JWTValidation.run() with pydantic data."""
    validation = JWTValidation(
        validation_model=JWTClaims,
        enabled=True,
    )

    data = JWTClaims(sub="user123")
    result = validation.run(data)

    # Should return dict
    assert isinstance(result, dict)
    assert result["sub"] == "user123"


def test_jwtvalidation_run_disabled():
    """Test JWTValidation.run() with validation disabled."""
    validation = JWTValidation(
        validation_model=None,
        enabled=False,
    )

    # Test with dict
    data_dict = {"sub": "user123"}
    result_dict = validation.run(data_dict)
    assert result_dict == data_dict

    # Test with pydantic model
    data_pydantic = JWTClaims(sub="user123")
    result_pydantic = validation.run(data_pydantic)
    assert isinstance(result_pydantic, dict)
    assert result_pydantic["sub"] == "user123"


# ============================================================================
# get_validation_config() Tests - DISABLE Cases
# ============================================================================


def test_get_validation_config_disable_with_validation_none():
    """Test get_validation_config with validation=None (DISABLE)."""
    data = {"sub": "user123"}
    default_validation = JWTValidation(validation_model=JWTClaims)

    result = get_validation_config(
        data=data,
        validation=None,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.enabled is False


def test_get_validation_config_disable_with_validation_disable():
    """Test get_validation_config with validation=Validation.DISABLE."""
    data = ModelA(field_a="test")
    default_validation = JWTValidation(validation_model=JWTClaims)

    result = get_validation_config(
        data=data,
        validation=Validation.DISABLE,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.enabled is False


def test_get_validation_config_disable_with_enabled_false():
    """Test get_validation_config with JWTValidation(enabled=False)."""
    data = {"sub": "user123"}
    custom_validation = JWTValidation(enabled=False, validation_model=JWTClaims)
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.enabled is False


# ============================================================================
# get_validation_config() Tests - DEFAULT Cases
# ============================================================================


def test_get_validation_config_default_with_pydantic_data_forward_true():
    """Test DEFAULT validation with pydantic data and forward=True.

    Expected: validation_model should be data's type (ModelA), not default's model.
    """
    data = ModelA(field_a="test")
    default_validation = JWTValidation(
        validation_model=JWTBaseModel,
        forward_pydantic_model=True,
    )

    result = get_validation_config(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model == ModelA
    assert result.enabled is True


def test_get_validation_config_default_with_pydantic_data_forward_false():
    """Test DEFAULT validation with pydantic data and forward=False.

    Expected: validation_model should be default's model (JWTBaseModel).
    """
    data = ModelA(field_a="test")
    default_validation = JWTValidation(
        validation_model=JWTBaseModel,
        forward_pydantic_model=False,
    )

    result = get_validation_config(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model == JWTBaseModel
    assert result.enabled is True


def test_get_validation_config_default_with_dict_data():
    """Test DEFAULT validation with dict data.

    Expected: validation_model should be default's model (no forwarding possible).
    """
    data = {"sub": "user123"}
    default_validation = JWTValidation(
        validation_model=JWTClaims,
        forward_pydantic_model=True,
    )

    result = get_validation_config(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model == JWTClaims
    assert result.enabled is True


def test_get_validation_config_default_inherits_internal_config():
    """Test DEFAULT validation inherits internal config from pydantic model."""
    data = ModelA(field_a="test")
    data.set_leeway(20.0)
    data.allow_future_iat()

    default_validation = JWTValidation(
        validation_model=JWTBaseModel,
        forward_pydantic_model=True,
        leeway=None,  # Should inherit from data
        allow_future_iat=None,  # Should inherit from data
    )

    result = get_validation_config(
        data=data,
        validation=Validation.DEFAULT,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.leeway == 20.0
    assert result.allow_future_iat is True


# ============================================================================
# get_validation_config() Tests - CUSTOM JWTValidation Cases
# ============================================================================


def test_get_validation_config_custom_jwtvalidation_with_pydantic_forward_true():
    """Test custom JWTValidation with pydantic data and forward=True.

    Expected: If validation_model is None, forward data's type.
    """
    data = ModelA(field_a="test")
    custom_validation = JWTValidation(
        validation_model=None,
        forward_pydantic_model=True,
    )
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model == ModelA
    assert result.enabled is True


def test_get_validation_config_custom_jwtvalidation_with_explicit_model():
    """Test custom JWTValidation with explicit validation_model.

    Expected: validation_model should NOT be overridden by forwarding.
    """
    data = ModelA(field_a="test")
    custom_validation = JWTValidation(
        validation_model=ModelB,  # Explicit model
        forward_pydantic_model=True,  # Should NOT override explicit model
    )
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model == ModelB  # NOT ModelA
    assert result.enabled is True


def test_get_validation_config_custom_jwtvalidation_forward_false_no_model():
    """Test custom JWTValidation with forward=False and validation_model=None.

    Expected: validation_model should be None (invalid configuration).
    """
    data = ModelA(field_a="test")
    custom_validation = JWTValidation(
        validation_model=None,
        forward_pydantic_model=False,
    )
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model is None
    assert result.enabled is True


def test_get_validation_config_custom_jwtvalidation_with_dict_data():
    """Test custom JWTValidation with dict data and explicit model."""
    data = {"sub": "user123"}
    custom_validation = JWTValidation(
        validation_model=JWTClaims,
        leeway=15.0,
    )
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model == JWTClaims
    assert result.leeway == 15.0
    assert result.enabled is True


def test_get_validation_config_custom_jwtvalidation_does_not_mutate():
    """Test that get_validation_config does not mutate input validation config."""
    custom_validation = JWTValidation(
        validation_model=JWTBaseModel,
        leeway=10.0,
        allow_future_iat=False,
    )
    data = {"sub": "user123"}
    default_validation = JWTValidation(validation_model=JWTClaims)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    # Modify result
    result.leeway = 20.0
    result.allow_future_iat = True

    # Original should be unchanged
    assert custom_validation.leeway == 10.0
    assert custom_validation.allow_future_iat is False


def test_get_validation_config_custom_jwtvalidation_inherits_from_model():
    """Test custom JWTValidation inherits internal config from pydantic model."""
    data = CustomModel(custom_field=42)
    data.set_leeway(30.0)
    data.force_jwtdatetime_to_float()

    custom_validation = JWTValidation(
        validation_model=None,
        forward_pydantic_model=True,
        leeway=None,  # Should inherit from data
        jwtdatetime_force_int=None,  # Should inherit from data
    )
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.leeway == 30.0
    assert result.jwtdatetime_force_int is False


# ============================================================================
# get_validation_config() Tests - CUSTOM Model Class Cases
# ============================================================================


def test_get_validation_config_custom_model_class():
    """Test get_validation_config with model class as validation parameter."""
    data = {"sub": "user123"}
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=JWTClaims,  # Model class
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model == JWTClaims
    assert result.enabled is True


def test_get_validation_config_custom_model_class_with_pydantic_data():
    """Test get_validation_config with model class and pydantic data."""
    data = ModelA(field_a="test")
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=ModelB,  # Different model class
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.validation_model == ModelB  # NOT ModelA
    assert result.enabled is True


# ============================================================================
# get_validation_config() Tests - Internal Config Application
# ============================================================================


def test_get_validation_config_applies_defaults_for_dict_data():
    """Test get_validation_config applies defaults for dict data."""
    data = {"sub": "user123"}
    custom_validation = JWTValidation(
        validation_model=JWTClaims,
        leeway=None,
        allow_future_iat=None,
        jwtdatetime_force_int=None,
    )
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    # Should have default values applied
    assert result.leeway == DEFAULT_LEEWAY_SECONDS
    assert result.allow_future_iat == DEFAULT_ALLOW_FUTURE_IAT
    assert result.jwtdatetime_force_int == DEFAULT_JWTDATETIME_FORCE_INT


def test_get_validation_config_does_not_override_explicit_values():
    """Test get_validation_config does not override explicit internal config."""
    data = ModelA(field_a="test")
    data.set_leeway(50.0)

    custom_validation = JWTValidation(
        validation_model=None,
        forward_pydantic_model=True,
        leeway=10.0,  # Explicit - should NOT be overridden
    )
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result = get_validation_config(
        data=data,
        validation=custom_validation,
        default_validation=default_validation,
        fallback_data_model=JWTBaseModel,
    )

    assert result.leeway == 10.0  # NOT 50.0 from data


# ============================================================================
# get_validation_config() Tests - Comprehensive Scenarios
# ============================================================================


def test_get_validation_config_all_combinations():
    """Test get_validation_config with all parameter combinations.

    This is a comprehensive test covering the 8 main scenarios:
    1. Pydantic data + forward=True + validation_model=None → forwards data type
    2. Pydantic data + forward=True + validation_model=Set → uses explicit model
    3. Pydantic data + forward=False + validation_model=None → no model
    4. Pydantic data + forward=False + validation_model=Set → uses explicit model
    5. Dict data + forward=True + validation_model=None → no model
    6. Dict data + forward=True + validation_model=Set → uses explicit model
    7. Dict data + forward=False + validation_model=None → no model
    8. Dict data + forward=False + validation_model=Set → uses explicit model
    """
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    # Case 1: Pydantic + forward=True + model=None
    data_1 = ModelA(field_a="test")
    validation_1 = JWTValidation(validation_model=None, forward_pydantic_model=True)
    result_1 = get_validation_config(
        data_1, validation_1, default_validation, JWTBaseModel
    )
    assert result_1.validation_model == ModelA

    # Case 2: Pydantic + forward=True + model=Set
    data_2 = ModelA(field_a="test")
    validation_2 = JWTValidation(validation_model=ModelB, forward_pydantic_model=True)
    result_2 = get_validation_config(
        data_2, validation_2, default_validation, JWTBaseModel
    )
    assert result_2.validation_model == ModelB

    # Case 3: Pydantic + forward=False + model=None
    data_3 = ModelA(field_a="test")
    validation_3 = JWTValidation(validation_model=None, forward_pydantic_model=False)
    result_3 = get_validation_config(
        data_3, validation_3, default_validation, JWTBaseModel
    )
    assert result_3.validation_model is None

    # Case 4: Pydantic + forward=False + model=Set
    data_4 = ModelA(field_a="test")
    validation_4 = JWTValidation(validation_model=ModelB, forward_pydantic_model=False)
    result_4 = get_validation_config(
        data_4, validation_4, default_validation, JWTBaseModel
    )
    assert result_4.validation_model == ModelB

    # Case 5: Dict + forward=True + model=None
    data_5 = {"sub": "user123"}
    validation_5 = JWTValidation(validation_model=None, forward_pydantic_model=True)
    result_5 = get_validation_config(
        data_5, validation_5, default_validation, JWTBaseModel
    )
    assert result_5.validation_model is None

    # Case 6: Dict + forward=True + model=Set
    data_6 = {"sub": "user123"}
    validation_6 = JWTValidation(validation_model=JWTClaims, forward_pydantic_model=True)
    result_6 = get_validation_config(
        data_6, validation_6, default_validation, JWTBaseModel
    )
    assert result_6.validation_model == JWTClaims

    # Case 7: Dict + forward=False + model=None
    data_7 = {"sub": "user123"}
    validation_7 = JWTValidation(validation_model=None, forward_pydantic_model=False)
    result_7 = get_validation_config(
        data_7, validation_7, default_validation, JWTBaseModel
    )
    assert result_7.validation_model is None

    # Case 8: Dict + forward=False + model=Set
    data_8 = {"sub": "user123"}
    validation_8 = JWTValidation(validation_model=JWTClaims, forward_pydantic_model=False)
    result_8 = get_validation_config(
        data_8, validation_8, default_validation, JWTBaseModel
    )
    assert result_8.validation_model == JWTClaims


def test_get_validation_config_default_vs_custom():
    """Test key differences between Validation.DEFAULT and custom JWTValidation.

    Key differences:
    1. DEFAULT with pydantic+forward=True → forwards data type
    2. CUSTOM with explicit model → uses explicit model only
    3. DEFAULT uses default_validation's config values
    4. CUSTOM uses its own config values
    """
    data_pydantic = ModelA(field_a="test")
    data_dict = {"sub": "user123"}

    default_validation = JWTValidation(
        validation_model=JWTBaseModel,
        forward_pydantic_model=True,
        leeway=10.0,
    )

    # Scenario 1: DEFAULT with pydantic data forwards model type
    result_default_pydantic = get_validation_config(
        data_pydantic, Validation.DEFAULT, default_validation, JWTBaseModel
    )
    assert result_default_pydantic.validation_model == ModelA
    assert result_default_pydantic.leeway == 10.0

    # Scenario 2: CUSTOM with explicit model uses explicit model
    custom_validation = JWTValidation(
        validation_model=JWTClaims,
        forward_pydantic_model=True,
        leeway=7.0,
    )
    result_custom_pydantic = get_validation_config(
        data_pydantic, custom_validation, default_validation, JWTBaseModel
    )
    assert result_custom_pydantic.validation_model == JWTClaims  # NOT ModelA
    assert result_custom_pydantic.leeway == 7.0  # NOT 10.0

    # Scenario 3: DEFAULT with dict data uses default's model
    result_default_dict = get_validation_config(
        data_dict, Validation.DEFAULT, default_validation, JWTBaseModel
    )
    assert result_default_dict.validation_model == JWTBaseModel
    assert result_default_dict.leeway == 10.0

    # Scenario 4: CUSTOM with dict data uses custom model
    result_custom_dict = get_validation_config(
        data_dict, custom_validation, default_validation, JWTBaseModel
    )
    assert result_custom_dict.validation_model == JWTClaims
    assert result_custom_dict.leeway == 7.0


# ============================================================================
# Edge Cases
# ============================================================================


def test_get_validation_config_invalid_validation_type():
    """Test get_validation_config raises error for invalid validation type."""
    data = {"sub": "user123"}
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    with pytest.raises(TypeError, match="Wrong validation object type"):
        get_validation_config(
            data=data,
            validation="invalid",  # type: ignore
            default_validation=default_validation,
            fallback_data_model=JWTBaseModel,
        )


def test_get_validation_config_with_data_model_tracking():
    """Test get_validation_config properly tracks data_model."""
    data_pydantic = ModelA(field_a="test")
    data_dict = {"sub": "user123"}
    default_validation = JWTValidation(validation_model=JWTBaseModel)

    result_pydantic = get_validation_config(
        data_pydantic, Validation.DEFAULT, default_validation, JWTBaseModel
    )
    assert result_pydantic.data_model == ModelA

    result_dict = get_validation_config(
        data_dict, Validation.DEFAULT, default_validation, JWTBaseModel
    )
    assert result_dict.data_model == JWTBaseModel
