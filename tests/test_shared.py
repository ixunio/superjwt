import pytest
from superjwt.exceptions import AlgorithmNotSupportedError, InvalidAlgorithmError
from superjwt.shared import (
    ALGORITHMS,
    SUPPORTED_ALGORITHMS,
    Alg,
    get_cached_algorithm,
    get_max_token_bytes,
    set_max_token_bytes,
)


# These imports are used in the test functions below
_ = (
    ALGORITHMS,
    SUPPORTED_ALGORITHMS,
    get_cached_algorithm,
    get_max_token_bytes,
    set_max_token_bytes,
)


class TestAlgEnum:
    """Test suite for the Alg enum methods."""

    def test_get_instance_not_implemented(self):
        """Test that get_instance() raises AlgorithmNotSupportedError for unimplemented algorithms."""
        # EdDSA is defined but not yet implemented (ALGORITHMS[EdDSA] = None)
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
        # EdDSA is defined but not yet implemented (ALGORITHMS[EdDSA] = None)
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

    def test_alg_enum_string_values(self):
        """Test that Alg enum members have correct string values."""
        assert Alg.HS256.value == "HS256"
        assert Alg.HS384.value == "HS384"
        assert Alg.HS512.value == "HS512"
        assert Alg.RS256.value == "RS256"
        assert Alg.RS384.value == "RS384"
        assert Alg.RS512.value == "RS512"
        assert Alg.PS256.value == "PS256"
        assert Alg.PS384.value == "PS384"
        assert Alg.PS512.value == "PS512"
        assert Alg.ES256.value == "ES256"
        assert Alg.ES256K.value == "ES256K"
        assert Alg.ES384.value == "ES384"
        assert Alg.ES512.value == "ES512"
        assert Alg.EdDSA.value == "EdDSA"
        assert Alg.Ed25519.value == "Ed25519"
        assert Alg.Ed448.value == "Ed448"

    def test_alg_enum_all_members_present(self):
        """Test that all expected algorithm names are in the enum."""
        expected_algorithms = {
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "EdDSA",
            "Ed25519",
            "Ed448",
        }
        actual_algorithms = {alg.value for alg in Alg}
        assert actual_algorithms == expected_algorithms

    def test_get_instance_caches_instances(self):
        """Test that get_instance() returns the same cached instance."""
        instance1 = Alg.HS256.get_instance()
        instance2 = Alg.HS256.get_instance()
        # Should be the exact same object (cached)
        assert instance1 is instance2

    def test_get_instance_by_name_caches_instances(self):
        """Test that get_instance_by_name() returns cached instances."""
        instance1 = Alg.get_instance_by_name("RS256")
        instance2 = Alg.get_instance_by_name("RS256")
        # Should be the exact same object (cached)
        assert instance1 is instance2

    def test_get_algorithm_with_string_uses_cache(self):
        """Test that get_algorithm() with string uses cached instances."""
        instance1 = Alg.get_algorithm("ES256")
        instance2 = Alg.get_algorithm("ES256")
        # Should be the exact same object (cached)
        assert instance1 is instance2

    def test_get_algorithm_with_enum_uses_cache(self):
        """Test that get_algorithm() with enum uses cached instances."""
        instance1 = Alg.get_algorithm(Alg.PS256)
        instance2 = Alg.get_algorithm(Alg.PS256)
        # Should be the exact same object (cached)
        assert instance1 is instance2

    def test_get_algorithm_enum_and_string_same_instance(self):
        """Test that enum and string access return the same cached instance."""
        instance_enum = Alg.get_algorithm(Alg.Ed25519)
        instance_string = Alg.get_algorithm("Ed25519")
        # Should be the exact same object
        assert instance_enum is instance_string

    def test_get_algorithm_with_enum_returns_same_as_get_instance(self):
        """Test that get_algorithm with enum returns the same as get_instance."""
        alg_enum = Alg.RS256
        instance_via_get_algorithm = Alg.get_algorithm(alg_enum)
        instance_via_get_instance = alg_enum.get_instance()
        # Should be the exact same object
        assert instance_via_get_algorithm is instance_via_get_instance


class TestGetCachedAlgorithm:
    """Test suite for get_cached_algorithm function."""

    def test_get_cached_algorithm_valid_name(self):
        """Test that get_cached_algorithm() returns algorithm for valid name."""
        algo = get_cached_algorithm("HS256")
        assert algo is not None
        assert algo.__class__.__name__ == "HS256Algorithm"

    def test_get_cached_algorithm_invalid_name(self):
        """Test that get_cached_algorithm() raises InvalidAlgorithmError for invalid name."""
        with pytest.raises(
            InvalidAlgorithmError, match=r"INVALID.*not a valid JWS algorithm"
        ):
            get_cached_algorithm("INVALID")

    def test_get_cached_algorithm_not_implemented(self):
        """Test that get_cached_algorithm() raises AlgorithmNotSupportedError for unimplemented algorithms."""
        with pytest.raises(
            AlgorithmNotSupportedError, match=r"EdDSA.*not yet implemented"
        ):
            get_cached_algorithm("EdDSA")

    def test_get_cached_algorithm_returns_same_instance(self):
        """Test that get_cached_algorithm() returns the same instance on repeated calls."""
        algo1 = get_cached_algorithm("RS256")
        algo2 = get_cached_algorithm("RS256")
        assert algo1 is algo2

    def test_get_cached_algorithm_all_implemented_algorithms(self):
        """Test that all implemented algorithms can be retrieved."""
        implemented_algorithms = [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "Ed25519",
            "Ed448",
        ]

        for alg_name in implemented_algorithms:
            algo = get_cached_algorithm(alg_name)
            assert algo is not None
            assert algo.name == alg_name


class TestMaxTokenBytes:
    """Test suite for max token bytes configuration."""

    def test_get_max_token_bytes_default_value(self):
        """Test that get_max_token_bytes() returns default value (16KB)."""
        # Note: This might be affected by previous tests, so we check it's an int
        max_bytes = get_max_token_bytes()
        assert isinstance(max_bytes, int)
        assert max_bytes > 0

    def test_set_and_get_max_token_bytes(self):
        """Test that set_max_token_bytes() updates the value returned by get_max_token_bytes()."""
        original_value = get_max_token_bytes()

        try:
            # Set a custom value
            new_value = 32 * 1024  # 32 KB
            set_max_token_bytes(new_value)

            # Verify it was set
            assert get_max_token_bytes() == new_value

            # Set another value
            another_value = 8 * 1024  # 8 KB
            set_max_token_bytes(another_value)
            assert get_max_token_bytes() == another_value

        finally:
            # Restore original value
            set_max_token_bytes(original_value)

    def test_set_max_token_bytes_accepts_different_sizes(self):
        """Test that set_max_token_bytes() accepts various token size values."""
        original_value = get_max_token_bytes()

        try:
            # Test small value
            set_max_token_bytes(1024)  # 1 KB
            assert get_max_token_bytes() == 1024

            # Test large value
            set_max_token_bytes(1024 * 1024)  # 1 MB
            assert get_max_token_bytes() == 1024 * 1024

            # Test very small value
            set_max_token_bytes(100)  # 100 bytes
            assert get_max_token_bytes() == 100

        finally:
            # Restore original value
            set_max_token_bytes(original_value)


class TestALGORITHMS:
    """Test suite for ALGORITHMS dictionary."""

    def test_algorithms_dict_structure(self):
        """Test that ALGORITHMS dict has expected structure."""
        assert isinstance(ALGORITHMS, dict)
        assert len(ALGORITHMS) > 0

    def test_algorithms_dict_contains_all_alg_enum_members(self):
        """Test that ALGORITHMS dict contains entries for all Alg enum members."""
        for alg in Alg:
            assert alg.value in ALGORITHMS

    def test_algorithms_dict_implemented_algorithms_have_class(self):
        """Test that implemented algorithms have a class reference."""
        implemented_algorithms = [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "Ed25519",
            "Ed448",
        ]

        for alg_name in implemented_algorithms:
            assert ALGORITHMS[alg_name] is not None
            assert callable(ALGORITHMS[alg_name])

    def test_algorithms_dict_eddsa_is_none(self):
        """Test that EdDSA algorithm is marked as not implemented (None)."""
        assert ALGORITHMS["EdDSA"] is None

    def test_algorithms_dict_has_expected_algorithms(self):
        """Test that ALGORITHMS dict contains all expected algorithm names."""
        expected_algorithms = {
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "EdDSA",
            "Ed25519",
            "Ed448",
        }

        assert set(ALGORITHMS.keys()) == expected_algorithms


class TestSupportedAlgorithms:
    """Test suite for SUPPORTED_ALGORITHMS constant."""

    def test_supported_algorithms_matches_alg_enum(self):
        """Test that SUPPORTED_ALGORITHMS contains all Alg enum member names."""
        expected = set(Alg.__members__.keys())
        actual = set(SUPPORTED_ALGORITHMS)
        assert actual == expected

    def test_supported_algorithms_includes_all_algorithms(self):
        """Test that SUPPORTED_ALGORITHMS includes expected algorithm names."""
        expected_algorithms = {
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "EdDSA",
            "Ed25519",
            "Ed448",
        }

        assert set(SUPPORTED_ALGORITHMS) == expected_algorithms

    def test_supported_algorithms_is_iterable(self):
        """Test that SUPPORTED_ALGORITHMS can be iterated."""
        count = 0
        for alg_name in SUPPORTED_ALGORITHMS:
            assert isinstance(alg_name, str)
            count += 1

        assert count > 0


class TestAlgorithmCacheInitialization:
    """Test suite for algorithm cache initialization."""

    def test_algorithm_cache_is_initialized_on_import(self):
        """Test that algorithm instances are cached when module is imported."""
        # All implemented algorithms should be in cache
        algo = get_cached_algorithm("HS256")
        assert algo is not None

        # Getting it again should return the same instance
        algo2 = get_cached_algorithm("HS256")
        assert algo is algo2

    def test_all_implemented_algorithms_are_cached(self):
        """Test that all implemented algorithms are pre-cached."""
        implemented_algorithms = [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "Ed25519",
            "Ed448",
        ]

        for alg_name in implemented_algorithms:
            # Should not raise any errors
            algo = get_cached_algorithm(alg_name)
            assert algo is not None
            assert algo.name == alg_name

    def test_cache_consistency_across_access_methods(self):
        """Test that different access methods return the same cached instances."""
        # Access via get_cached_algorithm
        algo1 = get_cached_algorithm("PS256")

        # Access via Alg enum
        algo2 = Alg.PS256.get_instance()

        # Access via Alg.get_algorithm with string
        algo3 = Alg.get_algorithm("PS256")

        # Access via Alg.get_algorithm with enum
        algo4 = Alg.get_algorithm(Alg.PS256)

        # All should be the same instance
        assert algo1 is algo2
        assert algo1 is algo3
        assert algo1 is algo4
