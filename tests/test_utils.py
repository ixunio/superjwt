import binascii
from datetime import datetime

import pytest
from superjwt.utils import (
    as_bytes,
    decode_integer,
    delta_datetime_timestamp,
    encode_integer,
    is_pem_format,
    is_ssh_key,
    pydantic_validation_errors_to_str,
    trim_str,
    urlsafe_b64decode,
    urlsafe_b64encode,
)


try:
    from datetime import UTC
except ImportError:
    from datetime import timezone

    UTC = timezone.utc


def test_rfc4648_vectors():
    """Test vectors from RFC 4648."""
    vectors = [
        (b"", b""),
        (b"f", b"Zg"),
        (b"fo", b"Zm8"),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg"),
        (b"fooba", b"Zm9vYmE"),
        (b"foobar", b"Zm9vYmFy"),
    ]
    for raw, encoded in vectors:
        # urlsafe_b64encode strips padding, but these vectors don't have padding issues
        # except "Zg==" -> "Zg", "Zm8=" -> "Zm8"
        assert urlsafe_b64encode(raw) == encoded
        assert urlsafe_b64decode(encoded) == raw


def test_padding_stripping():
    """Ensure padding is stripped on encode and handled on decode."""
    # "a" -> "YQ==" -> "YQ"
    assert urlsafe_b64encode(b"a") == b"YQ"
    assert urlsafe_b64decode(b"YQ") == b"a"

    # "ab" -> "YWI=" -> "YWI"
    assert urlsafe_b64encode(b"ab") == b"YWI"
    assert urlsafe_b64decode(b"YWI") == b"ab"

    # "abc" -> "YWJj" -> "YWJj" (no padding)
    assert urlsafe_b64encode(b"abc") == b"YWJj"
    assert urlsafe_b64decode(b"YWJj") == b"abc"


def test_decode_invalid_chars():
    """Ensure standard base64 characters + and / are rejected."""
    with pytest.raises(binascii.Error):
        urlsafe_b64decode(b"ab+c")

    with pytest.raises(binascii.Error):
        urlsafe_b64decode(b"ab/c")


def test_decode_invalid_length():
    """Ensure invalid lengths (length % 4 == 1) are rejected."""
    # "a" (len 1) -> invalid
    with pytest.raises(binascii.Error):
        urlsafe_b64decode(b"a")

    # "abcde" (len 5) -> invalid
    with pytest.raises(binascii.Error):
        urlsafe_b64decode(b"abcde")


def test_decode_safe_ending():
    """Ensure the last character is valid for the implied padding."""
    # pad = 1 (len % 4 == 3). Last char must be in "AEIMQUYcgkosw048"
    # Valid: "YWI" ("ab") -> 'I' is valid
    assert urlsafe_b64decode(b"YWI") == b"ab"

    # Invalid: b"YWB" -> 'B' is not in safe endings for pad=1
    with pytest.raises(binascii.Error):
        urlsafe_b64decode(b"YWB")

    # pad = 2 (len % 4 == 2). Last char must be in "AQgw"
    # Valid: "YQ" ("a") -> 'Q' is valid
    assert urlsafe_b64decode(b"YQ") == b"a"

    # Invalid: b"YR" -> 'R' is not in safe endings for pad=2
    with pytest.raises(binascii.Error):
        urlsafe_b64decode(b"YR")


def test_as_bytes():
    assert as_bytes("foo") == b"foo"
    assert as_bytes(b"foo") == b"foo"
    with pytest.raises(TypeError):
        as_bytes(123)  # type: ignore


def test_trim_str():
    # Shorter than max_length -> unchanged
    s_short = "a" * 10
    assert trim_str(s_short, max_length=20) == s_short

    # Exactly at max_length -> unchanged
    s_exact = "x" * 200
    assert trim_str(s_exact) == s_exact

    # Longer than default max_length -> truncated with ellipsis
    s_long = "y" * 250
    trimmed = trim_str(s_long)
    assert trimmed.endswith("...")
    assert len(trimmed) == 200 + 3

    # Custom max_length
    assert trim_str("abcdef", max_length=3) == "abc..."


def test_pydantic_validation_errors_to_str():
    """Test formatting pydantic validation errors with trimming."""
    # Basic case with normal-sized inputs
    err1 = {
        "loc": ("field", "sub"),
        "input": "test_value",
        "type": "value_error",
        "msg": "invalid",
    }
    result = pydantic_validation_errors_to_str([err1])
    assert "('field', 'sub')" in result
    assert "test_value" in result
    assert "validation failed (value_error)" in result
    assert "invalid" in result

    # Empty loc
    err2 = {"loc": (), "input": 123, "type": "type_error", "msg": "wrong type"}
    result = pydantic_validation_errors_to_str([err2])
    assert result.startswith(" = 123")
    assert "validation failed (type_error): wrong type" in result

    # Long input gets trimmed (250 chars -> 200 + "...")
    long_input = "x" * 250
    err3 = {
        "loc": ("field",),
        "input": long_input,
        "type": "value_error",
        "msg": "too long",
    }
    result = pydantic_validation_errors_to_str([err3])
    assert "x" * 200 + "..." in result
    assert "x" * 201 not in result  # Verify it was actually trimmed

    # Long loc gets trimmed (max_length=64 for loc)
    long_loc = ("a" * 100, "b" * 100)
    err4 = {"loc": long_loc, "input": "val", "type": "value_error", "msg": "test"}
    result = pydantic_validation_errors_to_str([err4])
    # str(long_loc) is longer than 64, should be trimmed
    assert "..." in result
    assert len(result.split(" = ")[0]) == 67  # 64 chars + "..."

    # Missing type should show 'Not found'
    err5 = {
        "loc": ("required_field",),
        "input": {"some": "data"},
        "type": "missing",
        "msg": "Field required",
    }
    result = pydantic_validation_errors_to_str([err5])
    assert "('required_field',)" in result
    assert " = Not found " in result  # Should be 'None', not the actual input
    assert "{'some': 'data'}" not in result  # Input should not appear
    assert "validation failed (missing): Field required" in result

    # Multiple errors joined by newline
    result_multi = pydantic_validation_errors_to_str([err1, err2])
    lines = result_multi.split("\n")
    assert len(lines) == 2
    assert "('field', 'sub')" in lines[0]
    assert " = 123" in lines[1]


def test_is_pem_format():
    # Valid PEM
    pem = (
        b"-----BEGIN PUBLIC KEY-----\n"
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
        b"-----END PUBLIC KEY-----"
    )
    assert is_pem_format(pem) is True

    # Invalid PEM
    assert is_pem_format(b"not a pem") is False

    # Wrong header
    pem_wrong = (
        b"-----BEGIN WRONG-----\n"
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
        b"-----END WRONG-----"
    )
    assert is_pem_format(pem_wrong) is False


def test_is_ssh_key():
    # Valid SSH keys
    assert is_ssh_key(b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...") is True
    assert is_ssh_key(b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...") is True

    # Invalid SSH key
    assert is_ssh_key(b"not-ssh-key") is False


def test_delta_datetime_timestamp():
    """Test delta_datetime_timestamp with various input types."""
    # Test with datetime objects
    dt1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    dt2 = datetime(2026, 1, 1, 12, 0, 10, tzinfo=UTC)
    assert delta_datetime_timestamp(dt2, dt1) == 10.0
    assert delta_datetime_timestamp(dt1, dt2) == -10.0

    # Test with timestamps (floats)
    ts1 = 1000.0
    ts2 = 1010.5
    assert delta_datetime_timestamp(ts2, ts1) == 10.5
    assert delta_datetime_timestamp(ts1, ts2) == -10.5

    # Test with timestamps (ints)
    ts1_int = 1000
    ts2_int = 1010
    assert delta_datetime_timestamp(ts2_int, ts1_int) == 10.0
    assert delta_datetime_timestamp(ts1_int, ts2_int) == -10.0

    # Test with mixed types (datetime and timestamp)
    dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    ts = dt.timestamp() + 5.5
    assert delta_datetime_timestamp(ts, dt) == 5.5
    assert delta_datetime_timestamp(dt, ts) == -5.5

    # Test zero difference
    dt_same = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert delta_datetime_timestamp(dt1, dt_same) == 0.0
    assert delta_datetime_timestamp(1000.0, 1000) == 0.0


def test_encode_integer():
    """Test encoding integers to bytes for ECDSA signatures."""
    # Test with 256-bit value (P-256 curve)
    r = 0x12345678901234567890123456789012
    encoded = encode_integer(r, 256)
    assert len(encoded) == 32  # 256 bits = 32 bytes
    assert isinstance(encoded, bytes)

    # Test with 384-bit value (P-384 curve)
    r = 0x123456789012345678901234567890123456789012345678
    encoded = encode_integer(r, 384)
    assert len(encoded) == 48  # 384 bits = 48 bytes

    # Test with 521-bit value (P-521 curve)
    r = 0x1234567890123456789012345678901234567890123456789012345678901234
    encoded = encode_integer(r, 521)
    assert len(encoded) == 66  # (521 + 7) // 8 = 66 bytes

    # Test with zero
    encoded = encode_integer(0, 256)
    assert len(encoded) == 32
    assert encoded == b"\x00" * 32

    # Test with max value for 256 bits
    max_val = (1 << 256) - 1
    encoded = encode_integer(max_val, 256)
    assert len(encoded) == 32
    assert encoded == b"\xff" * 32


def test_decode_integer():
    """Test decoding bytes to integers for ECDSA signatures."""
    # Test decoding 32 bytes (256-bit)
    data = b"\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12" * 2
    num = decode_integer(data)
    assert isinstance(num, int)
    # Verify it decodes correctly (calculated from the actual bytes)
    assert num > 0

    # Test with zeros
    data = b"\x00" * 32
    num = decode_integer(data)
    assert num == 0

    # Test with all ones
    data = b"\xff" * 32
    num = decode_integer(data)
    assert num == (1 << 256) - 1

    # Test with simple known value
    data = b"\x00\x00\x00\x01"  # 1 as 4 bytes
    num = decode_integer(data)
    assert num == 1

    # Test with another simple value
    data = b"\x00\x00\x01\x00"  # 256 as 4 bytes
    num = decode_integer(data)
    assert num == 256

    # Test round-trip
    original = 0x123456789ABCDEF
    encoded = encode_integer(original, 256)
    decoded = decode_integer(encoded)
    assert decoded == original


def test_encode_decode_integer_roundtrip():
    """Test that encoding and decoding are inverse operations."""
    test_values = [
        (0, 256),
        (1, 256),
        (0xFFFFFFFF, 256),
        (0x123456789ABCDEF0123456789ABCDEF, 256),
        ((1 << 255) - 1, 256),  # Large value
        (0x123456789ABCDEF, 384),
        (0xFEDCBA9876543210, 521),
    ]

    for num, bits in test_values:
        encoded = encode_integer(num, bits)
        decoded = decode_integer(encoded)
        assert decoded == num, f"Round-trip failed for {num} with {bits} bits"
