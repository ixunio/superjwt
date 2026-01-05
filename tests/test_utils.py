import binascii
from datetime import datetime

import pytest
from superjwt.utils import (
    as_bytes,
    delta_datetime_timestamp,
    is_pem_format,
    is_ssh_key,
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
