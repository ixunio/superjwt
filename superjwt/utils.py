import base64
import binascii
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any


def trim_str(s: str, max_length: int = 200) -> str:
    if len(s) <= max_length:
        return s
    return s[:max_length] + "..."


def pydantic_validation_errors_to_str(
    validation_errors: Sequence[Mapping[str, Any]],
) -> str:
    error = "\n".join(
        f"{trim_str(str(error['loc']), 64) if error['loc'] else ''} = "
        f"{trim_str(str(error['input'])) if error['type'] != 'missing' else 'Not found'} "
        f"-> validation failed ({error['type']}): {error['msg']}"
        for error in validation_errors
    )
    return error


def as_bytes(s: str | bytes) -> bytes:
    if isinstance(s, str):
        return s.encode("utf-8")
    if isinstance(s, bytes):
        return s
    raise TypeError("Expected str or bytes")


def urlsafe_b64decode(s: bytes) -> bytes:
    if b"+" in s or b"/" in s:
        raise binascii.Error

    pad = -len(s) % 4
    if pad == 3:
        raise binascii.Error

    safe_ending = (b"AEIMQUYcgkosw048", b"AQgw")
    if pad and s[-1] not in safe_ending[pad - 1]:
        raise binascii.Error

    s += b"=" * pad
    return base64.b64decode(s, b"-_", validate=True)


def urlsafe_b64encode(s: bytes) -> bytes:
    return base64.urlsafe_b64encode(s).rstrip(b"=")


def encode_integer(num: int, bits: int) -> bytes:
    length = ((bits + 7) // 8) * 2
    padded_hex = f"{num:0{length}x}"
    return binascii.a2b_hex(padded_hex.encode("ascii"))


def decode_integer(s: bytes) -> int:
    return int(binascii.b2a_hex(s), 16)


# Based on https://github.com/hynek/pem/blob/7ad94db26b0bc21d10953f5dbad3acfdfacf57aa/src/pem/_core.py#L224-L252
_PEMS = {
    b"CERTIFICATE",
    b"TRUSTED CERTIFICATE",
    b"PRIVATE KEY",
    b"PUBLIC KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"RSA PRIVATE KEY",
    b"RSA PUBLIC KEY",
    b"EC PRIVATE KEY",
    b"DH PARAMETERS",
    b"NEW CERTIFICATE REQUEST",
    b"CERTIFICATE REQUEST",
    b"SSH2 PUBLIC KEY",
    b"SSH2 ENCRYPTED PRIVATE KEY",
    b"X509 CRL",
}

# Match BEGIN/END markers anywhere (lookahead allows overlapping markers) rather than
# requiring strict line layout: the cryptography loader accepts PEM variants (tab before
# END, CR-only line endings, single-line) that a layout-strict regex would miss, which
# would let a public key slip through as an HMAC secret (see GHSA-ffc3-869f-jxw9).
_PEM_MARKER_RE = re.compile(
    b"(?=(----[- ](BEGIN|END) (" + b"|".join(_PEMS) + b")[- ]----))"
)


def is_pem_format(key: bytes) -> bool:
    """Return True if key contains a BEGIN marker followed later by a matching END marker.

    Single O(n) pass, no regex backtracking.
    """
    begin_markers: dict[bytes, int] = {}
    for marker in _PEM_MARKER_RE.finditer(key):
        marker_type, label = marker.group(2), marker.group(3)
        if marker_type == b"BEGIN":
            begin_markers[label] = marker.start(1) + len(marker.group(1))
        elif label in begin_markers and begin_markers[label] < marker.start(1):
            return True
    return False


# Based on https://github.com/pyca/cryptography/blob/bcb70852d577b3f490f015378c75cba74986297b/src/cryptography/hazmat/primitives/serialization/ssh.py#L40-L46
_SSH_KEY_FORMATS = (
    b"ssh-ed25519",
    b"ssh-rsa",
    b"ssh-dss",
    b"ecdsa-sha2-nistp256",
    b"ecdsa-sha2-nistp384",
    b"ecdsa-sha2-nistp521",
)


def is_ssh_key(key: bytes) -> bool:
    return key.startswith(_SSH_KEY_FORMATS)


def delta_datetime_timestamp(
    dt1: datetime | float | int, dt2: datetime | float | int
) -> float:
    """Return the absolute difference between two datetime objects or timestamps."""
    if isinstance(dt1, datetime):
        ts1 = dt1.timestamp()
    else:
        ts1 = float(dt1)

    if isinstance(dt2, datetime):
        ts2 = dt2.timestamp()
    else:
        ts2 = float(dt2)

    return ts1 - ts2
