import base64
import binascii
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any


def check_cryptography_available(raise_error: bool = True) -> bool:
    """Check if cryptography library is available, raise helpful error if not."""
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError as e:  # pragma: no cover
        if raise_error:
            raise ImportError(
                "Asymmetric key algorithms require the 'cryptography' library. "
                "Install it with: pip install superjwt[asymmetric]"
            ) from e
        return False


CRYPTOGRAPHY_AVAILABLE = check_cryptography_available(raise_error=False)


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

_PEM_RE = re.compile(
    b"----[- ]BEGIN ("
    + b"|".join(_PEMS)
    + b""")[- ]----\r?
.+?\r?
----[- ]END \\1[- ]----\r?\n?""",
    re.DOTALL,
)


def is_pem_format(key: bytes) -> bool:
    return bool(_PEM_RE.search(key))


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
