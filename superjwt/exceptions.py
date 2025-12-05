from pydantic_core import ErrorDetails


class SecurityWarning(UserWarning):
    """Base class for warnings of security issues."""


class JWTError(Exception):
    def __init__(self, message: str | None = None):
        if message is not None:
            self.error = message
        super().__init__(self.error)


class InvalidKeyError(JWTError):
    error = "Key is invalid"


class InvalidTokenError(JWTError):
    """Generic exception for incorrect token format or content,
    regardless of signature verification."""

    error = "Invalid token"

    def __init__(self, message: str | None = None):
        if message is not None:
            self.error = message
        super().__init__(self.error)


class SignatureVerificationFailedError(JWTError):
    """Raised when signature verification fails despite token
    being valid in its format. The token may have been tampered with."""

    error = "Signature verification failed, the token may have been tampered with!"


class SizeExceededError(InvalidTokenError):
    error = "Token size is too large"


class MalformedTokenError(InvalidTokenError):
    """Raised when the token data format is incorrect"""

    error = "Malformed token"


class InvalidHeaderError(InvalidTokenError):
    error = "Header data is invalid"


class HeaderValidationError(InvalidHeaderError):
    """Raised when a header validation fails."""

    error = "Header validation failed"

    def __init__(
        self,
        message: str | None = None,
        validation_errors: list[ErrorDetails] | None = None,
    ):
        self.error = message or self.error
        if validation_errors is not None:
            self.error += "\n".join(
                f"header '{error['loc'][0]}'={error['input']} -> validation failed ({error['type']}): {error['msg']}"
                for error in validation_errors
            )
        super().__init__(self.error)


class InvalidClaimsError(InvalidTokenError):
    error = "Claims data is invalid"


class ClaimsValidationError(InvalidClaimsError):
    """Raised when a claim validation fails."""

    error = "Claims validation failed"

    def __init__(
        self,
        message: str | None = None,
        validation_errors: list[ErrorDetails] | None = None,
    ):
        self.error = message or self.error
        if validation_errors is not None:
            self.error += "\n"
            self.error += "\n".join(
                f"claim {error['loc'] if error['loc'] else ''} = {error['input']} "
                f"-> validation failed ({error['type']}): {error['msg']}"
                for error in validation_errors
            )
        super().__init__(self.error)


class InvalidAlgorithmError(JWTError):
    """Base class for algorithm-related errors."""

    error = "Algorithm is invalid"


class AlgorithmNotSupportedError(InvalidAlgorithmError):
    """Raised when the specified algorithm is not supported."""

    error = "Algorithm not supported"
