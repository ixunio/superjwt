from pydantic_core import ErrorDetails


class SecurityWarning(UserWarning):
    """Base class for warnings of security issues."""


class SuperJWTError(Exception):
    """Base class for all SuperJWT related errors."""

    def __init__(self, message: str | None = None):
        if message is not None:
            self.error = message
        super().__init__(self.error)


class InvalidTokenError(SuperJWTError):
    """Generic exception for incorrect token format or content,
    regardless of signature verification."""

    error = "Invalid token"

    def __init__(self, message: str | None = None):
        if message is not None:
            self.error = message
        super().__init__(self.error)


class SignatureVerificationFailedError(InvalidTokenError):
    """Raised when signature verification fails despite token
    being valid in its format. The token may have been tampered with."""

    error = "Signature verification failed, the token may have been tampered with!"


class SizeExceededError(InvalidTokenError):
    """Raised when the token size exceeds the allowed limit."""

    error = "Token size is too large"


class InvalidHeadersError(InvalidTokenError):
    """Raised when the JWT headers are invalid."""

    error = "Header data is invalid"


class HeadersValidationError(InvalidHeadersError):
    """Raised when a header validation fails."""

    error = "Header validation failed"

    def __init__(
        self,
        message: str | None = None,
        validation_errors: list[ErrorDetails] | None = None,
    ):
        self.error = message or self.error
        if validation_errors is not None:
            self.error += "\n"
            self.error += "\n".join(
                f"header {error['loc'] if error['loc'] else ''} = {error['input']} "
                f"-> validation failed ({error['type']}): {error['msg']}"
                for error in validation_errors
            )
        super().__init__(self.error)


class AlgorithmMismatchError(InvalidHeadersError):
    """Raised during decoding when the algorithm in the JWT header
    does not match the expected registered algorithms."""

    error = "Algorithm mismatch in header"


class InvalidPayloadError(InvalidTokenError):
    error = "Payload data is invalid"


class ClaimsValidationError(InvalidPayloadError):
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


class TokenExpiredError(ClaimsValidationError):
    """Raised when the token has expired based on its 'exp' claim."""

    error = "Token has expired"


class TokenNotYetValidError(ClaimsValidationError):
    """Raised when the token is not yet valid based on its 'nbf' claim."""

    error = "Token is not yet valid"


class InvalidAlgorithmError(SuperJWTError):
    """Base class for algorithm-related errors."""

    error = "Algorithm is invalid"


class AlgorithmNotSupportedError(InvalidAlgorithmError):
    """Raised when the specified algorithm is not supported."""

    error = "Algorithm not supported"


class InvalidKeyError(SuperJWTError):
    error = "Key is invalid"
