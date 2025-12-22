from superjwt._version import __version__
from superjwt.definitions import JOSEHeader, JWTClaims, JWTDatetime
from superjwt.jwt import JWT


__all__ = [
    "JWT",
    "JOSEHeader",
    "JWTClaims",
    "JWTDatetime",
    "__version__",
    "decode",
    "encode",
    "inspect",
]

_local_jwt_instance = JWT()

encode = _local_jwt_instance.encode
decode = _local_jwt_instance.decode
inspect = _local_jwt_instance.inspect
