from superjwt.jwt import JWT


__version__ = "0.1.0"

_local_jwt_instance = JWT()

encode = _local_jwt_instance.encode
decode = _local_jwt_instance.decode
inspect = _local_jwt_instance.inspect
