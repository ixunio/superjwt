from superjwt._version import __version__
from superjwt.jwt import JWT


_local_jwt_instance = JWT()

encode = _local_jwt_instance.encode
decode = _local_jwt_instance.decode
inspect = _local_jwt_instance.inspect
