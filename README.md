<div align="center">

</div>

<div align="center">
<picture>
<img alt="SuperJWT full logo" src=/docs/assets/logo-full-superjwt.png>
</picture>
<br />
<em>
A modern implementation of JSON Web Token (JWT) for Python.
<br />
With powerful Pydantic validation features.
</em>
</p>

<img alt="GitHub Actions workflow status on main branch" src="https://img.shields.io/github/actions/workflow/status/ixunio/superjwt/ci.yml?branch=main&logo=github-actions&logoColor=white&label=CI">
<a href="https://codecov.io/github/ixunio/superjwt"><img src="https://codecov.io/github/ixunio/superjwt/graph/badge.svg?token=RF0O8W5LKG"/></a>
</div>
<div align="center">
<img alt="PyPI - Version" src="https://img.shields.io/pypi/v/superjwt?color=blue">
<img alt="Supported Python versions" src="https://img.shields.io/pypi/pyversions/superjwt.svg?logo=python&logoColor=white">

<br />

<a href="https://github.com/ixunio/superjwt"><strong><em>See documentation</em></strong></a>
</div>

## Overview & Installation

SuperJWT is a minimalist JWT library for Python 3.10+ that combines the simplicity of JWT encoding/decoding with the power of [Pydantic](https://docs.pydantic.dev/latest/) validation. It supports JWS (JSON Web Signature) format with HMAC-SHA2 algorithms and includes advanced features like token inspection and detached payload mode.

**Key Features:**

- 🔐 **Secure by default** - JWS signature algorithm required.
- 🪶 **Minimalist** - Clean, modern code with minimal dependencies.
- ✔️ **JWT validation** - Easy claims validation with Pydantic models.
- 🏷️ **Type hints** - IDE autocompletion with your JWT claims or JOSE header.

**Install via pip:**

```bash
pip install superjwt
```

---

## Usage

SuperJWT makes it easy to encode and decode JWT tokens with automatic validation and serialization. Here are the fundamental operations:

### Basic Usage 🐣

#### With a `dict`

```python
from superjwt import encode, decode

secret_key = "your-secret-key-of-len-32-bytes!"

claims = {"iss": "my-app", "sub": "John Doe"}

token: bytes = encode(claims, key=secret_key, algorithm="HS256")
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSJ9.HwnUqTLFAMzNkMrokd0aI7c-zSJJpSVXMrYIhUyWe4s'
decoded: dict = decode(token, key=secret_key, algorithm="HS256")
#> decoded = {'iss': 'my-app', 'sub': 'John Doe'}
```

#### With a `pydantic` model
*auto-validate JWT content and seamlessly include `'iat'` (Issued At) and `'exp'` (Expiration) claims*

```python
from superjwt import JWTClaims, encode, decode

secret_key = "your-secret-key-of-len-32-bytes!"

claims = (
    JWTClaims(iss="my-app", sub="John Doe")
    .with_issued_at()
    .with_expiration(minutes=15)
)

token: bytes = encode(claims, key=secret_key, algorithm="HS256")
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSIsImlhdCI6MTc2NzAyNzQ4MywiZXhwIjoxNzY3MDI4MzgzfQ.ZXxZT8VzL8IPTov-enslCh57S2M5fQBtqULZx5zEAm8'
decoded: dict = decode(token, key=secret_key, algorithm="HS256")
#> decoded = {'iss': 'my-app', 'sub': 'John Doe', 'iat': 1767027483, 'exp': 1767028383}
```

### Custom Claims and Validation

```python
from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, Field
from superjwt import JWTClaims, decode, encode
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

# Define a custom pydantic model to validate claims
class MyJWTClaims(JWTClaims):
    # redefine 'sub' as required integer
    sub: int = Field(default=...)

    # new custom claim:  'user_id' is required and must be a valid UUIDv4 string
    user_id: Annotated[str, AfterValidator(lambda x: str(UUID(x, version=4)))]
```

#### Valid Claims Example

```python
claims = (
    MyJWTClaims(sub=123, user_id="b2a4c791-2cf4-4e41-9a20-8532129ff47c")
    .with_issued_at()
    .with_expiration(minutes=15)
)
token = encode(claims, secret_key, algorithm="HS256")
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMywiaWF0IjoxNzY3MDI2NjkxLCJleHAiOjE3NjcwMjc1OTEsInVzZXJfaWQiOiJiMmE0Yzc5MS0yY2Y0LTRlNDEtOWEyMC04NTMyMTI5ZmY0N2MifQ.kKSdYM5gxZciqtlg3ID5ff1RLUXctmjP18fU0UbjthE'
decoded = decode(
    token=token,
    key=secret_key,
    algorithm="HS256",
    validation_claims=MyJWTClaims,
)
#> decoded = {'sub': 123, 'iat': 1767026691, 'exp': 1767027591, 'user_id': 'b2a4c791-2cf4-4e41-9a20-8532129ff47c'}
```

#### Invalid Claims Example

```python
# create a non-validated and invalid pydantic claims
invalid_claims = (
    MyJWTClaims.model_construct(**{"sub": "John Doe", "user_id": "invalid-uuid-string"})
    .with_issued_at()
    .with_expiration(minutes=15)
)
# disable claims validation to create an invalid token
invalid_token = encode(
    invalid_claims, secret_key, algorithm="HS256", validation_claims=None
)
#> invalid_token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJKb2huIERvZSIsImlhdCI6MTc2NzAyNzIxNiwiZXhwIjoxNzY3MDI4MTE2LCJ1c2VyX2lkIjoiaW52YWxpZC11dWlkLXN0cmluZyJ9.eBJKSxoBNWtS7uojVIIUYJWC26c2GHP8o4LPZm41tp8'
try:
    decoded_invalid = decode(
        token=invalid_token,
        key=secret_key,
        algorithm="HS256",
        validation_claims=MyJWTClaims,
    )
except ClaimsValidationError as e:
    print("Claims validation error:", e)
#> Claims validation error: Claims validation failed
#> claim ('sub',) = John Doe -> validation failed (int_parsing): Input should be a valid integer, unable to parse string as an integer
#> claim ('user_id',) = invalid-uuid-string -> validation failed (value_error): Value error, badly formed hexadecimal UUID string
```

## Documentation

<a href="https://github.com/ixunio/superjwt"><strong><em>See full documentation</em></strong></a>

## Test

1. Clone repository

2. Install dependencies
    ```bash
    pip install -e . --group test
    ```
3. Run tests
    ```bash
    pytest
    ```
