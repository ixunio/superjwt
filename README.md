<div align="center">

</div>

<div align="center">
<picture>
<img alt="SuperJWT full logo" src=https://raw.githubusercontent.com/ixunio/superjwt/main/docs/assets/logo-full-superjwt.png>
</picture>
<br />
<em>
A modern implementation of JSON Web Token (JWT) for Python.
<br />
With powerful Pydantic validation features.
</em>
</p>

<a href="https://github.com/ixunio/superjwt/actions?query=event%3Apush+workflow%3ACI+branch%3Amain++"><img alt="GitHub Actions workflow status on main branch" src="https://img.shields.io/github/actions/workflow/status/ixunio/superjwt/ci.yml?branch=main&logo=github-actions&logoColor=white&label=CI"></a>
<a href="https://codecov.io/github/ixunio/superjwt"><img src="https://codecov.io/github/ixunio/superjwt/graph/badge.svg?token=RF0O8W5LKG"/></a>
</div>
<div align="center">
<a href="https://pypi.org/project/superjwt/#history"><img alt="PyPI - Version" src="https://img.shields.io/pypi/v/superjwt?color=blue"></a>
<a href="https://pypi.org/project/superjwt/#history"><img alt="Supported Python versions" src="https://img.shields.io/pypi/pyversions/superjwt.svg?logo=python&logoColor=white"></a>

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
from superjwt import JWTClaims, encode, decode

secret_key = "your-secret-key-of-len-32-bytes!"

claims = {"iss": "my-app", "sub": "John Doe"}

token: bytes = encode(claims, secret_key, "HS256")
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSJ9.HwnUqTLFAMzNkMrokd0aI7c-zSJJpSVXMrYIhUyWe4s'
decoded: dict = decode(token, secret_key, "HS256", claims_validation=JWTClaims)
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

token: bytes = encode(claims, secret_key, "HS256")
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSIsImlhdCI6MTc2NzAyNzQ4MywiZXhwIjoxNzY3MDI4MzgzfQ.ZXxZT8VzL8IPTov-enslCh57S2M5fQBtqULZx5zEAm8'
decoded: dict = decode(token, secret_key, "HS256", claims_validation=JWTClaims)
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

##### Valid Claims Example

```python
claims = (
    MyJWTClaims(sub=123, user_id="b2a4c791-2cf4-4e41-9a20-8532129ff47c")
    .with_issued_at()
    .with_expiration(minutes=15)
)
token = encode(claims, secret_key, "HS256")
decoded = decode(token, secret_key, "HS256", claims_validation=MyJWTClaims)
#> decoded = {'sub': 123, 'iat': 1767026691, 'exp': 1767027591, 'user_id': 'b2a4c791-2cf4-4e41-9a20-8532129ff47c'}
```

##### Invalid Claims Example

```python
# create a non-validated and invalid pydantic claims
invalid_claims = (
    MyJWTClaims.model_construct(**{"sub": "John Doe", "user_id": "invalid-uuid-string"})
    .with_issued_at()
    .with_expiration(minutes=10)
)
# disable claims validation to create an invalid token
invalid_token = encode(
    invalid_claims, secret_key, "HS256", claims_validation=None
)
try:
    decoded_invalid = decode(invalid_token, secret_key, "HS256", claims_validation=MyJWTClaims)
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
