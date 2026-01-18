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
<br />

<a href="https://ixunio.github.io/superjwt/"><strong><em>See documentation</em></strong></a>
</div>

## Overview & Installation

SuperJWT is a minimalist JWT library for Python 3.10+ that combines the simplicity of JWT encoding/decoding with the power of [Pydantic](https://docs.pydantic.dev/latest/) validation. It supports JWS (JSON Web Signature) format, HMAC and asymmetric algorithms (RSA, ECDSA, EdDSA). SuperJWT includes advanced features like enhanced time integrity checks, compact token inspection, custom timestamp serialization, detached payload mode, time spoofing and more.

**Key Features:**

- 🔐 **Secure by default** - JWS signature algorithm required.
- 🪶 **Minimalist** - Clean, modern code with minimal dependencies.
- ✔️ **JWT validation** - Easy claims validation with Pydantic models.
- 🏷️ **Type hints** - IDE autocompletion with your JWT claims or JOSE headers.

**Install via pip:**

```bash
pip install superjwt
```

---

## Usage

SuperJWT makes it easy to encode and decode JWT tokens with automatic validation and serialization. Here are the fundamental operations:

### Basic Usage 🐣

Encode manually your claims from a `dict`. During decoding, validate your JWT content against a standard JWT claims Pydantic model.

```python
from superjwt import Alg, JWTClaims, encode, decode

secret_key = "your-secret-key-of-len-32-bytes!"

compact: bytes = encode({"iss": "my-app", "sub": "John Doe"}, secret_key, Alg.HS256)
print(compact)
#> b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
#   .eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSJ9
#   .HwnUqTLFAMzNkMrokd0aI7c-zSJJpSVXMrYIhUyWe4s'

decoded: JWTClaims = decode(compact, secret_key, Alg.HS256)
print(decoded.to_dict())
#> {'iss': 'my-app', 'sub': 'John Doe'}
print(decoded.sub)
#> 'John Doe'
```

Define dynamically your claims with Pydantic and easily include `'iat'` (Issued At) and `'exp'` (Expiration).
Validate your JWT content automatically during encoding and decoding. 

```python
from superjwt import Alg, JWTClaims, encode, decode

secret_key = "your-secret-key-of-len-32-bytes!"

claims = (
    JWTClaims(iss="my-app", sub="John Doe")
    .with_issued_at()
    .with_expiration(minutes=15)
)

compact: bytes = encode(claims, secret_key, Alg.HS256)

decoded: JWTClaims = decode(compact, secret_key, Alg.HS256)
print(decoded.to_dict())
#> {'iss': 'my-app', 'sub': 'John Doe', 'iat': 1767027483, 'exp': 1767028383}
print(decoded.exp)
#> 1767028383
```

### Custom Claims and Validation

Redefine standard claims or define new custom ones. Validate automatically during encoding and decoding.

```python
from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, Field
from superjwt import Alg, JWTClaims, Validation, decode, encode
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # redefine 'sub' as required integer
    sub: int = Field(default=...)

    # new custom claim:  'user_id' is required and must be a valid UUIDv4 string
    user_id: Annotated[str, AfterValidator(lambda x: str(UUID(x, version=4)))]
```

```python
# Example - Validation PASSING

claims = (
    MyJWTClaims(sub=123, user_id="b2a4c791-2cf4-4e41-9a20-8532129ff47c")
    .with_expiration(minutes=15)
)
compact = encode(claims, secret_key, Alg.HS256)
decoded: MyJWTClaims = decode(compact, secret_key, Alg.HS256, validation=MyJWTClaims)
print(decoded.to_dict())
#> {'sub': 123, 'exp': 1767027591, 'user_id': 'b2a4c791-2cf4-4e41-9a20-8532129ff47c'}
```

```python
# Example - Validation FAILING

# create an invalid pydantic claims
invalid_claims = (
    MyJWTClaims.model_construct(**{"sub": "John Doe", "user_id": "invalid-uuid-string"})
    .with_issued_at()
    .with_expiration(minutes=10)
)

# disable claims validation to create an "invalid" compact token
invalid_compact = encode(
    invalid_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
)
try:
    decode(invalid_compact, secret_key, Alg.HS256, validation=MyJWTClaims)
except ClaimsValidationError as e:
    print("Claims validation error:", e)
    #> Claims validation error: Claims validation failed
    #    claim ('sub',) = John Doe -> validation failed (int_parsing): 
    #      Input should be a valid integer, unable to parse string as an integer
    #    claim ('user_id',) = invalid-uuid-string -> validation failed (value_error):
    #      Value error, badly formed hexadecimal UUID string
```

### Compact Token Inspection

> [!CAUTION]
> When using `inspect()`, the JWT is not verified! Never trust the data until it is verified by `decode()`.

```python
from superjwt import JWSToken, inspect

compact = (
    b"eyJhbGciOiJOb05lIiwidHlwIjoiSldUIn0"
    b"."
    b"eyJjYW5fSV90cnVzdF95b3UiOiJubyJ9"
    b"."
    b"BsUynvYTk4w4_TCS39qAUoovSmS7hJxG4fahZGK9RrY"
)

token: JWSToken = inspect(compact)

print(token.payload)
#> {'can_I_trust_you': 'no'}

print(token.headers)
#> {'alg': 'NoNe', 'typ': 'JWT'}
```

<a href="https://ixunio.github.io/superjwt/"><strong><em>See full documentation</em></strong></a>

## Test

1. Clone repository

2. Install dependencies
    ```bash
    pip install -e .[asymmetric] --group test
    ```
3. Run tests
    ```bash
    pytest
    ```
