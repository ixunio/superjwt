<style>
/* Hide the h1 title in the main content area */
.md-content h1 {
    display: none;
}
</style>

![superjwt full logo](../assets/logo-full-superjwt.png)

<p align="center">
<em>
A modern implementation of JSON Web Token (JWT) for Python.
<br />
With powerful Pydantic validation features.
</em>
</p>
<div align="center">

</div>
<div align="center">
<img alt="GitHub Actions workflow status on main branch" src="https://img.shields.io/github/actions/workflow/status/ixunio/superjwt/ci.yml?branch=main&logo=github-actions&logoColor=white&label=CI">
<img alt="Codecov" src="https://img.shields.io/codecov/c/github/ixunio/superjwt">
</div>
<div align="center">
<img alt="PyPI - Version" src="https://img.shields.io/pypi/v/superjwt?color=blue">
<img alt="Supported Python versions" src="https://img.shields.io/pypi/pyversions/superjwt.svg?logo=python&logoColor=white">
</div>

---

## Overview & Installation

SuperJWT is a minimalist JWT library for Python 3.10+ that combines the simplicity of JWT encoding/decoding with the power of [Pydantic](https://docs.pydantic.dev/latest/) validation. It supports JWS (JSON Web Signature) format with HMAC-SHA2 algorithms and includes advanced features like detached payload mode. *[Learn more about JWT](../jwt/basics)*

**Key Features:**

- 🔐 **Secure by default** - Mandatory JWS signature algorithm.
- 🪶 **Minimalist** - Clean, modern code with minimal dependencies.
- ✔️ **JWT validation** - Easy claims validation with Pydantic models
- 🏷️ **Type hints** - IDE autocompletion with your JWT claims or JOSE headers.

**Install via pip:**

```bash
pip install superjwt
```

---

## Basic Usage 🐣

SuperJWT makes it easy to encode and decode JWT tokens with automatic validation and serialization. Here are the fundamental operations:

### Encode / Decode JWT

/// tab | With `JWTClaims`
    select: True

The `JWTClaims` ready-to-use Pydantic model allows you to add automatically the `iat` claim at the date/time of creation and validate all the other default optional registered claims you declare. See the list of official [registered claims](../jwt/content/#registered-claims).

##### Code sample
```python
from superjwt import encode, decode, JWTClaims

secret_key = "your-secret-key"

claims = JWTClaims(iss="my-app", sub="John Doe")
token: bytes = encode(claims, key=secret_key)
decoded: dict = decode(token, key=secret_key)
```

##### Results
```python
#> claims = JWTClaims(iss='my-app', sub='John Doe', aud=None, iat=datetime.datetime(2025, 12, 23, 23, 44, 44, tzinfo=datetime.timezone.utc), nbf=None, exp=None, jti=None)
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSIsImlhdCI6MTc2NjUzMzQ4NH0.qwu9S4C-mWCageyT9mX9cM0SPj6v1G4xsrd1pejZUS8'
#> decoded = {'iss': 'my-app', 'sub': 'John Doe', 'iat': 1766533484}
```

/// tip | `iat` is enabled by default
The `iat` claim (the Unix timestamp at which the JWT was issued) is automatically created. To disable it, use `JWTCompliantClaims` instead. See [Pydantic JWT Models](#pydantic-jwt-models).
///

///

/// tab | With `JWTCompliantClaims`

The `JWTCompliantClaims` ready-to-use Pydantic model allows you to validate all the default optional registered claims you declare. See the list of official [registered claims](../jwt/content/#registered-claims).

##### Code sample
```python
from superjwt import encode, decode, JWTClaims

secret_key = "your-secret-key"

claims = JWTCompliantClaims(iss="my-app", sub="John Doe")
token: bytes = encode(claims, key=secret_key)
decoded: dict = decode(token, key=secret_key)
```

##### Results
```python
#> claims = JWTCompliantClaims(iss='my-app', sub='John Doe', aud=None, iat=None, nbf=None, exp=None, jti=None)
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSJ9.szlGHnV58X8huJtw50McF4s_BN4zLorOgWjYP9jXqQY'
#> decoded = {'iss': 'my-app', 'sub': 'John Doe'}
```

///

/// tab | With `dict`

You can defined your claims manually with a Python `dict`. Even in this scenario, the standard registered JWT claims will still be automatically validated. See the list of all JWT [registered claims](../jwt/content/#registered-claims).

##### Code sample
```python
from superjwt import encode, decode

secret_key = "your-secret-key"

claims = {"iss": "my-app", "sub": "John Doe"}
token: bytes = encode(claims, key=secret_key)
decoded: dict = decode(token, key=secret_key)
```

##### Results
```python
#> claims = {'iss': 'my-app', 'sub': 'John Doe'}
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSJ9.szlGHnV58X8huJtw50McF4s_BN4zLorOgWjYP9jXqQY'
#> decoded = {'iss': 'my-app', 'sub': 'John Doe'}
```

///

/// note | Algorithm
Not providing an algorithm argument to encode() or decode() will default to the JWS Algorithm `HS256` (HMAC with SHA-256 signature) using a symmetric secret key. See [Algorithms](../security#jws-signature-algorithms) for a list of supported JWS algorithms.
///

---

### Set Token Expiration

/// tab | With `JWTClaims`
    select: True

Use `.with_expiration()` to returns a new `JWTClaims` with the updated `exp` timestamp claim. Choose your desired expiration relative to the JWT creation time. Accepts `days`, `hours`, `minutes`, and `seconds` delta.

##### Code sample
```python
from superjwt import encode, decode, JWTClaims

# Create JWT with 15 minutes expiration
claims = JWTClaims(sub="bob").with_expiration(minutes=15)
token = encode(claims, key=secret_key)
decoded = decode(token, key=secret_key)
```

##### Results
```python
#> claims = JWTClaims(iss=None, sub='bob', aud=None, iat=datetime.datetime(2025, 12, 24, 0, 8, 24, tzinfo=datetime.timezone.utc), nbf=None, exp=datetime.datetime(2025, 12, 24, 0, 23, 24, tzinfo=datetime.timezone.utc), jti=None)
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IiLCJpYXQiOjE3NjY1MzQ5MDQsImV4cCI6MTc2NjUzNTgwNH0.AYzDEdmH0J_pl9SRYAn2sYWfGDJxAYbCMQDVNkzNSI8'
#> decoded = {'sub': 'bob', 'iat': 1766534904, 'exp': 1766535804}
```

///

/// tab | With `JWTCompliantClaims`
    select: True

Use `.with_expiration()` to returns a new `JWTCompliantClaims` with the updated `exp` timestamp claim. Choose your desired expiration relative to the JWT creation time. Accepts `days`, `hours`, `minutes`, and `seconds` delta.

##### Code sample
```python
from superjwt import encode, decode, JWTClaims

# Create JWT with 15 minutes expiration
claims = JWTCompliantClaims(sub="bob").with_expiration(minutes=15)
token = encode(claims, key=secret_key)
decoded = decode(token, key=secret_key)
```

##### Results
```python
#> claims = JWTCompliantClaims(iss=None, sub='bob', aud=None, iat=None, nbf=None, exp=datetime.datetime(2025, 12, 24, 0, 37, 30, tzinfo=datetime.timezone.utc), jti=None)
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IiLCJleHAiOjE3NjY1MzY2NTB9.0eDUDCZjjve-dFS5Z6Oazc5xh53SHwKxAdmnZjACDHk'
#> decoded = {'sub': 'bob', 'exp': 1766536650}
```

///

/// tab | With `dict`

You can use a Python `dict` and add the `exp` timestamp claim as a Python datetime object. This will be automatically converted to an integer UNIX timestamp in the JWT.

##### Code sample
```python
from datetime import datetime, timedelta, UTC
from superjwt import encode, decode, JWTClaims

# Create JWT with 15 minutes expiration
claims = {"sub": "bob", "exp": datetime.now(UTC) + timedelta(minutes=15)}  # (1)
token = encode(claims, key=secret_key)
decoded = decode(token, key=secret_key)
```

1. Even though `exp` format is a Unix timestamp integer, thanks to internal Pydantic serialization, we can define a valid Python datetime, a float timestamp or an integer timestamp and it will be automatically converted to proper format. See [Datetime Claims](#datetime-claims)

##### Results
```python
#> claims = {'sub': 'bob', 'exp': datetime.datetime(2025, 12, 24, 0, 41, 59, 687287, tzinfo=datetime.timezone.utc)}
#> token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IiLCJleHAiOjE3NjY1MzY5MTl9.OYr8IF4TB3fAbCf_Alu9AKfhhMPSQPGAv4I-2jD0otg'
#> decoded = {'sub': 'bob', 'exp': 1766536919}
```

///

/// details | OAuth2.0 and short-lived JWT token
In a real production environment using OAuth2.0 standard, a logged-in user (the client) will exchange a short-lived JWT token generated by the web app (the server) with a lifespan of typically 15 minutes, this is called an "Access Token". Instead of having the user to log-in every 15 minutes, the server will try to regenerate a new Access Token as soon as the previous expires. How long can the server accept to regenerate a user Access Token depends on the validity of a second type of JWT token, valid for much longer, privately generated and kept on the server, called a "Refresh Token". See [OAuth2.0 Basic Example](integrations/oauth2) for real scenarios and code samples.
///

---

### Add Custom Claims

You can always add custom claims beyond standard registered claims. However, they won't be automatically validated without defining a custom JWT Pydantic model. See [Custom Validation](#custom-validation).

```python
from superjwt import JWTClaims


claims = JWTClaims(
    sub="Alice",
    jti="my-jwt-id",
    custom_claim="custom string",
    custom_date=1766536919  # (1)
)
token = encode(claims, key=secret_key)
decoded = decode(token, key=secret_key)
```

1. Without a custom JWT Pydantic model, you cannot input a datetime object and have an automatic serialization to UNIX timestamp. See [Datetime Claims](#datetime-claims).

```python
#> decoded = {'iss': 'my-app', 'sub': 'Alice', 'iat': 1766546874, 
#     'custom_claim': 'hi', 'custom_date': 1766536919}
```


You can do the other way around operation, making a JWTClaims from a dict and try to validate the data:
```python
from superjwt import JWTClaims

claims = {
    "sub": "user_123",
    "iss": 123,  # invalid format!
    "custom_claim": "hello"
}
try:
    # this will trigger a ValidationError as 'iss' must be a string or list[string]
    claims_dict = JWTClaims(**claims)
except ValidationError:
    # create a pydantic model without validation
    claims_dict = JWTClaims.model_construct(**claims)
print(claims_dict)
#> JWTClaims(iss=123, sub='user_123', aud=None, iat=datetime.datetime(2025, 12, 14, 12, 00, 00, tzinfo=datetime.timezone.utc), nbf=None, exp=None, jti=None, custom_claim='hello')
```

/// tip | Extra claims
`JWTClaims` Pydantic model is configured with `extra="allow"`, which allows to add any custom claims without explicit definition. Those custom claims will have no validation rules during encode() or decode(). Use a custom Pydantic model that inherits from JWTClaimsModel instead and that defines the new fields. See [Custom Claims](#custom-claims)
///

/// tip | Datetime objects
`iat`, `exp` and `nbf` represent all a datetime information and are coded as UNIX timestamp integer in the payload. But in the Pydantic model, they are stored as Python datetime objects! See more in [Datetime Objects](#datetime-claims).
///

---

## Advanced Usage 🤓

### Pydantic JWT Models

SuperJWT uses Pydantic for automatic validation and serialization of the JWT claims payload and headers during encoding and decoding. You can use ready-made Pydantic models or make your own.

<code style="font-size:1.1em">JWTBaseModel</code>

The base Pydantic model of SuperJWT that inherits from `pydantic.BaseModel`. All Pydantic models used in this package derive from `JWTBaseModel`. It has the following properties:

- **Custom fields**:<br>
by default, you can add extra fields to the model, even if not defined.<br>
`model_config = {"extra": "allow"}` is set in the Pydantic model.
- **Dump as dict**:<br>
a `.to_dict()` method serializes its non-empty fields data as a Python `dict`. This is equivalent to `pydantic.BaseModel.model_dump(exclude_none=True)` method.

<code style="font-size:1.1em">JOSEHeader</code>

Defines a compliant set of protected headers (JOSE Header). Inherits from `JWTBaseModel`, it has all of its properties plus:

- **Protected header values**<br>
defines mandatory `alg` value and a set of other optional values (`typ=JWT`, `kid`, `crit`)
- **b64=false is not supported**

```python
from superjwt import JOSEHeader

headers = JOSEHeader.make_default("ES256")
#> headers = {'alg': 'ES256', 'typ': 'JWT'}
```

<code style="font-size:1.1em">JWTCompliantClaims</code>

Defines a compliant claims set. Inherits from `JWTBaseModel`, has all of its properties plus:

- **Registered claims validation**<br>
defines all optional JWT [registered claims](../jwt/content/#registered-claims) as per [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- **Set expiration**:<br>
`.with_expiration()` method adds the JWT expiration, configured as a delta from JWT creation. See [Set Token Expiration](#set-token-expiration).
- **Check date/time consistency**:<br>
the model ensures that those three conditions are fulfilled for `iat` (issue at), `nbf` (not valid before), `exp` (expiration), provided each pair is declared:
    - `iat < nbf`, else raises `ValueError`
    - `iat < exp`, else raises `ValueError`
    - `nbf < exp`, else raises `ValueError`

```python
from datetime import datetime
from superjwt import JWTCompliantClaims

claims = JWTCompliantClaims(jti=1234, custom_jti=1234)
#> ValidationError: 1 validation error for JWTCompliantClaims
#> jti
#>  Input should be a valid string [type=string_type, input_value=1234, input_type=int]
claims = JWTCompliantClaims(jti="1234", custom_jti=1234).to_dict()
#> claims = {'jti': '1234', 'custom_jti': 1234}
```

<code style="font-size:1.1em">JWTClaims</code>

Inherits from `JWTCompliantClaims`, has all of its properties plus:

- ***Automatic Issued At***: add `iat` automatically when the object is created 

```python
claims = JWTClaims(sub="My Awesome User").to_dict()
#> claims = {'sub': 'My Awesome User', 'iat': 1766753149}
```

### Custom Validation

You can validate additional JWT claims or headers that you defined in your own pydantic model. Even though any pydantic.BaseModel should work, it is recommended to use a subclass of `JWTBaseModel` for ease of use and future compatibility.

#### Validate Extra Fields

/// tab | Claims - Example #1

```python
from pydantic import Field
from superjwt import JWTClaims, JWTDatetime, encode, decode

class MyCustomClaims(JWTClaims):

    # make 'iss' mandatory
    iss: str  # (1)

    # make 'exp' mandatory
    exp: JWTDatetime = Field(default=...)  # (2)

    # create a new required field
    items_id: list[str]

```

1. This syntax may trigger your python linter (`"iss" overrides a field of the same name but is missing a default value`), see [this](https://github.com/microsoft/pyright/issues/8766) pyright GitHub issue.
2. This is a syntax hack that won't trigger your Python linter and is identical to `exp: JWTDatetime`, see this GitHub issue.

///

/// tab | Claims - Example #2

///

/// tab | Headers

///

#### Datetime Fields

#### JWT Instance Object

```python
from superjwt import JWT, JWTClaims
from pydantic import Field, field_validator, model_validator
from typing import Self

class UserClaims(JWTClaims):
    # Override optional field to make it required
    sub: str = Field(default=...)
    
    # Add custom fields
    user_id: str
    email: str
    roles: list[str]
    permission_level: int = Field(ge=0, le=10)
    
    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        if not v.startswith("usr_"):
            raise ValueError("user_id must start with 'usr_'")
        return v
    
    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("Invalid email format")
        return v.lower()
    
    @model_validator(mode="after")
    def validate_admin_permissions(self) -> Self:
        # Admin users must have permission level >= 8
        if "admin" in self.roles and self.permission_level < 8:
            raise ValueError("Admin role requires permission level >= 8")
        return self

# Create claims with custom validation
claims = UserClaims(
    sub="john.doe",
    user_id="usr_123456",
    email="john.doe@example.com",
    roles=["user", "admin"],
    permission_level=9
)

# IMPORTANT: Use the same JWT() instance for encoding and decoding
# to maintain custom Pydantic validation
jwt = JWT()
token = jwt.encode(claims=claims, key="secret")
decoded = jwt.decode(token, key="secret")

print(decoded["user_id"])  # 'usr_123456'
print(decoded["email"])    # 'john.doe@example.com'
print(decoded["roles"])    # ['user', 'admin']
```

/// warning | Important: Same JWT Instance
When using custom Pydantic models with validators, you **must use the same `JWT()`instance** for both encoding and decoding. This ensures that your custom validation logic is applied during decoding as well.
///

**Example with dynamic extra fields:**

```python
from superjwt.definitions import JWTClaims
import superjwt

# You can add any custom field on the fly
claims = JWTClaims(
    sub="user_id",
    custom_field="custom_value",
    another_field={"nested": "data"}
)

token = superjwt.encode(claims=claims, key="secret")
decoded = superjwt.decode(token, key="secret")

print(decoded["custom_field"])  # 'custom_value'
```

---

### Datetime Claims

When defining claims that are date/time objects, the Pydantic serializer will understand both Python `datetime` objects and Python `int` or `float` representing UNIX timestamps. It will transform them internally to Python `datetime` objects with UTC timezone, stripped from their microseconds information. When dumped to the JWT payload, those fields will always be correctly cast as UNIX timestamp integers. This allow to work in Python with dynamic Python `datetime` objects and forget about the actual JWT content.

Example:
```python
from pydantic import Field
from superjwt import JWTClaims

class MyClaims(JWTClaims):
    exp: Field(default=...)  # make exp mandatory
    nbf: datetime


```

---

### Inspecting Tokens

For debugging purposes, you can inspect a token without verifying its signature:

```python
import superjwt

token = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'

# Inspect without signature verification
unsafe_token = superjwt.inspect(token)

# Access header information
print(unsafe_token.decoded.header)
# JOSEHeader(alg='HS256', typ='JWT', kid=None, crit=None)

# Access payload (claims)
print(unsafe_token.decoded.payload)
# {'sub': 'user_id', 'iat': 1734134400}

# Access individual header fields
print(unsafe_token.decoded.header.alg)   # 'HS256'
print(unsafe_token.decoded.header.typ)   # 'JWT'

# Access individual payload fields
print(unsafe_token.decoded.payload.get("sub"))  # 'user_id'
```

!!! danger "Production Warning"
    The `inspect()` function does **NOT** verify the token signature. This means the token could be tampered with or forged. **NEVER** use this function in production code or for security-critical operations. Use it only for debugging and development purposes.

---

### Disabling Claims Validation

In some scenarios, you may need to work with non-standard JWT claims or bypass validation temporarily:

```python
import superjwt

# Encode with validation disabled
token = superjwt.encode(
    claims={"custom": "data", "non_standard": "format"},
    key="secret",
    disable_claims_validation=True
)

# Decode with validation disabled
claims = superjwt.decode(
    token,
    key="secret",
    disable_claims_validation=True
)

print(claims)
# {'custom': 'data', 'non_standard': 'format', 'iat': 1734134400}
```

!!! warning "Security Note"
    Disabling validation only bypasses Pydantic's type checking and field validation. **Signature verification is still performed**, ensuring the token hasn't been tampered with. However, use this option cautiously and only when necessary.

---

### Detached Payload Mode

For bandwidth optimization when the payload is transmitted through a separate secure channel:

```python
from superjwt.jwt import JWT
from superjwt.definitions import JWTClaims

jwt = JWT()
claims = JWTClaims(sub="user123", iss="myapp")

# Encode normally
token = jwt.encode(claims=claims, key="secret")
print(token)
# b'eyJhbGc...eyJzdWIiOiJ1c2VyMTIzIn0...signature'

# Create detached version (empty payload part)
detached_token = jwt.detach_payload()
print(detached_token)
# b'eyJhbGc...eyJ9...signature'
# Notice the payload part is now just 'eyJ9' (empty JSON object)

# Later, decode with the detached payload
# You must provide the original claims
decoded = jwt.decode(
    detached_token,
    key="secret",
    with_detached_payload=claims
)

print(decoded)
# {'sub': 'user123', 'iss': 'myapp', 'iat': 1734134400}
```

!!! info "Use Cases"
    Detached payload mode is useful when:
    
    - Payload is transmitted through a separate secure channel (e.g., POST body while signature is in header)
    - You need to minimize token size in URLs or HTTP headers
    - The payload is already available at the receiving end
    - You want to sign large payloads without embedding them in the token

---

### Error Handling

SuperJWT provides specific exceptions for different error scenarios:

```python
from superjwt import encode, decode
from superjwt.definitions import JWTClaims
from superjwt.exceptions import (
    ClaimsValidationError,
    InvalidSignatureError,
    JWTError
)
from pydantic import Field

secret_key = "correct-secret"
wrong_key = "wrong-secret"

# Create a valid token
token = encode(claims={"sub": "user_id"}, key=secret_key)

# Example 1: Invalid Signature Error
try:
    decoded = decode(token, key=wrong_key)
except InvalidSignatureError as e:
    print(f"Signature verification failed: {e}")
    # Output: Signature verification failed: Invalid signature

# Example 2: Claims Validation Error
try:
    # Create claims with invalid data
    class UserClaims(JWTClaims):
        sub: str = Field(default=...)
        permission_level: int = Field(ge=0, le=10)
    
    invalid_claims = UserClaims(
        sub="user",
        permission_level=15  # Invalid: exceeds maximum of 10
    )
    token = encode(claims=invalid_claims, key=secret_key)
except ClaimsValidationError as e:
    print(f"Claims validation failed: {e}")
    print(f"Validation errors: {e.errors}")
    # Output includes detailed error information from Pydantic

# Example 3: General JWT Error
try:
    # Attempt to use an invalid token format
    decode(b"not-a-valid-token", key=secret_key)
except JWTError as e:
    print(f"JWT error: {e}")
```

**Error Hierarchy:**

- `JWTError` - Base exception for all JWT-related errors
    - `InvalidSignatureError` - Token signature verification failed
    - `ClaimsValidationError` - Claims don't pass Pydantic validation
    - `HeaderValidationError` - JOSE header validation failed
    - `AlgorithmNotSupportedError` - Requested algorithm not supported

---


## Asymmetric keys algorithms

### RSA

### ECDSA

### EdDSA


