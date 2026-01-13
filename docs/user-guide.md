## Encoding a JWT ⏫

The function `encode()` produces a compact (three-part) signed JWT/JWS.

/// details | See `encode()` parameters
| Function&nbsp;Parameters | Type | Description |
| :--- | :--- | :--- |
| `claims` | `JWTClaims` \| `dict` \| `None` | The claims data for the JWT payload. |
| `key` | `Key` \| `bytes` \| `str` | The key to sign the JWT with (a secret key, a private key in PEM format, or a `Key` instance). |
| `algorithm` | `Alg` \| `str` | The signing algorithm (e.g., `Alg.HS256` or `"HS256"`). |
| `headers` | `JOSEHeader` \| `dict` \| `None` | *(optional)* Custom JOSE headers. |
| `detach_payload` | `bool` | *(optional)* If `True`, produces a detached payload JWT. |
| `claims_validation` | `type[JWTBaseModel]`<br> &nbsp;&nbsp;\| `ValidationConfig`<br> &nbsp;&nbsp;\| `Validation` | *(optional)* Validation settings for claims. If `claims` is a Pydantic model it is validated automatically. |
| `headers_validation` | `type[JWTBaseModel]`<br> &nbsp;&nbsp;\| `ValidationConfig`<br> &nbsp;&nbsp;\| `Validation` | *(optional)* Validation settings for headers. If `headers` is a Pydantic model it is validated automatically. |
///

### Examples

/// tab | Basic<br>Example

The `JWTClaims` Pydantic model allows you to create and validate all official registered claims automatically. See [JWTClaims Pydantic model](#jwtclaims).

```python
from superjwt import Alg, JWTClaims, encode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

claims = JWTClaims(iss="my-app", sub="John Doe")
print(claims)
#> JWTClaims(iss='my-app', sub='John Doe', aud=None, iat=None, nbf=None, exp=None, jti=None)

compact: bytes = encode(claims, secret_key, Alg.HS256)
print(compact)
#> b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
#   .eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSJ9
#   .HwnUqTLFAMzNkMrokd0aI7c-zSJJpSVXMrYIhUyWe4s'

print(inspect(compact).payload)
#> {'iss': 'my-app', 'sub': 'John Doe'}
```

///

/// tab | Data from<br>a `dict`

You can define your claims manually from a Python `dict`.

```python
from superjwt import Alg, encode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

claims_dict = {"iss": "my-app", "sub": "John Doe"}

compact = encode(claims_dict, secret_key, Alg.HS256)  # (1)

print(inspect(compact).payload)
#> {'iss': 'my-app', 'sub': 'John Doe'}
```

1. When encoding from a raw `dict`, the claims are automatically validated against `JWTClaims` to ensure compliance with JWT standards. You can also [disable validation](#disable-validation).


///

/// tab | Invalid Token<br>Example


```python
from superjwt import Alg, JWTClaims, encode
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

claims = JWTClaims.model_construct(jti=1234)  # (1)

try:
    encode(claims, secret_key, Alg.HS256)  # --> ❌ fails (2)
except ClaimsValidationError as e:
    print(e)
    #> ClaimsValidationError: Claims validation failed
    #> claim ('jti',) = 1234 -> validation failed (string_type): Input should be a valid string
```

1. `.model_construct()` creates a Pydantic instance without validating its model. This allows for the creation of an invalid Pydantic instance without raising a `pydantic.ValidationError`.
2. During encoding, if the `claims` object is a Pydantic instance, validation runs automatically based on its own Pydantic model. Since `'jti'` is not a `str`, a `ClaimsValidationError` is raised. To disable validation, see [Disable Validation](#disable-validation).

///

/// tab | With Extra<br>Fields

You can add custom claims as extra fields beyond the registered claims. However, these fields won't be validated unless you define your own Pydantic model. See the [custom model example](#with-a-custompydantic-model).

```python
from superjwt import Alg, JWTClaims, encode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

claims = JWTClaims(
    sub="Alice", jti="jwt-id",
    custom_claim="a string",
    custom_date=1766536919  # (1)
)
compact = encode(claims, secret_key, Alg.HS256)

print(inspect(compact).payload)
#> {'sub': 'Alice', 'jti': 'jwt-id', 'custom_claim': 'a string', 'custom_date': 1766536919}
```

1. Without a custom Pydantic model, you cannot pass a Python `datetime` object and have it automatically serialized to a UNIX timestamp.

/// tip | Extra claims
The `JWTClaims` Pydantic model is configured with `extra="allow"`, which allows adding custom claims without explicit definition. These custom claims will not have validation rules during `encode()` or `decode()`. To include validation, use a custom model that inherits from `JWTClaims`. See [Pydantic Models](#pydantic-models) and [Validation](#validation).
///

///

/// tab | With a Custom<br>Pydantic Model

See [Custom Models](#custom-models) for more information about custom Pydantic models and custom validation.

```python
from datetime import datetime
from pydantic import AfterValidator, Field
from superjwt import Alg, JWTClaims, JWTDatetime, encode, inspect
from typing import Annotated
from uuid import UUID

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    sub: int = Field(default=...)  # 'sub' is redefined as a required integer
    user_id: Annotated[str, AfterValidator(lambda x: str(UUID(x, version=4)))]  # must be UUIDv4
    custom_date: JWTDatetime  # must be a datetime/timestamp

claims = MyJWTClaims(
    sub=1234,
    user_id="d134196e-f27e-4c0b-a7b8-fedca264e51f",
    custom_date=datetime(2025, 12, 31, 23, 59, 59, 987654)  # (1)
)

compact: bytes = encode(claims, secret_key, Alg.HS256)
print(inspect(compact).payload)
#> {'sub': 1234, 'user_id': 'd134196e-f27e-4c0b-a7b8-fedca264e51f', 'custom_date': 1767225599}
```

1. We passed a Python `datetime` to the `JWTDatetime` field `'custom_date'`. It is automatically serialized as a timestamp in the JSON output. See [Datetime Fields](#datetime-fields).

///

### Add Issued At &#8680; `'iat'`

You can automatically add the `'iat'` (Issued At) claim. The value will be set to the current UTC time.

```python
from superjwt import Alg, JWTClaims, encode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

claims = (
    JWTClaims(iss="my-app", sub="John Doe")
    .with_issued_at()
)
print(claims)
#> JWTClaims(iss='my-app', sub='John Doe', aud=None, 
#    iat=datetime.datetime(2026, 1, 8, 2, 9, 15, 603171, tzinfo=datetime.timezone.utc), (1)
#    nbf=None, exp=None, jti=None)

compact: bytes = encode(claims, secret_key, Alg.HS256)
print(inspect(compact).payload)
#> {'iss': 'my-app', 'sub': 'John Doe', 'iat': 1767838155} (2)
```

1. We have added the creation time. In the `JWTClaims` Pydantic instance, the value is stored as a Python `datetime` (UTC). It is automatically serialized as a timestamp in the JSON output.
2. By default, timestamps are serialized as integers, but this can be changed to floats. See [Datetime Fields](#datetime-fields).

### Set Expiration &#8680; `'exp'`

/// tab | Basic<br>Example

Use `.with_expiration()` to return a new `JWTClaims` instance with the `'exp'` timestamp set. Choose your desired expiration as a duration from the time of creation. It accepts `days`, `hours`, and `minutes` as arguments.

```python
from superjwt import Alg, JWTClaims, encode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

claims = (
    JWTClaims(sub="Jane Doe")
    .with_expiration(minutes=15)
)

compact = encode(claims, secret_key, Alg.HS256)
print(inspect(compact).payload)
#> {'sub': 'Jane Doe', 'exp': 1767045509}  (1)
```

1. By default, timestamps are serialized as integers. See [Datetime Fields](#datetime-fields).

///

/// tab | Include `'iat'`<br> as well

Use `.with_expiration()` chained with `.with_issued_at()` to return a new `JWTClaims` instance with both updated `'iat'` and `'exp'` timestamp claims.

```python
from superjwt import Alg, JWTClaims, encode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

claims = (
    JWTClaims(sub="Jane Doe")
    .with_issued_at()
    .with_expiration(minutes=10)
)

compact = encode(claims, secret_key, Alg.HS256)
print(inspect(compact).payload)
#> {'sub': 'Jane Doe', 'iat': 1767044818, 'exp': 1767045418}
```
///

/// tab | Data from a `dict`<br><small>(Python 3.11+)</small>

You can use a Python `dict` and add the `'exp'` timestamp manually.

```python
from datetime import datetime, timedelta, UTC
from superjwt import Alg, encode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

claims = {"sub": "Jane Doe", "exp": (datetime.now(UTC) + timedelta(minutes=15)).timestamp()}

compact = encode(claims, secret_key, Alg.HS256)
print(inspect(compact).payload)
#> {'sub': 'Jane Doe', 'exp': 1767046329.859796}  # (1)
```

1. Since the claims were passed as a raw `dict`, no Pydantic validation or serialization is performed. Therefore, the timestamp remains a `float`. See [Datetime Fields](#datetime-fields).

///

/// details | Date/time objects
`iat`, `exp` and `nbf` represent all date/time information and are serialized as UNIX timestamp in the payload. But in a Pydantic model, they are stored as Python datetime objects! See more in [Datetime Fields](#datetime-fields).
///

---

## Decoding a JWT ⏬

The function `decode()` decodes and verifies a compact (three-part) signed JWT/JWS. It can optionally perform [validation](#validation) on JWT content.

/// details | See `decode()` parameters
| &nbsp;Function&nbsp;Parameters&nbsp; | Type | Description |
| :--- | :--- | :--- |
| `compact` | `bytes` \| `str` | The JWT compact token to decode. |
| `key` | `Key` \| `bytes` \| `str` | The key to verify the JWT with (a secret key, a private key in PEM format, or a `Key` instance). |
| `algorithm` | `Alg` \| `str` | The verifying algorithm (e.g., `Alg.HS256` or `"HS256"`). |
| `with_detached_payload` | `JWTClaims` \| `dict` \| `None` | *(optional)* The detached payload data, if the token was encoded with a detached payload. |
| `claims_validation` | `type[JWTBaseModel]`<br> &nbsp;&nbsp;\| `ValidationConfig`<br> &nbsp;&nbsp;\| `Validation` | *(optional)* Validation settings for claims. See [Validation](#validation). |
| `headers_validation` | `type[JWTBaseModel]`<br> &nbsp;&nbsp;\| `ValidationConfig`<br> &nbsp;&nbsp;\| `Validation` | *(optional)* Validation settings for headers. By default, headers are validated against `JOSEHeader`. |
///

/// tip | JWT Signature Verification
When using the `decode()` function, the JWT compact token is automatically verified. If the content of the JWT has been tampered with, or if the key used for decoding is incorrect, verification fails and a `SignatureVerificationError` is raised. See the [example below](#invalid-token--verification-failed).
///

### Examples

/// tab | Basic<br>Example

During decoding, compact token are automatically verified and validated against [JWTClaims](#jwtclaims) Pydantic model.

```python
from superjwt import Alg, decode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

compact = (
    b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    b"eyJpc3MiOiJteS1hcHAiLCJzdWIiOiJKb2huIERvZSJ9."
    b"HwnUqTLFAMzNkMrokd0aI7c-zSJJpSVXMrYIhUyWe4s"
)
print(inspect(compact).payload)  # (1)
#> {'iss': 'my-app', 'sub': 'John Doe'}

decoded: dict = decode(compact, secret_key, Alg.HS256)  # (2)
print(decoded)
#> {'iss': 'my-app', 'sub': 'John Doe'}
```

1.  /// danger | Unverified JWT

    Token inspection DOES NOT verify the signature! Never trust information from an unverified JWT. Only the `decode()` function guarantees integrity.
    ///
2. The token was successfully verified and validated against the `JWTClaims` Pydantic model. Use the `claims_validation` parameter to validate against your own custom models. See [Validation](#validation).

///

/// tab | Invalid Token -<br>Verification Failed
The token may have been tampered with!
```python
from superjwt import Alg, decode, inspect
from superjwt.exceptions import SignatureVerificationError

secret_key = "your-secret-key-of-len-32-bytes!"

compact = (
    b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    b"eyJjYW5fSV90cnVzdF95b3UiOiJubyJ9."
    b"BsUynvYTk4w4_TCS39qAUoovSmS7hJxG4fahZGK9RrY"
)

try:
    decode(compact, secret_key, Alg.HS256)  # --> ❌ fails (1)
except SignatureVerificationError as e:
    print(inspect(compact).payload)
    #> {'can_I_trust_you': 'no'}
    print(e)
    #> Signature verification failed, the token may have been tampered with!

```

1. 😱 The token might have been tampered with, or the secret key is incorrect.
///

/// tab | Invalid Token -<br>Validation Failed
When claims validation fails, a `ClaimsValidationError` is raised. This does not change the fact that the token has been verified and is authentic. See [Validation](#validation).
```python
from superjwt import Alg, Validation, decode, inspect
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

compact = (
    b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    b"eyJpc3MiOnRydWV9."
    b"PfIcUJHW8m8qRD-Lu4Sj5tCuN1cRGjNAjhxtXzXM6_U"
)
print(inspect(compact).payload)  # (1)
#> {'iss': True}

try:
    decode(compact, secret_key, Alg.HS256)  # --> ❌ fails (2)
except ClaimsValidationError as e:
    print(e)
    #> Claims validation failed
    #> claim ('iss',) = True -> validation failed (string_type): Input should be a valid string
    
    decoded = decode(
        compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
        )  # --> 🤔 passes (3)
    print(decoded)
    #> {'iss': True}

```

1.  /// danger | Unverified JWT

    Token inspection DOES NOT verify the signature! Never trust information from an unverified JWT.
    ///
2. By default, `decode()` validates claims against `JWTClaims`. Since `'iss'` must be a string, validation fails.
3. To decode without validation, explicitly use `Validation.DISABLE`. The JWT is still verified, proving its authenticity.

///

/// tab | Validation -<br>Custom Model
See [Custom Models](#custom-models).

```python
from pydantic import Field
from superjwt import Alg, JWTClaims, decode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    custom_field: int = Field(default=...)

compact = (
    b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    b"eyJzdWIiOiJ1c2VyIiwiY3VzdG9tX2ZpZWxkIjo0Mn0."
    b"m4CHuuAgVICiDVeDcJwTT7Vf0yG3skwzsyp9mroxdw0"
)
print(inspect(compact).payload)  # (1)
#> {'sub': 'user', 'custom_field': 42}

decoded = decode(compact, secret_key, Alg.HS256, claims_validation=MyJWTClaims)
print(decoded)
#> {'sub': 'user', 'custom_field': 42}
```

1.  /// danger | Unverified JWT

    A compact token inspection DOES NOT verify the signature! Never trust the information from an unverified JWT. Only the `decode()` function will prove the JWT integrity.
    ///

///


/// tab | Validation -<br>Validation Config
See [Validation Config](#validation-config).

```python
from pydantic import Field
from superjwt import Alg, JWTClaims, ValidationConfig, decode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    custom_field: int = Field(default=...)

validation = ValidationConfig(
    validation_model=MyJWTClaims,
    leeway=30.0,  # (1)
)

compact = (
    b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    b"eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNzY3ODQ1OTM4LCJleHAiOjE3Njc4NDY4MzgsImN1c3RvbV9maWVsZCI6NDJ9."
    b"EGNJ2bGmuhTlQa45xMs1HG2gnGNDoy632mgAx-rhk6g"
)
print(inspect(compact).payload)  # (2)
#> {'sub': 'user', 'iat': 1767845938, 'exp': 1767846838, 'custom_field': 42}

decoded = decode(compact, secret_key, Alg.HS256, claims_validation=validation)
print(decoded)
#> {'sub': 'user', 'iat': 1767845938, 'exp': 1767846838, 'custom_field': 42}
```

1. By creating a `ValidationConfig` instance to be passed to `claims_validation` parameter, you can change other behaviors like the leeway when decoding `'iat'`, `'exp'`, `'nbf'` claims.
2.  /// danger | Unverified JWT

    A compact token inspection DOES NOT verify the signature! Never trust the information from an unverified JWT. Only the `decode()` function will prove the JWT integrity.
    ///

///

### Token Expired

A token that has expired (i.e., its `'exp'` value is in the past) will raise a `TokenExpiredError` during validation.

/// details | Code Example
    type: example

```python
# Python 3.11+
from datetime import datetime, timedelta, UTC
from superjwt import Alg, JWTClaims, Validation, decode, encode
from superjwt.exceptions import TokenExpiredError


secret_key = "your-secret-key-of-len-32-bytes!"

# create a fake expired compact token
compact = encode(
    JWTClaims.model_construct(exp=datetime.now(UTC) - timedelta(days=1)),  # (1),
    secret_key,
    Alg.HS256,
    claims_validation=Validation.DISABLE
)

# decode token
try:
    decode(compact, secret_key, Alg.HS256)  # --> ❌ fails (2)
    #> TokenExpiredError: Token has expired
except TokenExpiredError:
    decoded = decode(
        compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE
        )  # --> 🤔 passes (3)
    print(decoded)
    #> {'exp': 1766960212}
```

1. `.model_construct()` creates a Pydantic instance without running validation.
2. Since `'exp'` is in the past, the token fails `JWTClaims` validation.
3. If we decode without claims validation, the token is returned (it was successfully verified), regardless of its content.

///

/// details | OAuth2.0 and short-lived JWT token
In a production environment using OAuth2.0, a logged-in user (the client) typically receives a short-lived "Access Token" (e.g., 15 minutes). Instead of requiring a login every 15 minutes, the server can issue a new Access Token for the user. See the [OAuth2.0 Basic Example](integrations/oauth2.md) for real-world scenarios.
///


### Inspecting Tokens

For debugging purposes, you can inspect a token without verifying its signature:

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

token.payload
#> {'can_I_trust_you': 'no'}

token.headers
#> {'alg': 'NoNe', 'typ': 'JWT'}
```

/// danger | Unsafe operation
The `inspect()` function does **NOT** verify the JWT content. This means the token could be tampered with or forged.

**NEVER** rely on `inspect()` in production or for security-critical operations. Use it only for debugging and development.
///

---

## Pydantic Models ♦️

SuperJWT uses Pydantic for automatic validation and serialization of JWT claims and headers. You can use ready-made Pydantic models or create your own by inheriting from the following base models.

### <code style="font-size:1.1em">JWTBaseModel</code>

The base Pydantic model for SuperJWT, which inherits from `pydantic.BaseModel`. All Pydantic models used in this package derive from `JWTBaseModel`. It includes the following features:

- **Extra Fields**<br>
    By default, extra fields are allowed, even if not explicitly defined.
- **Serialization**<br>
    The `.to_dict()` method serializes non-empty fields into a Python `dict`. This is similar to `pydantic.BaseModel.model_dump(exclude_none=True)` but with internal context injected.
- **Internal Settings**<br>
    \> `now`: Allows for time spoofing by setting a value for the "present time".<br>
    \> `jwtdatetime_force_int`: Forces all `JWTDatetime` timestamps to be integers instead of floats (default: `True`).<br>
    See [Validation Config](#validation-config).
- **Auto-Revalidation**<br>
    Automatically revalidates Pydantic instances (equivalent to `revalidate_instances="always"`).

### <code style="font-size:1.1em">JOSEHeader</code>

Inherits from `JWTBaseModel` and defines a compliant set of protected headers (JOSE Header).

Properties:

- **Protected Header Values**<br>
    Defines a mandatory `alg` field and other optional fields such as `'typ'='JWT'`, `'kid'`, and `'crit'`.
- **Default Headers Model for Validation**<br>
    Headers are validated against this model when `headers_validation` is not set in `decode()`.
- **Make Default Method**<br>
    Creates header data with the required `'alg'` field populated.
    ```python
    from superjwt import Alg, JOSEHeader

    headers = JOSEHeader.make_default(Alg.ES256)
    #> {'alg': 'ES256', 'typ': 'JWT'}
    ```

- **No Support for `b64=false`**

<h3><code style="font-size:1.1em">JWTClaimsModel</code></h3>

Inherits from `JWTBaseModel`: an internal model that defines all standard JWT [registered claims](jwt/content.md#registered-claims).

### <code style="font-size:1.1em">JWTClaims</code>

Inherits from `JWTClaimsModel` and defines a compliant JWT claims set.

Properties:

- **Compliance with RFC 7519**<br>
    A compliant Pydantic model for standard JWT payloads. Defines all standard registered claims with proper Python types.

    /// details | List of registered claims
    - `'iss'`, optional `str`
    - `'sub'`, optional `str`
    - `'aud'`, optional `str` or `list[str]`
    - `'iat'`, optional `JWTDatetime`
    - `'nbf'`, optional `JWTDatetime`
    - `'exp'`, optional `JWTDatetime`
    - `'jti'`, optional `str`
    ///

    /// details | Code Examples
        type: example
    
    /// tab | Example #1
    ```python
    from pydantic import ValidationError
    from superjwt import JWTClaims

    try:
        JWTClaims(sub=1234, user_id=1234)
        #> ValidationError: 1 validation error for JWTClaims
        #> sub
        #>   Input should be a valid string [type=string_type, input_value=1234, input_type=int]
    except ValidationError:
        claims_dict = JWTClaims(sub="1234", user_id=1234).to_dict()
        #> {'sub': '1234', 'user_id': 1234}
    ```
    ///
    /// tab | Example #2
    ```python
    from pydantic import ValidationError
    from superjwt import JWTClaims

    claims = {"iss": 123, "sub": "user_123", "custom_claim": "hello"}

    try:
        JWTClaims(**claims)
        #> ValidationError: 1 validation error for JWTClaims
        #> iss
        #>   Input should be a valid string [type=string_type, input_value=123, input_type=int]
    except ValidationError:
        claims_dict = JWTClaims.model_construct(**claims).to_dict()  # do not validate model
        #> {'iss': 123, 'sub': 'user_123', 'custom_claim': 'hello'}
    ```
    ///
    ///

- **Default Claims Model for Validation**<br>
    Claims are validated against this model when `claims_validation` is not set in `decode()`.
- **Time Integrity Checks**<br>
    Ensures the following conditions are met for `'iat'`, `'nbf'`, and `'exp'`:
    - `'iat'` < *now* (can be disabled with `allow_future_iat`, see [Validation Config](#validation-config))
    - `'nbf'` < *now*
    - `'exp'` > *now*
- **Token Time Validity**<br>
    Raises `TokenExpiredError` if the token has expired (given `'exp'` claim timestamp) or `TokenNotYetValidError` if it is not yet valid (given `'nbf'` claim timestamp).
- **Time Leeway**<br>
    Allows leeway (default: 5 seconds) during decoding to account for clock skew. Can be configured in a [Validation Config](#validation-config).
- **Time Claim Methods**<br>
    Shortcut methods like `.with_issued_at()` and `.with_expiration()`.

---

## Validation ☑️

In SuperJWT, **validation** refers to the process of ensuring that the JWT data—both headers and claims—complies with a predefined structure and set of rules. While **verification** checks the integrity and authenticity of the token (proving it hasn't been tampered with), **validation** ensures that the information contained within the token meets your application's requirements, such as required fields, specific data types, or value constraints, typically through the use of Pydantic models.

There are several ways to validate your custom JWT data:

- By using Pydantic directly before encoding or after decoding.
- When using `decode()`, claims are validated against `JWTClaims` by default. You can specify a custom model via the `claims_validation` parameter or use a [ValidationConfig](#validation-config).
- When using `encode()`, raw `dict` claims are validated against `JWTClaims` by default, and Pydantic claims are validated against their own Pydantic model.

/// tab | Decoding Process
During decoding, claims validation happens **after** the JWT is verified. Validation can be [disabled](#disable-validation).

```mermaid
graph LR
    HV["`**Headers Validation**
    *(HeadersValidationError)*`"] --> S["`🔏 **Signature Verification**
    *(SignatureVerificationError)*`"]
    S --> CV["`✔️ **Claims Validation**
    *(ClaimsValidationError)*`"]
```
///

/// tab | Encoding Process
During encoding, claims validation happens **before** the JWT is signed. Validation can be [disabled](#disable-validation).

```mermaid
graph LR
    CV["`**Claims Validation** ✔️
    *(ClaimsValidationError)*`"] --> HV["`**Headers Validation**
    *(HeadersValidationError)*`"]
    HV --> S["`**JWT Signature** 🔏`"]
```

///

### Custom Models

You can create custom Pydantic models by extending `JWTClaims` or `JWTBaseModel` to define your own fields and validation rules. For custom headers, inherit from `JOSEHeader`. See [Pydantic Models](#pydantic-models).

/// tab | Custom Claims<br><small>Example #1</small>

<h4>Claims</h4>

```python
from pydantic import AfterValidator, Field, ValidationError
from superjwt import Alg, JWTClaims, JWTDatetime
from superjwt.exceptions import ClaimsValidationError
from typing import Annotated
from uuid import UUID

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # 'exp' is required
    exp: JWTDatetime  # (1)

    # 'sub' is required and its type is changed to integer
    sub: int = Field(default=...)  # (2)

    # 'user_id' is optional and must be a valid UUIDv4 string
    user_id: Annotated[str | None, AfterValidator(lambda x: str(UUID(x, version=4)))]
    

claims = MyJWTClaims.model_construct(
    sub=12345, user_id="not-a-uuidv4"
    ).with_expiration(minutes=15)  # (3)

try:
    claims.revalidate()  # --> ❌ fails
except ValidationError:
    claims.user_id = "d4dc7b96-36cc-4ab5-846e-17e4fc85bf6d"
    claims.revalidate()  # --> ✅ passes

claims.to_dict()
#> {'sub': 12345, 'user_id': 'd4dc7b96-36cc-4ab5-846e-17e4fc85bf6d', 'exp': 1767652061}
```

1. This syntax may trigger your python linter (`"iss" overrides a field of the same name but is missing a default value`), see [this](https://github.com/microsoft/pyright/issues/8766) pyright GitHub issue.<br><br>Note that `JWTDatetime` is the standard internal type for date/time data in SuperJWT. Internally, it is stored as a Python `datetime` (UTC) and serialized as a UNIX timestamp (integer by default). See [Datetime Fields](#datetime-fields).

2. This syntax redefines a field while maintaining linter compatibility.

3. `.model_construct()` creates a Pydantic instance without running validation.

///

/// tab | Custom Claims<br><small>Example #2</small>

<h4>Claims</h4>

```python
from datetime import datetime, UTC
from pydantic import Field
from superjwt import Alg, JWTClaims, JWTDatetimeFloat, decode, encode
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # 'nbf' is required and serialized as a float timestamp
    nbf: JWTDatetimeFloat = Field(default=...)  # (1)

    # a new required field
    items_id: list[str]

claims = MyJWTClaims.model_construct(
    **{
        "nbf": datetime(2025, 12, 31, 23, 59, 59, 987654, tzinfo=UTC), 
        "items_id": ["banana", "apple", 1]
        }
    )

try:
    encode(claims, secret_key, Alg.HS256)  # --> ❌ fails (2)
except ClaimsValidationError:
    claims.items_id = ["banana", "apple", "orange"]
    compact = encode(claims, secret_key, Alg.HS256)  # --> ✅ passes (3)

decoded = decode(compact, secret_key, Alg.HS256, claims_validation=MyJWTClaims)  # --> ✅ passes
#> {'nbf': 1767225599.987654, 'items_id': ['banana', 'apple', 'orange']} (4)
```

1. Serializes `'nbf'` as a float timestamp.
2. Fails validation because `MyJWTClaims` is used automatically.
3. Once the `items_id` data is corrected, encoding succeeds.
4. `'nbf'` is correctly serialized as a float. See [Datetime Fields](#datetime-fields).

///

/// tab | Custom Headers<br><small>Example #1</small>

<h4>Headers</h4>

```python
from pydantic import ValidationError
from superjwt import Alg, JOSEHeader, JWT

secret_key = "your-secret-key-of-len-32-bytes!"

class CustomHeaders(JOSEHeader):
    session_id: str

headers = CustomHeaders.make_default(Alg.HS512, session_id="sess-123456")
headers.session_id = 123456
headers.to_dict()
#> {'alg': 'HS512', 'typ': 'JWT', 'session_id': 'sess-123456'}

try:
    headers.revalidate()  # --> ❌ fails (1)
except ValidationError:
    headers.session_id = "sess-123456"
    headers.revalidate()  # --> ✅ passes
```

1. Because `headers` is a Pydantic instance, headers validation runs against its own Pydantic model. Here, `session_id` is `int` and not `str`, thus failing.

///

/// tab | Custom Headers<br><small>Example #2</small>

<h4>Headers</h4>

```python
from superjwt import Alg, JOSEHeader, JWT
from superjwt.exceptions import HeadersValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

class CustomHeaders(JOSEHeader):
    session_id: str

headers = CustomHeaders.make_default(Alg.HS512, session_id="sess-123456")
headers.session_id = 123456
headers.to_dict()
#> {'alg': 'HS512', 'typ': 'JWT', 'session_id': '123456'}

jwt = JWT()  # (1)

try:
    jwt.encode({}, secret_key, Alg.HS512, headers=headers)  # --> ❌ fails (2)
except HeadersValidationError:
    headers.session_id = "sess-123456"
    compact = jwt.encode({}, secret_key, Alg.HS512, headers=headers).compact  # --> ✅ passes

jws_token = jwt.decode(compact, secret_key, Alg.HS512, headers_validation=CustomHeaders)
jws_token.headers
#> {'alg': 'HS512', 'typ': 'JWT', 'session_id': 'sess-123456'}
```

1. We are using a lower-level API here to access the headers data. But it works the same with module-level `encode()` and `decode()` functions. Warning: `JWT` is a stateful and non thread-safe object.
2. Because `headers` is a Pydantic instance, headers validation runs against its own Pydantic model. Here, `session_id` is `int` and not `str`, thus failing.

///

### Examples

/// tab | — DECODING —<br><small><em>Default Behavior</em></small>

```python
from pydantic import AfterValidator
from superjwt import Alg, JWTClaims, decode, inspect
from superjwt.exceptions import ClaimsValidationError
from typing import Annotated
from uuid import UUID

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # 'user_id' is required and must be a valid UUIDv4 string
    user_id: Annotated[str, AfterValidator(lambda x: str(UUID(x, version=4)))]

valid_compact = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiY2U3OGI4MTMtMjQ0YS00YmRmLWEzNmMtYTc5YjkxOWIyOTY4In0.EEfaVozcCntiHpbuuV2WRGKw1UtLQge2GoJ19HTq_dc"
inspect(valid_compact).payload
#> {'user_id': 'ce78b813-244a-4bdf-a36c-a79b919b2968'} ⚡ (1)

invalid_compact = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoibm90LWEtdXVpZC12NCJ9.-DeMZUugR40FDbWBU4nRESczZb5d8UDfuhkTumEeme0"
inspect(invalid_compact).payload
#> {'user_id': 'not-a-uuid-v4'} ⚡ (2)

decode(invalid_compact, secret_key, Alg.HS256)  # --> 🤔 passes (3)
#> {'user_id': 'not-a-uuid-v4'}

try:
    decode(invalid_compact, secret_key, Alg.HS256, claims_validation=MyJWTClaims)  # --> ❌ fails (4)
except ClaimsValidationError:
    decoded = decode(
        valid_compact, secret_key, Alg.HS256, claims_validation=MyJWTClaims
        )  # --> ✅ passes

```

1.  /// danger | Unverified JWT

    Token inspection DOES NOT verify the signature! Never trust information from an unverified JWT.
    ///
2. /// danger | Unverified JWT

    Token inspection DOES NOT verify the signature! Never trust information from an unverified JWT.
    ///
3. During decoding, claims are validated against `JWTClaims` by default. `user_id` is not a requirement of `JWTClaims`.
4. The `'user_id'` claim is not valid because the value is not a UUIDv4, as required by `MyJWTClaims`.

///

/// tab | — DECODING —<br><small><em>Pydantic Validation</em></small>

```python
from pydantic import Field, ValidationError
from superjwt import Alg, JWTClaims, JWTDatetime, decode, inspect
from typing import Literal

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # redefine 'exp' as required
    exp: JWTDatetime = Field(default=...)

    # 'permissions' is required and must be a list of string among 3 choices
    permissions: list[Literal["user", "dev", "admin"]]

invalid_compact = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwZXJtaXNzaW9ucyI6WyJkZXYiLCJhbmFseXN0Il0sImV4cCI6MjExMzI2NzI1MH0.ul7aDgO0VQmIKu-7OGpa2qHfXkA6s2XDQuyTA38HDiE"
inspect(invalid_compact).payload
#> {'permissions': ['dev', 'analyst'], 'exp': 2113267250} ⚡ (1)

decoded = decode(invalid_compact, secret_key, Alg.HS256)  # --> 🤔 passes (2)
#> {'permissions': ['dev', 'analyst'], 'exp': 2113267250}

decoded_claims = MyJWTClaims.model_construct(**decoded)

try:
    decoded_claims.revalidate()  # --> ❌ fails (3)
except ValidationError:
    # token is invalid!
    pass

```

1. /// danger | Unverified JWT

    Token inspection DOES NOT verify the signature! Never trust information from an unverified JWT.
    ///
2. Without specifying a custom model, `decode()` validates against `JWTClaims` by default. Since `'permissions'` is not a registered claim, it is just an extra field with no validation rules and decoding is successful.<br><br>Regardless, the JWT signature is always verified during the decoding process proving its authenticity.
3. The `'permissions'` claim is invalid because `'analyst'` is not an allowed value in our custom model.

///

/// tab | — DECODING —<br><small><em>with ValidationConfig</em></small>
Use a `ValidationConfig` to specify both a Pydantic model and additional parameters like leeway.

```python
from pydantic import Field
from superjwt import Alg, JWTClaims, ValidationConfig, decode, encode
from superjwt.exceptions import ClaimsValidationError
from typing import Literal

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    sub: str = Field(default=...)

strict = ValidationConfig(
    model=MyJWTClaims,
    leeway=1.0,
    allow_future_iat=False,
)

lenient = ValidationConfig(
    model=JWTClaims,
    leeway=30.0,
    allow_future_iat=True,
)

claims = JWTClaims(iss="my-app")
compact = encode(claims, secret_key, Alg.HS256)

try:
    decoded = decode(compact, secret_key, Alg.HS256, claims_validation=strict)
except ClaimsValidationError as e:
    print(e)
    #> Claims validation failed
    #> claim ('sub',) -> validation failed (missing): Field required

decoded = decode(compact, secret_key, Alg.HS256, claims_validation=lenient)
print(decoded)
#> {'iss': 'my-app'}

```
///

/// details | See Encoding Examples
    type: example

/// tab | — ENCODING —<br><small><em>Default Behavior #1</em></small>

When encoding JWT claims from a Pydantic instance, validation against its own model is automatic.

```python
from pydantic import AfterValidator, Field
from superjwt import Alg, JWTClaims, encode
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # redefine existing 'iss' to required integer
    iss: int = Field(default=...)

    # 'permissions' is required and must be a list of string
    permissions: list[str]

valid_claims = MyJWTClaims.model_construct(**{"permissions": ["user", "admin"]})  # (1)

try:
    encode(
        valid_claims, secret_key, Alg.HS256, claims_validation=JWTClaims  # --> ❌ fails (2)
    )
except:
    compact = encode(valid_claims, secret_key, Alg.HS256)  # --> ✅ passes (3)

```

1. `.model_construct()` allows the creation of a Pydantic instance without running validation.
2. By using `JWTClaims` as the validation model, the claims are no longer compliant because `'iss'` is an integer instead of a string.
3. Even though `claims_validation` is not specified, if the input is a Pydantic instance, it is automatically validated against its own model.

///

/// tab | — ENCODING —<br><small><em>Default Behavior #2</em></small>

When encoding JWT claims from a `dict`, validation runs against `JWTClaims`.

```python
from superjwt import Alg, JWTClaims, encode
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # 'user_id' is required and must be a valid UUIDv4 string
    permissions: list[str]

invalid_claims = MyJWTClaims.model_construct(**{"permissions": [1, "admin"]})  # (1)

try:
    encode(invalid_claims, secret_key, Alg.HS256)  # ❌ fails (2)
except ClaimsValidationError:
    compact = encode(
        {"permissions": [1, "admin"]}, secret_key, Alg.HS256  # --> 🤔 passes (3)
    )

try:
    encode(
        {"permissions": [1, "admin"]},
        secret_key,
        Alg.HS256,
        claims_validation=MyJWTClaims
    )  # --> ❌ fails (4)
except ClaimsValidationError:
    ...


```

1. `.model_construct()` creates a Pydantic instance without running validation.
2. Even without `claims_validation` specified, Pydantic instances are automatically validated against their own model.
3. During encoding, if claims are passed as a raw `dict`, claims validation runs against `JWTClaims`. The `permissions` extra field is allowed and has no validation rule, so the encoding is successful.
4. Here, we explicitly request validation using `MyJWTClaims`, so it fails.

///

/// tab | — ENCODING —<br><small><em>Pydantic Validation</em></small>

You can manually validate your claims before encoding your JWT.

```python
from pydantic import AfterValidator, Field, ValidationError
from superjwt import Alg, JWTClaims, JWTDatetime, encode
from typing import Annotated
from uuid import UUID

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # 'exp' is required
    exp: JWTDatetime = Field(default=...)

    # 'user_id' is required and must be a valid UUIDv4 string
    user_id: Annotated[str, AfterValidator(lambda x: str(UUID(x, version=4)))]

try:
    claims = MyJWTClaims.model_construct(**{"user_id": "not-a-uuid-v4"})
    claims.with_expiration(minutes=15)
    claims.revalidate()  # --> ❌ fails (1)
except ValidationError:
    claims = MyJWTClaims.model_construct(
        **{"user_id":"ce78b813-244a-4bdf-a36c-a79b919b2968"}
    )
    claims.with_expiration(minutes=15)
    claims.revalidate()  # --> ✅ passes

compact = encode(claims, secret_key, Alg.HS256)
```

1. `.revalidate()` is a `JWTBaseModel` method that verifies if the instance passes model validation.

///

///

### Disable Validation

You can disable claims validation entirely during encoding or decoding.

```python
from superjwt import Alg, JWTClaims, Validation, decode, encode

secret_key = "your-secret-key-of-len-32-bytes!"

claims = JWTClaims.model_construct(iss=12345)  # 'iss' should be a string
claims_dict = {"iss": 12345}  # 'iss' should be a string

# Encode without validation
compact = encode(claims, secret_key, Alg.HS256, claims_validation=Validation.DISABLE)  # (1)
compact = encode(claims_dict, secret_key, Alg.HS256, claims_validation=Validation.DISABLE)  # (2)

# Decode without validation
decoded = decode(compact, secret_key, Alg.HS256, claims_validation=Validation.DISABLE)  # (3)
```

1. By default, encoding validates Pydantic claims against its own Pydantic model. Use `Validation.DISABLE` to skip validation.
2. By default, encoding validates raw `dict` claims against `JWTClaims`. Use `Validation.DISABLE` to skip validation.
3. By default, decoding validates claims in the JWT against `JWTClaims`. Use `Validation.DISABLE` to skip validation.

/// note
Even with validation disabled, the signature is always verified when using `decode()`. To view token content without verification, use the [`inspect()` function](#inspecting-tokens).
///

### Validation Config

The `ValidationConfig` class allows you to configure validation by injecting a Pydantic model and additional settings.

| Configuration&nbsp;Argument | Type | Default | Description |
|---|---|---|---|
| `model` | `type[JWTBaseModel] | None` | `None` | The Pydantic model to use for validation. |
| `leeway` | `float` | `5.0` | A constant added to `iat`, `nbf`, and `exp` during validation to account for clock skew. |
| `allow_future_iat` | `bool` | `False` | If `False`, validation fails if `iat` is in the future. |
| `now` | `datetime | None` | `None` | Spoof current time with a custom datetime for testing purposes. |

```python
from superjwt import Alg, JWTClaims, ValidationConfig, decode

validation_config = ValidationConfig(
    model=JWTClaims,
    leeway=60, # 1 minute leeway
    allow_future_iat=False
)

decoded = decode(
    compact, 
    secret_key, 
    Alg.HS256, 
    claims_validation=validation_config
)
```

---

## Datetime Fields ⌚

### `JWTDatetime`

In your Pydantic models, fields defined with the `JWTDatetime` type represent date/time objects. They are stored internally as Python `datetime` and serialized as UNIX timestamps.

- Accepts Python `datetime` objects (with or without timezone).
- Accepts `int` or `float` UNIX timestamps.
- Values are converted to `datetime` objects when appropriate.
- Serializes as integer timestamps by default (can be changed to float using `JWTBaseModel.force_jwtdatetime_to_float()`).

`JWTDatetimeInt`

Similar to `JWTDatetime`, but always serializes as an `int`.

`JWTDatetimeFloat`

Similar to `JWTDatetime`, but always serializes as a `float`.

```python title="Code example"
from datetime import datetime
from pydantic import Field
from superjwt import Alg, JWTClaims, JWTDatetime, JWTDatetimeInt, encode, inspect

secret_key = "your-secret-key-of-len-32-bytes!"

class MyJWTClaims(JWTClaims):
    # 'exp' is required
    exp: JWTDatetime = Field(default=...)
    custom_time: JWTDatetimeInt

claims = MyJWTClaims.model_construct(
    custom_time=datetime(2025, 12, 31, 23, 59, 59, 987654)
    ).with_expiration(days=1)

claims.force_jwtdatetime_to_float()
compact = encode(claims, secret_key, Alg.HS256)
print(inspect(compact).payload)
#> {'custom_time': 1767225599, 'exp': 1768257699.998604} (1)

claims.force_jwtdatetime_to_int()
compact = encode(claims, secret_key, Alg.HS256)
print(inspect(compact).payload)
#> {'custom_time': 1767225599, 'exp': 1768257699} (2)
```

1. `'exp'` is serialized as a `float` because `.force_jwtdatetime_to_float()` was called.<br><br>`'custom_time'` remains an `int` because of its `JWTDatetimeInt` type.
2. `'exp'` is serialized back to an `int`.

### Spoof Time

You can override the current time with a custom `datetime` object for testing purposes. All time integrity and validity checks will account for the new spoofed "present time".

/// tab | with a Pydantic<br>instance
```python
from datetime import datetime
from superjwt import Alg, JWTClaims, encode
from superjwt.exceptions import TokenExpiredError

secret_key = "your-secret-key-of-len-32-bytes!"

claims = JWTClaims(sub="user-123").with_expiration(days=7)
# Set current time to a future date
claims.spoof_time(
    datetime(2046, 12, 31, 23, 59, 59)
)

try:
    encode(claims, secret_key, Alg.HS256)
except TokenExpiredError as e:
    print(e)
    #> Token has expired
```
///

/// tab | with a Validation<br>Config
```python
from datetime import datetime
from superjwt import Alg, JWTClaims, ValidationConfig, decode, inspect
from superjwt.exceptions import TokenExpiredError

secret_key = "your-secret-key-of-len-32-bytes!"

compact = (
    b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    b"eyJzdWIiOiJ1c2VyLTEyMyIsImV4cCI6MjI0MzQ2NTE5NX0."
    b"tHxnTwpkkxOBK2oZ0O2rq7ObV96DgcgjDGwQ__cH8LA"
)
print(inspect(compact).payload)
#> {'sub': 'user-123', 'exp': 2243465195}  exp = Feb 3, 2041

validation = ValidationConfig(
    model=JWTClaims, 
    now=datetime(2046, 12, 31, 23, 59, 59)
)

try:
    decode(compact, secret_key, Alg.HS256, claims_validation=validation)
except TokenExpiredError as e:
    print(e)
    #> Token has expired
```
///

---

## Asymmetric Algorithms 🔓

Unlike HMAC algorithm which uses the same key for encoding and decoding, asymmetric algorithms use a private key to sign tokens and a corresponding public key to verify them.

/// tip | Why Use Asymmetric Algorithms?
In this scenario, the private key never needs to be shared, while the public key can be distributed widely to many verifiers. This enables scalable architectures (multiple services can verify tokens without access to private keys), easier key rotation and auditability, and support for robust algorithms (RSA, ECDSA, EdDSA) suited for cross‑service and third‑party integrations.
<br><br>See [Pros & Cons (Asymmetric)](jwt/signing-algorithms.md/#pros-cons-asymmetric)
///

### Encode With a Private Key

/// tab | RSA<br>Algorithms
```python
from superjwt import Alg, RSAKey, decode, encode

private_pem = b"-----BEGIN PRIVATE KEY-----\nMIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGB...JKcY1op6RcnYLA/h2XmxWxMgJa9eqL8/s0tk\ncAQ2NIRpUOJf\n-----END PRIVATE KEY-----\n"

key = RSAKey.import_key(private_pem)

compact = encode({"sub": "user123"}, key, Alg.RS256)

decoded = decode(compact, key, Alg.RS256)  # (1)
```

1. When importing a private key, the public key component is derived automatically. You can use then this key instance for both encoding and decoding.
///

/// tab | ECDSA<br>Algorithms
```python
from superjwt import Alg, ECKey, decode, encode

private_pem = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49A...qzlKhJzG\n-----END PRIVATE KEY-----\n"

key = ECKey.import_key(private_pem)

compact = encode({"sub": "user123"}, key, Alg.ES256)

decoded = decode(compact, key, Alg.ES256)  # (1)
```

1. When importing a private key, the public key component is derived automatically. You can use then this key instance for both encoding and decoding.
///

/// tab | EdDSA<br>Algorithms
```python
from superjwt import Alg, OKPKey, decode, encode

private_pem = b"-----BEGIN PRIVATE KEY-----\nMEcCAQAwBQYDK2VxBDsEOWe...Yr\n+y4nNmgf3BsBvc3wRKPdfaO4dya2CJLLnA==\n-----END PRIVATE KEY-----\n"

key = OKPKey.import_key(private_pem)

compact = encode({"sub": "user123"}, key, Alg.Ed25519)

decoded = decode(compact, key, Alg.Ed25519)  # (1)
```

1. When importing a private key, the public key component is derived automatically. You can use then this key instance for both encoding and decoding.
///

See [How to generate keys](./algorithms.md#how-to-generate-keys).

### Decode with a Public Key

/// tab | RSA<br>Algorithms
```python
from superjwt import Alg, RSAKey, decode

public_pem = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w...IDAQAB\n-----END PUBLIC KEY-----\n"

key = RSAKey.import_public_key(public_pem)

decoded = decode(compact, key, Alg.RS256)  # (1)
```

1. You can only decode a JWT with a public key, not create one.
///

/// tab | ECDSA<br>Algorithms
```python
from superjwt import Alg, ECKey, decode

public_pem = b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKo...jnBeBPp/f8HA==\n-----END PUBLIC KEY-----\n"

key = ECKey.import_public_key(public_pem)

decoded = decode(compact, key, Alg.ES256)  # (1)
```

1. You can only decode a JWT with a public key, not create one.
///

/// tab | EdDSA<br>Algorithms
```python
from superjwt import Alg, OKPKey, decode

public_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwA...VotMRLDwHw=\n-----END PUBLIC KEY-----\n"

key = OKPKey.import_public_key(public_pem)

decoded = decode(compact, key, Alg.Ed25519)  # (1)
```

1. You can only decode a JWT with a public key, not create one.
///

---

## Detached Payload 🕊️

You can make a JWT with a *detached* payload, meaning the claims are not embedded in the compact token. Useful for bandwidth optimization when the payload is transmitted through a separate secure channel or when it is too large to be exchanged through HTTP headers.

```python
from superjwt import Alg, JWTClaims, decode, encode

secret_key = "your-secret-key-of-len-32-bytes!"
claims = JWTClaims(sub="user123", iss="myapp").with_expiration(minutes=30)
claims_dict = claims.to_dict()
#> {'iss': 'myapp', 'sub': 'user123', 'exp': 1767715523}

compact = encode(claims, secret_key, Alg.HS256, detach_payload=True)
#> b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
#   .. (1)
#   wNZgGwkVGw_Rble80j2J6a9IylXa5jgq4EO33XiEa4g'

decoded = decode(
    compact,
    secret_key,
    Alg.HS256,
    with_detached_payload=claims_dict,  # (2)
    claims_validation=JWTClaims
)
#> {'iss': 'myapp', 'sub': 'user123', 'exp': 1767715523}
```

1. Note that the encoded payload is empty!
2. The claims payload was transferred separately and is needed to perform the JWT verification. Remember the JWT signing input is the `.`-concatenated encoded Base64Url headers with encoded Base64Url claims.
