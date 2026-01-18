SuperJWT provides specific exceptions or warnings in different scenarios.

## Exceptions

/// tab | Diagram View

```mermaid
graph LR
    SJE["SuperJWTError"] --> ITE["InvalidTokenError"]
    SJE --> IAE["InvalidAlgorithmError"]
    SJE --> IKE["InvalidKeyError"]
    
    ITE --> SVFE["SignatureVerificationError"]
    ITE --> SEE["SizeExceededError"]
    ITE --> IHE["InvalidHeadersError"]
    ITE --> IPE["InvalidPayloadError"]
    
    IHE --> HVE["HeadersValidationError"]
    IHE --> AME["AlgorithmMismatchError"]
    
    IPE --> CVE["ClaimsValidationError"]
    
    CVE --> TEE["TokenExpiredError"]
    CVE --> TNVE["TokenNotYetValidError"]
    
    IAE --> ANSE["AlgorithmNotSupportedError"]
```
///

/// tab | Tree View

```
SuperJWTError
├──── InvalidTokenError
│     ├──── SignatureVerificationError
│     ├──── SizeExceededError
│     ├──── InvalidHeadersError
│     │     ├──── HeadersValidationError
│     │     └──── AlgorithmMismatchError
│     └── InvalidPayloadError
│         └──── ClaimsValidationError
│               ├──── TokenExpiredError
│               └──── TokenNotYetValidError
├──── InvalidAlgorithmError
│     └──── AlgorithmNotSupportedError
└──── InvalidKeyError
```
///

### `SuperJWTError`
<small>*inherits from `Exception`*</small>

The base exception of the SuperJWT library. It can be used to catch all SuperJWT errors.

---

### `InvalidTokenError`
<small>*inherits from `SuperJWTError`*</small>

Generic error when token is invalid (bad format, cannot be verified, cannot be validated).

/// details | Code Example
    type: example

```python
from superjwt import Alg, decode
from superjwt.exceptions import InvalidTokenError

secret_key = "your-secret-key-of-len-32-bytes!"

try:
    decode(b"invalid-token-format", secret_key, Alg.HS256)
except InvalidTokenError as e:
    print(e)
    #> Token must have exactly 3 parts separated by dots
```
///

---

### `SignatureVerificationError`
<small>*inherits from `InvalidTokenError`*</small>

Raised when signature verification fails. This happens when decoding with the wrong key or when the token has been tampered with.

/// details | Code Example
    type: example

/// tab | Token has been tampered with
```python
from superjwt import Alg, JWTClaims, decode, encode
from superjwt.exceptions import SignatureVerificationError

secret_key = "your-secret-key-of-len-32-bytes!"

token_a = encode(JWTClaims(sub="user123"), secret_key, Alg.HS256)
token_b = encode(JWTClaims(sub="user456"), secret_key, Alg.HS256)

# Forge a token
header_a, _payload_a, sig_a = token_a.split(b".")
_header_b, payload_b, _sig_b = token_b.split(b".")
forged = header_a + b"." + payload_b + b"." + sig_a

try:
    decode(forged, secret_key, Alg.HS256)
except SignatureVerificationError as e:
    print(e)
    #> Signature verification failed, the token may have been tampered with!
```
///

/// tab | Encoding & decoding with a different key

```python
from superjwt import Alg, JWTClaims, decode, encode
from superjwt.exceptions import SignatureVerificationError

secret_key = "your-secret-key-of-len-32-bytes!"
wrong_key = "a-different-key-also-32-bytes!!!"

claims = JWTClaims(sub="user123")
compact = encode(claims, secret_key, Alg.HS256)

try:
    decode(compact, wrong_key, Alg.HS256)
except SignatureVerificationError as e:
    print(e)
    #> Signature verification failed, the token may have been tampered with!
```
///

///

---

### `InvalidHeadersError`
<small>*inherits from `InvalidTokenError`*</small>

Raised when JWT headers are malformed or contain invalid values.

/// details | Code Example
    type: example

```python
from superjwt import Alg, decode, encode
from superjwt.exceptions import InvalidHeadersError

secret_key = "your-secret-key-of-len-32-bytes!"

valid_token = encode({"sub": "test"}, secret_key, Alg.HS256)
parts = valid_token.split(b".")
invalid_compact = b".".join([b"!!!invalid-base64!!!", parts[1], parts[2]])

try:
    # Create a token with invalid b64 header which is not supported
    decode(invalid_compact, secret_key, Alg.HS256)
except InvalidHeadersError as e:
    print(e)
    #> Headers are not encoded as a valid Base64url
```
///

---

### `HeadersValidationError`
<small>*inherits from `InvalidHeadersError`*</small>

Raised when header data fails Pydantic validation (defaults to `JOSEHeader`).

/// details | Code Example
    type: example

```python
from superjwt import Alg, JOSEHeader, encode
from superjwt.exceptions import HeadersValidationError

secret_key = "your-secret-key-of-len-32-bytes!"

headers = JOSEHeader.model_construct(alg="INVALID_ALG", typ="JWT")

try:
    encode({}, secret_key, Alg.HS256, headers=headers)
except HeadersValidationError as e:
    print(e)
    #> Header validation failed
    #> header ('alg',) = INVALID_ALG -> validation failed (value_error): 
    #>   Value error, 'INVALID_ALG' is not a valid algorithm
```
///

---

### `AlgorithmMismatchError`
<small>*inherits from `InvalidHeadersError`*</small>

Raised when the algorithm in the JWT header doesn't match the expected algorithm during encoding or decoding.

/// details | Code Example
    type: example

```python
from superjwt import Alg, JOSEHeader, Validation, decode, encode, inspect
from superjwt.exceptions import AlgorithmMismatchError

secret_key = "your-secret-key-of-len-32-bytes!"

compact = (
    "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"
    "."
    "eyJpc3MiOiJ1c2VyLTEyMyJ9"
    "."
    "Mp0Pcwsz5VECK11Kf2ZZNF_SMKu5CgBeLN9ZOP04kZo"
)
print(inspect(compact).headers["alg"])
#> 'HS512'

try:
    # Decode expecting HS256 but header says HS512
    # even with headers validation disabled, an AlgorithmMismatchError is raised
    decode(compact, secret_key, Alg.HS256, headers_validation=Validation.DISABLE)
except AlgorithmMismatchError as e:
    print(e)
    #> JWS algorithm 'HS512' does not match expected 'HS256'
```
///

---

### `InvalidPayloadError`
<small>*inherits from `InvalidTokenError`*</small>

Raised when the payload is not valid JSON or not a proper mapping (dict).

/// details | Code Example
    type: example

```python
import json
from superjwt import Alg, decode
from superjwt.exceptions import InvalidPayloadError
from superjwt.utils import urlsafe_b64encode

secret_key = "your-secret-key-of-len-32-bytes!"

# Create a token with invalid payload (not a JSON object)
header = urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = urlsafe_b64encode(b"not-valid-json")
fake_signature = urlsafe_b64encode(b"fake")

malformed_token = header + b"." + payload + b"." + fake_signature

try:
    decode(malformed_token, secret_key, Alg.HS256)
except InvalidPayloadError as e:
    print(e)
    #> The payload segment is not valid JSON
```
///

---

### `ClaimsValidationError`
<small>*inherits from `InvalidPayloadError`*</small>

Raised when claims data fails Pydantic validation.

/// details | Code Example
    type: example

/// tab | Example #1
```python
from superjwt import Alg, JWTClaims, Validation, decode, encode
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"


invalid_claims = JWTClaims.model_construct(sub="user123", iss=12345)

# ENCODING
try:
    encode(invalid_claims, secret_key, Alg.HS256)
except ClaimsValidationError as e:
    print(e)
    #> Claims validation failed
    #> claim ('iss', 'str') = 12345 -> validation failed (string_type): 
    #>   Input should be a valid string

invalid_compact = encode(
    invalid_claims,
    secret_key,
    Alg.HS256,
    validation=Validation.DISABLE
)

# DECODING
try:
    decode(invalid_compact, secret_key, Alg.HS256, validation=JWTClaims)
except ClaimsValidationError as e:
    print(e)
    #> Claims validation failed
    #> claim ('iss', 'str') = 12345 -> validation failed (string_type): 
    #>   Input should be a valid string

```
///

/// tab | Example #2
```python
from pydantic import Field
from superjwt import Alg, JWTClaims, Validation, decode, encode
from superjwt.exceptions import ClaimsValidationError

secret_key = "your-secret-key-of-len-32-bytes!"


# Example 2: Custom claims model with required field
class MyClaims(JWTClaims):
    user_id: str = Field(default=...)  # required field

invalid_claims = {"sub": "user123"}

# ENCODING
try:
    encode(invalid_claims, secret_key, Alg.HS256, validation=MyClaims)
except ClaimsValidationError as e:
    print(e)
    #> Claims validation failed
    #> claim ('user_id',) = ... -> validation failed (missing): Field required

invalid_compact = encode(
    invalid_claims,
    secret_key,
    Alg.HS256,
    validation=Validation.DISABLE
)

# DECODING
try:
    decode(invalid_compact, secret_key, Alg.HS256, validation=MyClaims)
except ClaimsValidationError as e:
    print(e)
    #> Claims validation failed
    #> claim ('user_id',) = ... -> validation failed (missing): Field required

```
///
///

---

### `TokenExpiredError`
<small>*inherits from `ClaimsValidationError`*</small>

Raised when the token's `'exp'` claim indicates the token has expired.

/// details | Code Example
    type: example

```python
from datetime import datetime, timedelta, UTC
from superjwt import Alg, JWTClaims, Validation, decode, encode
from superjwt.exceptions import TokenExpiredError

secret_key = "your-secret-key-of-len-32-bytes!"

# Create an expired token (exp in the past)
expired_claims = JWTClaims.model_construct(
    sub="user123",
    exp=datetime.now(UTC) - timedelta(hours=1),  # expired 1 hour ago
)

# Encode without validation to create the expired token
compact = encode(
    expired_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
)

try:
    # Decode with validation will check exp claim
    decode(compact, secret_key, Alg.HS256, validation=JWTClaims)
except TokenExpiredError as e:
    print(e)
    #> Token has expired
```
///

---

### `TokenNotYetValidError`
<small>*inherits from `ClaimsValidationError`*</small>

Raised when the token's `'nbf'` (not before) claim indicates the token is not yet valid.

/// details | Code Example
    type: example

```python
from datetime import datetime, timedelta, UTC
from superjwt import Alg, JWTClaims, Validation, decode, encode
from superjwt.exceptions import TokenNotYetValidError

secret_key = "your-secret-key-of-len-32-bytes!"

# Create a token that won't be valid for another day
future_claims = JWTClaims.model_construct(
    sub="user123",
    nbf=datetime.now(UTC) + timedelta(days=1),  # valid starting tomorrow
)

# Encode without validation to create the future token
compact = encode(
    future_claims, secret_key, Alg.HS256, validation=Validation.DISABLE
)

try:
    # Decode with validation will check nbf claim
    decode(compact, secret_key, Alg.HS256, validation=JWTClaims)
except TokenNotYetValidError as e:
    print(e)
    #> Token is not yet valid
```
///

---

### `InvalidAlgorithmError`
<small>*inherits from `SuperJWTError`*</small>

Raised when an invalid algorithm name is provided.

/// details | Code Example
    type: example

```python
from superjwt import Alg
from superjwt.exceptions import InvalidAlgorithmError

try:
    # Try to use an algorithm that doesn't exist
    Alg.get_instance_by_name("FAKE_ALG")
except InvalidAlgorithmError as e:
    print(e)
    #> Algorithm 'FAKE_ALG' is not a valid JWS algorithm
```
///

---

### `AlgorithmNotSupportedError`
<small>*inherits from `InvalidAlgorithmError`*</small>

Raised when an algorithm exists in the specification but is not yet implemented in the library.

/// details | Code Example
    type: example

```python
from superjwt import Alg
from superjwt.exceptions import AlgorithmNotSupportedError

try:
    # EdDSA is a valid JWS algorithm but is deprecated and not implemented
    alg = Alg.EdDSA
    alg.get_instance()
except AlgorithmNotSupportedError as e:
    print(e)
    #> JWS Algorithm 'EdDSA' is not yet implemented
```
///

---

### `InvalidKeyError`
<small>*inherits from `SuperJWTError`*</small>

Raised when the provided key format is invalid for the selected algorithm.

/// details | Code Example
    type: example

```python
from superjwt.exceptions import InvalidKeyError
from superjwt.keys import OctKey

# Create a fake PEM-formatted key (asymmetric key format)
pem_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
-----END RSA PRIVATE KEY-----"""

try:
    # Try to use a PEM key for HMAC algorithm (symmetric)
    OctKey.import_key(pem_key)
except InvalidKeyError as e:
    print(e)
    #> The specified key is an asymmetric key or x509 certificate 
    #>   and should not be used as an HMAC secret.
```
///

---

## Warnings

### `SecurityWarning`
<small>*inherits from `UserWarning`*</small>

Base warning for security concerns.

### `KeyLengthSecurityWarning`
<small>*inherits from `SecurityWarning`*</small>

Raised when a key length/size is deemed insufficient but working.

/// details | Code Example
    type: example

```python
import warnings
from superjwt import OctKey
from superjwt.exceptions import KeyLengthSecurityWarning

# Capture warnings
with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter("always")
    
    # Use a very short key (less than 112 bits / 14 bytes)
    weak_key = "short"  # Only 5 bytes
    OctKey.import_key(weak_key)
    
    # Check if SecurityWarning was raised
    if len(w) > 0 and issubclass(w[-1].category, KeyLengthSecurityWarning):
        print(w[-1].message)
        #> HMAC key size is 40 bits. Key size should be >= 112 bits for security
```
///
