## Best Practices

✅ **Do**

&rarr; **Always** verify signatures when decoding tokens in production.

&rarr; Use **appropriate** keys matching used JWS algorithm, see how to [generate keys](#generate-symmetric-keys) accordingly.

&rarr; Set an **expiration time** to limit token lifetime, see [Set Token Expiration](../#set-token-expiration)

&rarr; Use Pydantic models to **validate** automatically your claims, see [Custom Claims Validation].

&rarr; Handle **exceptions** to catch tampering attempts or claim alignment, see [Exceptions].

&rarr; Keep **secrets secure** by storing them in secret management systems / environment variables

❌ **Don't**

&rarr; Never use `inspect()` in production as it bypasses signature verification

&rarr; Don't store sensitive data in the JWT, they are not encrypted, the user can see them

&rarr; Don't disable validation without reason,  only bypass it for debugging

&rarr; Don't share or reuse secret keys across environments

&rarr; Never trust client-provided tokens until signature verification is done

## JWS Signature Algorithms

| `alg`<br>Algorithm | `kty`<br>Key Type | `__class__`<br>Key Class | Support | Reference |
|-------------------------|-------|----------|-----------|-----|
| `HS256`<br><small>HMAC using SHA-256</small> | `oct`<br><small>Octet Sequence</small> | `OctKey`<br><small>symmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2)<br> |
| `HS384`<br><small>HMAC using SHA-384</small> | `oct`<br><small>Octet Sequence</small> | `OctKey`<br><small>symmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2) |
| `HS512`<br><small>HMAC using SHA-512</small> | `oct`<br><small>Octet Sequence</small> | `OctKey`<br><small>symmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2) |
| `PS256`<br><small>RSASSA-PSS using SHA-256 <br>and MGF1 with SHA-256</small> | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.5) |
| `PS384`<br><small>RSASSA-PSS using SHA-384 <br>and MGF1 with SHA-384 | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.5) |
| `PS512`<br><small>RSASSA-PSS using SHA-512 <br>and MGF1 with SHA-512 | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.5) |
| `ES256`<br><small>ECDSA using secp256r1 curve <br>and SHA-256 | `EC`<br><small>Elliptic Curve</small> | `ECKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4) |
| `ES256K`<br><small>ECDSA using secp256k1 curve <br>and SHA-256 | `EC`<br><small>Elliptic Curve</small> | `ECKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812) |
| `ES384`<br><small>ECDSA using secp384r1 curve <br>and SHA-384 | `EC`<br><small>Elliptic Curve</small> | `ECKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4) |
| `ES512`<br><small>ECDSA using secp521r1 curve <br>and SHA-512 | `EC`<br><small>Elliptic Curve</small> | `ECKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4) |
| `Ed25519`<br><small>EdDSA using Ed25519 curve | `OKP`<br><small>Octet Key Pair</small> | `OKPKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 9864](https://datatracker.ietf.org/doc/html/rfc9864) |
| `Ed448`<br><small>EdDSA using Ed448 curve | `OKP`<br><small>Octet Key Pair</small> | `OKPKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 9864](https://datatracker.ietf.org/doc/html/rfc9864) |

## Generate Symmetric Keys

Uses the same secret key for encoding and decoding JWT.

### Octet Sequence (HMAC)

The secret key is a random byte sequence. Compatible with these HMAC signature algorithms:

/// tab | HS256
```bash title="bash"
# generate a 32 bytes (256 bits) secret key for HMAC+SHA256
openssl rand -hex 32
```
```python title="python"
import secrets

# generate a 32 bytes (256 bits) secret key for HMAC+SHA256
secret_key: str = secrets.token_bytes(32).hex()
```
///

/// tab | HS384
```bash title="bash"
# generate a 48 bytes (384 bits) secret key for HMAC+SHA384
openssl rand -hex 48
```
```python title="python"
import secrets

# generate a 48 bytes (384 bits) secret key for HMAC+SHA384
secret_key: str = secrets.token_bytes(48).hex()
```
///

/// tab | HS512
```bash title="bash"
# generate a 64 bytes (512 bits) secret key for HMAC+SHA512
openssl rand -hex 64
```
```python title="python"
import secrets

# generate a 64 bytes (512 bits) secret key for HMAC+SHA512
secret_key: str = secrets.token_bytes(64).hex()
```
///

## Generate Asymmetric Keys

Works with a public and private keys pair. The private key is used for encoding the JWT while the public key is used for decoding the JWT. Use `openssl` or `python` to generate a PKCS#8 `private_key.pem` file; you can always derive the public key then from a private key. See below instructions for each algorithm.

A PKCS#8 unencrypted private key always:

- begins with `-----BEGIN PRIVATE KEY-----`
- ends with &nbsp;&nbsp;&nbsp;&nbsp;`-----END PRIVATE KEY-----`

A PEM public key always:

- begins with `-----BEGIN PUBLIC KEY-----`
- ends with &nbsp;&nbsp;&nbsp;&nbsp;`-----END PUBLIC KEY-----`

### RSA

Compatible with RSA signature algorithms: `PS256`, `PS358`, `PS512`.

```bash title="bash"
# generate a 2048 bits RSA private key in PKCS#8 format
openssl genpkey -algorithm RSA -out private_key_rsa.pem -pkeyopt rsa_keygen_bits:2048

# generate the public key
openssl pkey -pubout -in private_key_rsa.pem -out public_key_rsa.pem
```
```python title="python"
# /!\ requires 'cryptography' package
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# generate a 2048 bits RSA private key
private_key_obj= rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# to PKCS#8 format
private_key: bytes = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

public_key: bytes = private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(private_key.decode("utf-8"))
print(public_key.decode("utf-8"))

```
/// warning | RSA Key Sizes
- 2048 bits: a widely accepted minimum standard for many years, but will be deprecated in 2030
- 3072 bits: offers a higher security level and is recommended for strong, long-term security
- 4096 bits: provides even greater long-term security but requires a lot more processing power
///
### Elliptic Curve (ECDSA)

Compatible with these ECDSA signature algorithms:

/// tab | ES256
```bash title="bash"
# generate a private key for ECDSA with secp256r1 curve
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private_key_p256.pem

# generate the public key
openssl pkey -pubout -in private_key_p256.pem -out public_key_p256.pem
```
```python title="python"
# /!\ requires 'cryptography' package
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# generate an ECDSA with secp256r1 curve private key
private_key_obj = ec.generate_private_key(ec.SECP256R1())

# to PKCS#8 format
private_key: bytes = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# generate the public key in PEM format
public_key: bytes = private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(private_key.decode("utf-8"))
print(public_key.decode("utf-8"))
```
///

/// tab | ES256K
```bash title="bash"
# generate a private key for ECDSA with secp256k1 curve
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out private_key_secp256k1.pem

# generate the public key
openssl pkey -pubout -in private_key_secp256k1.pem -out public_key_secp256k1.pem
```
```python title="python"
# /!\ requires 'cryptography' package
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# generate an ECDSA with secp256k1 curve private key
private_key_obj = ec.generate_private_key(ec.SECP256K1())

# to PKCS#8 format
private_key: bytes = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# generate the public key in PEM format
public_key: bytes = private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(private_key.decode("utf-8"))
print(public_key.decode("utf-8"))
```
///

/// tab | ES384
```bash title="bash"
# generate a private key for ECDSA with secp384r1 curve
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out private_key_p384.pem

# generate the public key
openssl pkey -pubout -in private_key_p384.pem -out public_key_p384.pem
```
```python title="python"
# /!\ requires 'cryptography' package
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# generate an ECDSA with secp384r1 curve private key
private_key_obj = ec.generate_private_key(ec.SECP384R1())

# to PKCS#8 format
private_key: bytes = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# generate the public key in PEM format
public_key: bytes = private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(private_key.decode("utf-8"))
print(public_key.decode("utf-8"))
```
///

/// tab | ES512
```bash title="bash"
# generate a private key for ECDSA with secp521r1 curve
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out private_key_p521.pem

# generate the public key
openssl pkey -pubout -in private_key_p521.pem -out public_key_p521.pem
```
```python title="python"
# /!\ requires 'cryptography' package
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# generate an ECDSA with secp521r1 curve private key
private_key_obj = ec.generate_private_key(ec.SECP521R1())

# to PKCS#8 format
private_key: bytes = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# generate the public key in PEM format
public_key: bytes = private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(private_key.decode("utf-8"))
print(public_key.decode("utf-8"))
```
///


### Octet Key Pair (EdDSA)

Compatible with these EdDSA signature algorithms:

/// tab | Ed25519
```bash title="bash"
# generate an Ed25519 private key
openssl genpkey -algorithm ED25519 -out private_key_ed25519.pem

# generate the public key
openssl pkey -pubout -in private_key_ed25519.pem -out public_key_ed25519.pem
```
```python title="python"
# /!\ requires 'cryptography' package
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# generate an Ed25519 private key
private_key_obj = ed25519.Ed25519PrivateKey.generate()

# to PKCS#8 format
private_key: bytes = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# generate the public key in PEM format
public_key: bytes = private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(private_key.decode("utf-8"))
print(public_key.decode("utf-8"))
```
///

/// tab | Ed448
```bash title="bash"
# generate an Ed448 private key
openssl genpkey -algorithm ED448 -out private_key_ed448.pem

# generate the public key
openssl pkey -pubout -in private_key_ed448.pem -out public_key_ed448.pem
```
```python title="python"
# /!\ requires 'cryptography' package
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448

# generate an Ed448 private key
private_key_obj = ed448.Ed448PrivateKey.generate()

# to PKCS#8 format
private_key: bytes = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# generate the public key in PEM format
public_key: bytes = private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(private_key.decode("utf-8"))
print(public_key.decode("utf-8"))

```
///
