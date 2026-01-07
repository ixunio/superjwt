## Supported JWS Algorithms

These are the JWS signature algorithms that can be used to sign and verify a JWT/JWS with SuperJWT:

| `alg`<br>Algorithm | `kty`<br>Key Type | `__class__`<br>Key Class | SuperJWT<br>Support | Reference |
|-------------------------|-------|----------|-----------|-----|
| `HS256`<br><small>HMAC using SHA-256</small> | `oct`<br><small>Octet Sequence</small> | `OctKey`<br><small>symmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2)<br> |
| `HS384`<br><small>HMAC using SHA-384</small> | `oct`<br><small>Octet Sequence</small> | `OctKey`<br><small>symmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2) |
| `HS512`<br><small>HMAC using SHA-512</small> | `oct`<br><small>Octet Sequence</small> | `OctKey`<br><small>symmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2) |
| `RS256`<br><small>RSASSA-PKCS1-v1_5 using SHA-256</small> | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.3) |
| `RS384`<br><small>RSASSA-PKCS1-v1_5 using SHA-384</small> | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.3) |
| `RS512`<br><small>RSASSA-PKCS1-v1_5 using SHA-512</small> | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.3) |
| `PS256`<br><small>RSASSA-PSS using SHA-256 <br>and MGF1 with SHA-256</small> | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.5) |
| `PS384`<br><small>RSASSA-PSS using SHA-384 <br>and MGF1 with SHA-384 | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.5) |
| `PS512`<br><small>RSASSA-PSS using SHA-512 <br>and MGF1 with SHA-512 | `RSA`<br><small>RSA</small> | `RSAKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.5) |
| `ES256`<br><small>ECDSA using secp256r1 curve <br>and SHA-256 | `EC`<br><small>Elliptic Curve</small> | `ECKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4) |
| `ES256K`<br><small>ECDSA using secp256k1 curve <br>and SHA-256 | `EC`<br><small>Elliptic Curve</small> | `ECKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812) |
| `ES384`<br><small>ECDSA using secp384r1 curve <br>and SHA-384 | `EC`<br><small>Elliptic Curve</small> | `ECKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4) |
| `ES512`<br><small>ECDSA using secp521r1 curve <br>and SHA-512 | `EC`<br><small>Elliptic Curve</small> | `ECKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4) |
| `EdDSA`<br><small>EdDSA signature algorithms<br>(deprecated, use Ed25519 or Ed448)</small> | `OKP`<br><small>Octet Key Pair</small> | `OKPKey`<br><small>asymmetric</small> | ![No](https://img.shields.io/badge/-No-red) | [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)<br><em><small>(deprecated)</small></em> |
| `Ed25519`<br><small>EdDSA using Ed25519 curve | `OKP`<br><small>Octet Key Pair</small> | `OKPKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 9864](https://datatracker.ietf.org/doc/html/rfc9864) |
| `Ed448`<br><small>EdDSA using Ed448 curve | `OKP`<br><small>Octet Key Pair</small> | `OKPKey`<br><small>asymmetric</small> | ![Yes](https://img.shields.io/badge/-Yes-success) | [RFC 9864](https://datatracker.ietf.org/doc/html/rfc9864) |

/// note | Installation Requirement
Asymmetric algorithms require the `cryptography` library. You can install it with:
```bash
pip install superjwt[asymmetric]
```
///

Which algorithm to choose? [See What is best, and why?](./jwt/signing-algorithms.md#what-is-best-and-why)

TLDR; use `Ed25519`!

---

## How to Generate Keys

### Secret Key 🔄
<em>for a **symmetric** algorithm</em>

Uses the same secret key for encoding and decoding a JWT. The secret key is a random byte sequence. Compatible with HMAC signature algorithms: `HS256`, `HS384`, and `HS512`.

/// details | View code
    type: example

/// tab | HS256<br><small>(32 bytes)</small>
```python title="with Python"
from superjwt import Alg

# generate a 32 bytes (256 bits) secret key for HMAC+SHA256
jws_alg = Alg.HS256.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'720d649040e48161e4b47c8ccf8577194d7b7ee543083fb07f036daf0d711a84'
```
```bash title="with Bash"
# generate a 32 bytes (256 bits) secret key for HMAC+SHA256
openssl rand -hex 32
#> 466bc5cfb0a7bd1cba94d72b0ff0d96d93a377d6a50ce4993e7fca7e5437d393
```
///
/// tab | HS384<br><small>(48 bytes)</small>
```python title="with Python"
from superjwt import Alg

# generate a 48 bytes (384 bits) secret key for HMAC+SHA384
jws_alg = Alg.HS384.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'c379cdc39119ff82b2584dfdff92d803d38cf574281bd6f77ac5a8478020e3fbcda228caf0d8f4e370cf684803f015d3'
```
```bash title="with Bash"
# generate a 48 bytes (384 bits) secret key for HMAC+SHA384
openssl rand -hex 48
#> 8c4e4fba8d1cd5de6a8ec68c88ae96ae116bd8a58d174f52bd301bdc0df17da43295a756f3db9a49a51c7a2e8fb3fa6b
```
///
/// tab | HS512<br><small>(64 bytes)</small><br>
```python title="with Python"
from superjwt import Alg

# generate a 64 bytes (512 bits) secret key for HMAC+SHA512
jws_alg = Alg.HS512.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'58ff0cd9d90969b968d2b41b3ca1fa3f99f501faabeca16cd7715139b827c99ba676b68a76cc5a75a08105220833167878b30d32e4963a10f069ee79e7413f69'
```
```bash title="with Bash"
# generate a 64 bytes (512 bits) secret key for HMAC+SHA512
openssl rand -hex 64
#> eee657e8cb83768ee1e84792c670cdef6f549d4e97d02af4674e32fe32d463a67a52ad95c79bca1589a0c10f0e2c718b558f4476f0c5b2256b34b95000ac496d
```
///
/// tab | Custom
```python title="with Python"
from superjwt import OctKey

# generate a 42-byte hex string key (default)
key = OctKey.generate(42, human_readable=True)
print(key.private_key)
#> b'b7f5bea63d48a2cf545b6f1495f07d6f1314a2f71951c2d95c7cf53a3ecdcc7af22c8b649cfa161d1658'

# generate a 42-byte raw bytes key
key = OctKey.generate(42, human_readable=False)
print(key.private_key)
#> b'o\xb7C\xb8\xb9\xd5\x97\x19\xd5<\x8a\x8a\x89s\xa73t\xf0\x93\xbc\xcc\xb8@\xe2\xe5\x85\xa0\xbcb\x05\xb5Y\xe5\xf2\xad\x902a5[Y\xa2'
```
///

///

---

### Key Pair 🔀
<em>for an **asymmetric** algorithm</em>

| Key Type | Header (Start) | Footer (End) |
| :--- | :--- | :--- |
| **Private Key** (PKCS#8) | `-----BEGIN PRIVATE KEY-----` | `-----END PRIVATE KEY-----` |
| **Public Key** (PEM) | `-----BEGIN PUBLIC KEY-----` | `-----END PUBLIC KEY-----` |

#### RSA Key Pair

Compatible with RSA signature algorithms: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, and `PS512`.

/// details | View code
    type: example

/// tab | 2048-bit
```python title="with Python"
from superjwt import RSAKey

key = RSAKey.generate(2048)

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9...CQZaE0rgg8=\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQ...IDAQAB\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate a 2048 bits RSA private key in PKCS#8 format
openssl genpkey -algorithm RSA -out private_key_rsa.pem -pkeyopt rsa_keygen_bits:2048

# generate the public key
openssl pkey -pubout -in private_key_rsa.pem -out public_key_rsa.pem
```
///
/// tab | 3072-bit
```python title="with Python"
from superjwt import RSAKey

key = RSAKey.generate(3072)

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9...CQZaE0rgg8=\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQ...IDAQAB\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate a 3072 bits RSA private key in PKCS#8 format
openssl genpkey -algorithm RSA -out private_key_rsa.pem -pkeyopt rsa_keygen_bits:3072

# generate the public key
openssl pkey -pubout -in private_key_rsa.pem -out public_key_rsa.pem
```
///
/// tab | 4096-bit
```python title="with Python"
from superjwt import RSAKey

key = RSAKey.generate(4096)

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9...CQZaE0rgg8=\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQ...IDAQAB\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate a 4096 bits RSA private key in PKCS#8 format
openssl genpkey -algorithm RSA -out private_key_rsa.pem -pkeyopt rsa_keygen_bits:4096

# generate the public key
openssl pkey -pubout -in private_key_rsa.pem -out public_key_rsa.pem
```
///

/// warning | RSA Key Sizes
- **2048 bits**: A widely accepted minimum standard for many years, but it will be deprecated in 2030.
- **3072 bits**: Offers a higher security level and is recommended for strong, long-term security.
- **4096 bits**: Provides even greater long-term security but requires significantly more processing power.
///

///


#### Elliptic Curve (ECDSA)

Compatible with these ECDSA signature algorithms: `ES256`, `ES256K`, `ES384`, and `ES512`.

/// details | View code
    type: example

/// tab | ES256 with<br>`secp256r1` curve
```python title="with Python"
from superjwt import Alg

jws_alg = Alg.ES256.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGAgEGC...aOcF4E+n9/wc\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKo...jnBeBPp/f8HA==\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate a private key for ECDSA with secp256r1 curve
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private_key_p256.pem

# generate the public key
openssl pkey -pubout -in private_key_p256.pem -out public_key_p256.pem
```
///
/// tab | ES256K with<br>`secp256k1` curve
```python title="with Python"
from superjwt import Alg

jws_alg = Alg.ES256K.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM...QYnLhTnBnCKLQMe\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKo...jnBeBPp/f8HA==\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate a private key for ECDSA with secp256k1 curve
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out private_key_secp256k1.pem

# generate the public key
openssl pkey -pubout -in private_key_secp256k1.pem -out public_key_secp256k1.pem
```
///
/// tab | ES384 with<br>`secp384r1` curve
```python title="with Python"
from superjwt import Alg

jws_alg = Alg.ES384.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM...QYnLhTnBnCKLQMe\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKo...jnBeBPp/f8HA==\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate a private key for ECDSA with secp384r1 curve
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out private_key_p384.pem

# generate the public key
openssl pkey -pubout -in private_key_p384.pem -out public_key_p384.pem
```
///
/// tab | ES512 with<br>`secp521r1` curve
```python title="with Python"
from superjwt import Alg

jws_alg = Alg.ES512.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM...QYnLhTnBnCKLQMe\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKo...jnBeBPp/f8HA==\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate a private key for ECDSA with secp521r1 curve
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out private_key_p521.pem

# generate the public key
openssl pkey -pubout -in private_key_p521.pem -out public_key_p521.pem
```
///

///

#### Octet Key Pair (EdDSA)

Compatible with these EdDSA signature algorithms: `Ed25519` and `Ed448`.

/// details | View code
    type: example

/// tab | Ed25519
```python title="with Python"
from superjwt import Alg

jws_alg = Alg.Ed25519.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2...tRRQq/r9bcmGe2ODBBz\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwA...aL4MNzotMRLDwHw=\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate an Ed25519 private key
openssl genpkey -algorithm ED25519 -out private_key_ed25519.pem

# generate the public key
openssl pkey -pubout -in private_key_ed25519.pem -out public_key_ed25519.pem
```
///
/// tab | Ed448
```python title="with Python"
from superjwt import Alg

jws_alg = Alg.Ed448.get_instance()
key = jws_alg.generate_key()

print(key.private_key)
#> b'-----BEGIN PRIVATE KEY-----\nMEcCAQAwBQYDK2...CHJRpieeRB4RR6VZA==\n-----END PRIVATE KEY-----\n'

print(key.public_key)
#> b'-----BEGIN PUBLIC KEY-----\nMEMwBQYDK2VxA...Rle7Dh0PZxkvBa6A\n-----END PUBLIC KEY-----\n'
```
```bash title="with Bash"
# generate an Ed448 private key
openssl genpkey -algorithm ED448 -out private_key_ed448.pem

# generate the public key
openssl pkey -pubout -in private_key_ed448.pem -out public_key_ed448.pem
```
///

///