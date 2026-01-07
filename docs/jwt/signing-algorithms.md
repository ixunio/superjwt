# Signing Algorithms

The security of a JWT depends heavily on the signing algorithm used. The `alg` header parameter specifies which algorithm was used to sign the token.

There are two main categories of signing algorithms: **Symmetric** (HMAC) and **Asymmetric** (RSA, ECDSA, Ed25519/Ed448).

/// tip | Quick recommendations
- Single service / monolith: start with `HS256` using a strong random secret.
- Multiple independent verifiers (microservices, third parties): prefer `Ed25519` (or `Ed448`) when available; otherwise `ES256`; otherwise `RS256`.
///

/// note | SuperJWT dependency note
Asymmetric algorithms require the optional `cryptography` dependency.
///

See also: [JWT Content](content.md) for how `alg`, `kid`, and related headers fit into the token.

---

## Symmetric Algorithms (HMAC)

**HMAC (Hash-based Message Authentication Code)** algorithms use a **single shared secret key** for both signing and verification.

- **Signing**: The issuer signs the token using the secret key.
- **Verification**: The receiver verifies the token using the **same** secret key.

### Common Algorithms

| Algorithm | Description | Key Type | Security Level |
|-----------|-------------|----------|----------------|
| **HS256** | HMAC using SHA-256 | Octet Sequence (Shared Secret) | Good (Standard) |
| **HS384** | HMAC using SHA-384 | Octet Sequence (Shared Secret) | Better |
| **HS512** | HMAC using SHA-512 | Octet Sequence (Shared Secret) | Best |

### Pros & Cons

**✅ Pros:**

- Faster computation (signing and verifying are very fast)
- Smaller token size (signature is shorter)
- Simple to implement

**❌ Cons:**

- **Key Distribution**: The secret key must be shared with every service that needs to verify the token. If one service is compromised, the key is compromised for everyone.
- **No Non-repudiation**: Since multiple parties have the key, you can't prove *who* created the token (any party with the key could have created it).

### When to use
Use HMAC when the token issuer and verifier are the same application, or when you have a trusted internal network where sharing the secret key is safe.

/// warning | Shared secret blast radius
With HMAC, every verifier must know the same secret. If any verifier is compromised, an attacker can **forge** tokens.
///

---

## Asymmetric Algorithms

Asymmetric algorithms use a **key pair**: a **Private Key** for signing and a **Public Key** for verification.

- **Signing**: The issuer signs the token using the **Private Key** (kept secret).
- **Verification**: The receiver verifies the token using the **Public Key** (can be shared openly).

### 1. RSA (Rivest–Shamir–Adleman)

RSA is the most widely used asymmetric algorithm.

| Algorithm | Description | Key Type | Security Level |
|-----------|-------------|----------|----------------|
| **RS256** | RSASSA-PKCS1-v1_5 using SHA-256 | RSA Key Pair | Good (Standard) |
| **RS384** | RSASSA-PKCS1-v1_5 using SHA-384 | RSA Key Pair | Better |
| **RS512** | RSASSA-PKCS1-v1_5 using SHA-512 | RSA Key Pair | Best |
| **PS256** | RSASSA-PSS using SHA-256 | RSA Key Pair | Stronger than RS256 |

/// tip | RSA choice
Prefer RSA-PSS (`PS256`) over PKCS#1 v1.5 (`RS256`) when your ecosystem supports it.
///

### 2. ECDSA (Elliptic Curve Digital Signature Algorithm)

ECDSA offers the same security level as RSA but with **much smaller key sizes**, resulting in faster computations and smaller signatures.

| Algorithm | Description | Key Type | Curve |
|-----------|-------------|----------|-------|
| **ES256** | ECDSA using P-256 and SHA-256 | EC Key Pair | P-256 |
| **ES256K** | ECDSA using secp256k1 and SHA-256 | EC Key Pair | secp256k1 |
| **ES384** | ECDSA using P-384 and SHA-384 | EC Key Pair | P-384 |
| **ES512** | ECDSA using P-521 and SHA-512 | EC Key Pair | P-521 |

### 3. EdDSA (Edwards-curve Digital Signature Algorithm)

EdDSA is a modern, high-performance signature scheme. In JOSE/JWT, you typically select a specific curve with `alg = Ed25519` or `alg = Ed448`.

| Algorithm | Description | Key Type | Curve |
|-----------|-------------|----------|-------|
| **Ed25519** | EdDSA using Ed25519 curve | OKP (Octet Key Pair) | Ed25519 |
| **Ed448** | EdDSA using Ed448 curve | OKP (Octet Key Pair) | Ed448 |

### RSA vs ECDSA vs EdDSA

**RSA (`RS256`/`PS256`)**

- ✅ Very widely supported; often the safest choice for interoperability.
- ✅ Verification is commonly fast (useful because tokens are usually verified far more often than they’re signed).
- ❌ Signatures are large compared to ECDSA/EdDSA.
- ❌ Prefer `PS256` over `RS256` for new systems when possible; PSS is generally considered more robust and easier to implement correctly.

**ECDSA (`ES256`/`ES384`/`ES512`)**

- ✅ Smaller keys and signatures than RSA for comparable security.
- ✅ Often faster at signing than RSA.
- ❌ Requires high-quality per-signature randomness (a nonce). Bugs or nonce reuse can leak the private key.
- ❌ Verification speed is not necessarily better than RSA, so verify-heavy workloads may not benefit.

**EdDSA (`Ed25519`/`Ed448`)** 👍👍👍

- ✅ Deterministic signatures (avoids the ECDSA nonce-generation footgun).
- ✅ Fast signing and verification with compact signatures.
- ❌ Support can be uneven in older JWT libraries and SaaS identity products (though it keeps improving).

Reference: https://www.scottbrady.io/jose/jwts-which-signing-algorithm-should-i-use

### Pros & Cons (Asymmetric)

**✅ Pros:**

- **Secure Key Distribution**: The private key never leaves the issuer. Verifiers only need the public key.
- **Non-repudiation**: Only the holder of the private key could have signed the token.
- **Scalability**: Perfect for microservices or third-party clients where you don't want to share secrets.

**❌ Cons:**

- Slower computation than HMAC (especially RSA).
- Larger token size (signatures are longer).
- More complex key management (key rotation, JWKS endpoints).

### When to use
Use Asymmetric algorithms when:

- You have multiple services verifying tokens (microservices).
- You are issuing tokens to third-party clients (OAuth2/OIDC).
- You cannot trust the verifier with a secret key.

---

## What is best, and why?

There is no single best algorithm for every deployment, but these are strong defaults:

- **Best default asymmetric**: `Ed25519` - fast, compact signatures, strong modern design.
- **Best asymmetric for broad enterprise interoperability**: `RS256` (or `PS256` if supported) - widely supported, but larger and slower.
- **Best symmetric**: `HS256` - simplest and fastest, but only appropriate when sharing a secret across verifiers is acceptable.

Your best choice depends on:

- **Who verifies** (one service vs many services).
- **Interoperability constraints** (legacy clients, language runtimes).
- **Performance and token size** requirements.

---

## Qualitative benchmark (rules of thumb)

Real performance depends on hardware and crypto backends, but this table captures typical trade-offs.

| Algorithm family | Sign speed | Verify speed | Signature size | Interop |
|---|---|---|---|---|
| HMAC (`HS256/384/512`) | Fastest | Fastest | Small | Excellent |
| EdDSA (`Ed25519`/`Ed448`) | Fast | Fast | Small | Good (improving) |
| ECDSA (`ES256/384/512`) | Medium | Medium | Small | Good |
| RSA-PSS (`PS256/384/512`) | Slow | Medium | Large | Medium |
| RSA v1.5 (`RS256/384/512`) | Slow | Medium | Large | Excellent |

### Picking an algorithm by scenario

- **Single API + single verifier**: `HS256`
- **Microservices (many verifiers)**: `Ed25519` (or `ES256`)
- **OAuth2/OIDC-style ecosystems / maximum compatibility**: `RS256` (or `PS256`)
- **Constrained bandwidth (cookies, mobile)**: prefer `HS256` or `Ed25519` over RSA

---

## Summary Comparison

| Feature | HMAC (Symmetric) | RSA/ECDSA/EdDSA (Asymmetric) |
|---------|------------------|------------------------------|
| **Keys** | Single Shared Secret | Private (Sign) + Public (Verify) |
| **Speed** | Very Fast | Slower |
| **Signature Size** | Small | Larger |
| **Key Management** | Simple (but risky distribution) | Complex (but secure distribution) |
| **Best For** | Internal Monoliths, Trusted Services | Microservices, Public APIs, OAuth2 |

---

## Security Best Practices

1. **Don't use `none`**: The `none` algorithm allows tokens without signatures. Always disable this in production (SuperJWT disables it by default).
2. **Use Strong Keys**:

      - HMAC: Minimum 256-bit random key (32 bytes).
      - RSA: Minimum 2048-bit key length.

3. **Protect Private Keys**: Never share or commit private keys. Use environment variables or secret managers (Vault, AWS Secrets Manager, ...etc).
4. **Rotate Keys**: Regularly rotate keys to minimize impact if a key is compromised. Use `kid` (Key ID) in the header to manage rotation.

/// tip | Rotation and `kid`
If you rotate signing keys, publish (or distribute) the current set of verification keys and use `kid` to let verifiers select the correct key.
///
