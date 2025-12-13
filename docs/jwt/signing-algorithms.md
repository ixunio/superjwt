# Signing Algorithms

The security of a JWT depends heavily on the signing algorithm used. The `alg` header parameter specifies which algorithm was used to sign the token.

There are two main categories of signing algorithms: **Symmetric** (HMAC) and **Asymmetric** (RSA, ECDSA, EdDSA).

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

### 2. ECDSA (Elliptic Curve Digital Signature Algorithm)

ECDSA offers the same security level as RSA but with **much smaller key sizes**, resulting in faster computations and smaller signatures.

| Algorithm | Description | Key Type | Curve |
|-----------|-------------|----------|-------|
| **ES256** | ECDSA using P-256 and SHA-256 | EC Key Pair | P-256 |
| **ES384** | ECDSA using P-384 and SHA-384 | EC Key Pair | P-384 |
| **ES512** | ECDSA using P-521 and SHA-512 | EC Key Pair | P-521 |

### 3. EdDSA (Edwards-curve Digital Signature Algorithm)

EdDSA is a modern, high-performance signature scheme (using Ed25519 or Ed448 curves). It is faster and more secure against side-channel attacks than ECDSA.

| Algorithm | Description | Key Type | Curve |
|-----------|-------------|----------|-------|
| **EdDSA** | EdDSA signature scheme | OKP (Octet Key Pair) | Ed25519 / Ed448 |

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

## Summary Comparison

| Feature | HMAC (Symmetric) | RSA/ECDSA/EdDSA (Asymmetric) |
|---------|------------------|------------------------------|
| **Keys** | Single Shared Secret | Private (Sign) + Public (Verify) |
| **Speed** | Very Fast | Slower |
| **Signature Size** | Small | Larger |
| **Key Management** | Simple (but risky distribution) | Complex (but secure distribution) |
| **Best For** | Internal Monoliths, Trusted Services | Microservices, Public APIs, OAuth2 |

## Security Best Practices

1. **Don't use `none`**: The `none` algorithm allows tokens without signatures. Always disable this in production (SuperJWT disables it by default).
2. **Use Strong Keys**:
   - HMAC: Minimum 256-bit random key (32 bytes).
   - RSA: Minimum 2048-bit key length.
3. **Protect Private Keys**: Never share or commit private keys. Use environment variables or secret managers (Vault, AWS Secrets Manager).
4. **Rotate Keys**: Regularly rotate keys to minimize impact if a key is compromised. Use `kid` (Key ID) in the header to manage rotation.
