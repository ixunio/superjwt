
# Signing Algorithms

In a signed JWT (a JWS in compact form), the integrity of the token ultimately comes down to the signature. The `alg` header parameter tells verifiers **which signing algorithm** was used so they can verify the signature correctly.

This page explains the most common algorithm families, the trade-offs between them, and how to pick a reasonable default. If you want more context about how `alg`, `kid`, and other header fields fit into a token, see: [JWT Content](content.md).

At a high level there are two categories:

- **Symmetric** algorithms (HMAC): one shared secret is used for both signing and verification.
- **Asymmetric** algorithms (RSA, ECDSA, EdDSA): a private key signs and a public key verifies.

/// tip | Quick recommendations
- **Single service / monolith**: start with `HS256` and a strong random secret.
- **Many independent verifiers** (microservices, third parties): prefer `Ed25519` (or `Ed448`) when available; otherwise `ES256`; otherwise `RS256`.
///

---

## Symmetric Algorithms (HMAC)

**HMAC (Hash-based Message Authentication Code)** algorithms use a **single shared secret key** for both signing and verification. This makes them extremely fast and simple, but it also means every verifier must be trusted with the same secret.

Concretely:

- When you **sign**, you use the shared secret.
- When you **verify**, you use that same shared secret.

### Most Used

If you only need one HMAC algorithm, `HS256` is the common default.

| Algorithm | Description | Key Type | Security Level |
|-----------|-------------|----------|----------------|
| **HS256** | HMAC using SHA-256 | Octet Sequence (Shared Secret) | Good |
| **HS384** | HMAC using SHA-384 | Octet Sequence (Shared Secret) | Better |
| **HS512** | HMAC using SHA-512 | Octet Sequence (Shared Secret) | Best |

### Pros & Cons

HMAC tends to feel “easy” because there are fewer moving parts, and performance is excellent. The trade-off is operational: distributing the same secret to many verifiers increases the impact of a single compromise.

**What HMAC is great at**

- Very fast signing and verification
- Small signatures (good for cookies and bandwidth-constrained contexts)
- Minimal key management complexity

**What you give up**

- **Key distribution safety**: every verifier that can validate can also forge if compromised
- **Non-repudiation**: you cannot prove which holder of the secret signed a token

### When to use
Use HMAC when the token issuer and verifier are the same application (or a tightly controlled cluster where sharing a single secret is acceptable).

/// warning | Shared secret blast radius
With HMAC, every verifier must know the same secret. If any verifier is compromised, an attacker can **forge** tokens.
///

---

## Asymmetric Algorithms

Asymmetric algorithms use a **key pair**: a **private key** for signing and a **public key** for verification. This separates responsibilities cleanly: only the issuer needs the private key, while any number of services can hold the public key.

In practice:

- When you **sign**, you use the private key (keep it secret).
- When you **verify**, you use the public key (it can be widely distributed).

This model is usually the right choice when many independent systems must verify tokens, or when you can’t (or don’t want to) trust every verifier with the power to mint tokens.

### 1. RSA (Rivest–Shamir–Adleman)

RSA is the most widely deployed asymmetric option in JWT ecosystems. It’s often chosen for interoperability, especially in enterprise stacks.

RSA has two common flavors in JWT:

- **RS*** (PKCS#1 v1.5): very widely supported.
- **PS*** (RSA-PSS): generally considered a more robust padding scheme, but support can be less universal.

| Algorithm | Description | Key Type | Security Level |
|-----------|-------------|----------|----------------|
| **RS256** | RSASSA-PKCS1-v1_5 using SHA-256 | RSA Key Pair | Good (Standard) |
| **RS384** | RSASSA-PKCS1-v1_5 using SHA-384 | RSA Key Pair | Better |
| **RS512** | RSASSA-PKCS1-v1_5 using SHA-512 | RSA Key Pair | Best |
| **PS256** | RSASSA-PSS using SHA-256 | RSA Key Pair | Stronger than RS256 |
| **PS384** | RSASSA-PSS using SHA-384 | RSA Key Pair | Stronger than RS384 |
| **PS512** | RSASSA-PSS using SHA-512 | RSA Key Pair | Stronger than RS512 |

/// tip | RSA choice
Prefer RSA-PSS (`PS256`) over PKCS#1 v1.5 (`RS256`) when your ecosystem supports it.
///

### 2. ECDSA (Elliptic Curve Digital Signature Algorithm)

ECDSA offers comparable security to RSA with **much smaller key sizes**, which usually yields smaller signatures but is slower.

The main operational footgun with ECDSA is that signing requires a fresh per-signature nonce. High-quality implementations handle this correctly, but nonce reuse (or biased randomness) can leak the private key.

| Algorithm | Description | Key Type | Curve |
|-----------|-------------|----------|-------|
| **ES256** | ECDSA using P-256 and SHA-256 | EC Key Pair | P-256 |
| **ES256K** | ECDSA using secp256k1 and SHA-256 | EC Key Pair | secp256k1 |
| **ES384** | ECDSA using P-384 and SHA-384 | EC Key Pair | P-384 |
| **ES512** | ECDSA using P-521 and SHA-512 | EC Key Pair | P-521 |

### 3. EdDSA (Edwards-curve Digital Signature Algorithm)

EdDSA is a modern signature scheme designed to avoid common pitfalls (notably, it’s deterministic rather than relying on per-signature randomness like ECDSA).

In **SuperJWT**, you select a specific EdDSA curve by choosing `alg = Ed25519` or `alg = Ed448`.

/// note | Interop note
Some JOSE/JWT ecosystems expose EdDSA as `alg = EdDSA` with the curve specified elsewhere (for example via key parameters). SuperJWT intentionally uses `Ed25519` and `Ed448` as algorithm identifiers.
///

| Algorithm | Description | Key Type | Curve |
|-----------|-------------|----------|-------|
| **Ed25519** | EdDSA using Ed25519 curve | OKP (Octet Key Pair) | Ed25519 |
| **Ed448** | EdDSA using Ed448 curve | OKP (Octet Key Pair) | Ed448 |

### RSA vs ECDSA vs EdDSA

If you’re choosing among asymmetric families, it helps to think in terms of interoperability, signature size, and operational risk.

**RSA (`RS256`/`PS256`)**

- ✅ Very widely supported; often the safest choice for interoperability.
- ✅ Verification is commonly fast (useful because tokens are usually verified far more often than they’re signed).
- ❌ Signatures are large compared to ECDSA/EdDSA.
- ❌ Prefer `PS256` over `RS256` for new systems when possible; PSS is generally considered more robust and easier to implement correctly.

**ECDSA (`ES256`/`ES384`/`ES512`)**

- ✅ Smaller keys and signatures than RSA for comparable security.
- ❌ Requires high-quality per-signature randomness (a nonce). Bugs or nonce reuse can leak the private key.
- ❌ Verification speed is slower than RSA, especially for ES256K, ES384, and ES512, so verify-heavy workloads may not benefit.

**EdDSA (`Ed25519`/`Ed448`)** 👍👍👍

- ✅ Deterministic and compact signatures.
- ✅ Fast signing and verification with compact signatures.
- ❌ Support can be uneven in older JWT libraries and SaaS identity products (though it keeps improving).
- ❌ Verification speed is slower than RSA, especially for Ed448, so verify-heavy workloads may not benefit.

### Pros & Cons

Asymmetric signing is typically what you want once you have multiple verifiers or third-party consumers.

**Why teams like asymmetric keys**

- You can distribute verification widely without distributing signing power
- Key rotation can be done by publishing public keys (for example via a JWKS endpoint)
- You get a clearer separation of duties between issuer and verifier

**What it costs**

- More complex key management (rotation, publishing, `kid` selection)
- Typically larger signatures and slower crypto than HMAC (especially with ECDSA)

### When to use
Use asymmetric algorithms when any of the following are true:

- You have multiple services verifying tokens (microservices).
- You are issuing tokens to third-party clients (OAuth2/OIDC).
- You cannot trust the verifier with a secret key.

---

## What is best, and why?

There isn’t a single "best" algorithm for every deployment. Good defaults depend on who verifies tokens, how painful key distribution is for you, and what your interoperability constraints look like.

These are strong, commonly safe defaults:

- **Best default asymmetric**: `Ed25519` - fast, compact signatures, strong modern design.
- **Best asymmetric for broad enterprise interoperability**: `RS256` (or `PS256` if supported) - widely supported, but larger and slower.
- **Best symmetric**: `HS256` - simplest and fastest, but only appropriate when sharing a secret across verifiers is acceptable.

When in doubt, decide based on:

- **Who verifies** (one service vs many services).
- **Interoperability constraints** (legacy clients, language runtimes).
- **Performance and token size** requirements.

---

## Qualitative benchmark (rules of thumb)

Real performance depends on hardware and crypto backends, but this table captures the usual trade-offs you can expect.

| Algorithm family | Sign speed | Verify speed | Signature size | Interop |
|---|---|---|---|---|
| HMAC (`HS256/384/512`) | Fastest | Fastest | Small | Excellent |
| EdDSA (`Ed25519`/`Ed448`) | Fast | Fast | Small | Good (improving) |
| ECDSA (`ES256/384/512`) | Medium | Medium | Small | Good |
| RSA-PSS (`PS256/384/512`) | Slow | Medium | Large | Medium |
| RSA v1.5 (`RS256/384/512`) | Slow | Medium | Large | Excellent |

### Picking an algorithm by scenario

If you just need a "good enough" decision quickly:

- If **one service both issues and verifies** (or you fully trust every verifier), choose `HS256`.
- If **many services verify** and you want to avoid sharing a single secret, choose `Ed25519` (or `ES256`).
- If you need **maximum compatibility with existing JWT consumers**, choose `RS256` (or `PS256` if supported).
- If you care about **small tokens** (cookies, mobile), prefer `HS256` or `Ed25519` over RSA.

---

## Summary Comparison

This is the "shape" of the trade-off:

| Feature | HMAC (Symmetric) | RSA/ECDSA/EdDSA (Asymmetric) |
|---------|------------------|------------------------------|
| **Keys** | Single Shared Secret | Private (Sign) + Public (Verify) |
| **Speed** | Very Fast | Slower |
| **Signature Size** | Small | Larger |
| **Key Management** | Simple (but risky distribution) | Complex (but secure distribution) |
| **Best For** | Internal Monoliths, Trusted Services | Microservices, Public APIs, OAuth2 |

---

## Security Best Practices

Good algorithm choice helps, but most JWT failures in real systems come from configuration mistakes, key leaks, or verification shortcuts.

1. **Never accept `none`**

      The `none` algorithm produces an unsigned token. That’s almost never what you want for authentication. SuperJWT blocks `none` by default.

2. **Use strong keys**

      - HMAC: generate at least 256 bits of randomness (32 bytes) and treat it like a password that must never leak.
      - RSA: use at least 2048-bit keys (3072+ is a common upgrade path for long-lived deployments).

3. **Protect private keys**

      Store private keys in a secret manager (Vault, AWS Secrets Manager, etc.) and limit access to only the systems that must sign.

4. **Rotate keys deliberately**

      Plan for rotation from day one: publish (or distribute) verification keys and use `kid` (Key ID) to let verifiers select the right key.

/// tip | Rotation and `kid`
If you rotate signing keys, publish (or distribute) the current set of verification keys and use `kid` to let verifiers select the correct key.
///
