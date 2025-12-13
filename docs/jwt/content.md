A JSON Web Token (JWT) consists of three parts separated by dots (`.`):

1. **Header** (JOSE Header)
2. **Payload** (JWT Claims)
3. **Signature**

```
[Header].[Payload].[Signature]
```

This document details the structure and standard fields for each part.

## 1. JOSE Header

The **JOSE (JSON Object Signing and Encryption)** header describes the cryptographic operations applied to the JWT. It typically consists of two parts: the type of the token and the signing algorithm being used.

### Standard Header Parameters

| Parameter | Full Name | Required | Description |
|-----------|-----------|----------|-------------|
| `alg` | Algorithm | **Yes** | The cryptographic algorithm used to secure the JWS. Examples: `HS256`, `RS256`, `none`. |
| `typ` | Type | No | The media type of this complete JWS. Recommended value is `JWT`. |
| `cty` | Content Type | No | The content type of the secured payload. Used when the payload is not a set of claims (e.g., nested JWTs). |
| `kid` | Key ID | No | A hint indicating which key was used to secure the JWS. Useful for key rotation. |
| `crit` | Critical | No | A list of header parameter names that MUST be understood and processed by the recipient. |

### Example Header

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key-2024-01"
}
```

### Critical Header (`crit`)

The `crit` header parameter indicates that extensions to the JWS/JWE specification are being used that MUST be understood and processed. If the recipient does not understand any of the header parameters listed in `crit`, it **MUST reject** the JWS.

```json
{
  "alg": "ES256",
  "crit": ["exp"],
  "exp": 1363284000
}
```

## 2. JWT Payload (Claims)

The payload contains the **claims**. Claims are statements about an entity (typically, the user) and additional data. There are three types of claims: **Registered**, **Public**, and **Private**.

### Registered Claims

These are a set of predefined claims which are not mandatory but recommended, to provide a set of useful, interoperable claims.

| Claim | Full Name | Type | Description |
|-------|-----------|------|-------------|
| `iss` | Issuer | str | Identifies the principal that issued the JWT. |
| `sub` | Subject | str | Identifies the principal that is the subject of the JWT (e.g., user ID). |
| `aud` | Audience | str \| list[str] | Identifies the recipients that the JWT is intended for. |
| `iat` | Issued At | int | Identifies the time at which the JWT was issued. (Unix timestamp) |
| `exp` | Expiration Time | int | Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. (Unix timestamp) |
| `nbf` | Not Before | int | Identifies the time before which the JWT MUST NOT be accepted for processing. (Unix timestamp) |
| `jti` | JWT ID | str | Provides a unique identifier for the JWT. Useful for preventing replay attacks. |

### Public Claims

These can be defined at will by those using JWTs. However, to avoid collisions, they should be defined in the [IANA JSON Web Token Claims Registry](https://www.iana.org/assignments/jwt/jwt.xhtml) or be defined as a URI that contains a collision-resistant namespace.

**Example:**

```json
{
  "https://example.com/is_root": true
}
```

### Private Claims

These are custom claims created to share information between parties that agree on using them and are neither registered or public claims.

**Example:**

```json
{
  "user_id": "123456",
  "role": "admin",
  "email": "user@example.com"
}
```

### Example Payload

```json
{
  "iss": "auth.example.com",
  "sub": "user123",
  "aud": "api.example.com",
  "exp": 1735689600,
  "iat": 1735686000,
  "role": "admin",
  "permissions": ["read:users", "write:users"]
}
```

!!! tip "Payload Size"
    Keep the payload small. The JWT is sent with every request, so a large payload can increase traffic and latency. Avoid storing large objects or sensitive data.

## 3. Signature

The signature is the third part of the JWT. It is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.

### Creation Process

To create the signature part, you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.

For example, if you want to use the HMAC SHA256 algorithm, the signature will be created in the following way:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

### Verification Process

When a server receives a JWT, it can verify the signature by:

1. Taking the header and payload from the received token
2. Using the same algorithm and secret key
3. Re-calculating the signature
4. Comparing the calculated signature with the signature in the token

If the signatures match, the token is valid and hasn't been tampered with.

### Security Implications

- **Integrity**: The signature ensures that the header and payload have not been modified.
- **Authentication**: If a shared secret (HMAC) is used, it verifies that the sender has the secret. If a private key (RSA/ECDSA) is used, it verifies that the sender has the private key.
- **Non-repudiation**: With asymmetric keys, the sender cannot deny signing the token.

## Complete Example

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

**Encoded Token:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

*(Newlines added for readability)*

## References

- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [IANA JSON Web Token Claims Registry](https://www.iana.org/assignments/jwt/jwt.xhtml)
