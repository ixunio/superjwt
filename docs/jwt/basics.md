## What is JWT?

**JWT (JSON Web Token)** is an open standard ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) that defines a compact, URL-safe means of representing claims to be transferred between two parties. The claims in a JWT token are encoded as a JSON object that is used either:

- as the payload of a JSON Web Signature (JWS) structure, enabling the claims to be digitally signed with a Message Authentication Code (MAC).
- as the payload of a JSON Web Encryption (JWE) structure, enabling the claims to be further encrypted. *❌ currently NOT supported by SuperJWT.*

JWT tokens are commonly used for:

- 🔓 **Web Authentication** - Once a user logs in, each subsequent request includes the JWT, allowing access to routes and resources without providing login/password credentials.
- 🔁 **Information Exchange** - Securely transmitting information between two parties with signature verification.
- 🕊️ **Stateless Sessions** - Avoiding server-side session storage by encoding session data in the token with optional expiration policy

Key benefits:

- 🤏 **Compact** - Small size makes it easy to send via HTTP header
- 🫙 **Self-contained** - Payload contains all required information about the user
- 👮 **Secure** - Digitally signed to prevent tampering

/// warning | SuperJWT support
SuperJWT does not currently support JWE structure. For the rest of the documentation, we will discuss only JWT embedded as a JWS structure.
///

## What is JWS?

**JWS (JSON Web Signature)** is is an open standard defined in [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) and represents content secured with digital signatures using JSON-based data structures.

In practice, **a signed JWT is a JWS**. When you create a JWT token with a signature, you're actually creating a JWS token where the payload is a set of encoded JWT claims.

Relationship Between JWT and JWS:

```
┌─────────────────────────────────────┐
│             JWS Token               │
│       (JSON Web Signature)          │
│                                     │
│     Header . Payload . Signature    │
│                 │                   │
│                 ▼                   │
│  ┌───────────────────────────────┐  │
│  │          JWT Claims           │  │
│  │    (JSON Web Token Payload)   │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

**Simply put:**

- **JWS** provides the signing mechanism and structure
- **JWT** defines the standard claims and semantics for the payload
- A **JWT token** is typically a JWS token with JWT-formatted claims

## Token Structure

Both JWT and JWS share the same three-part structure in their **compact serialization** format:

```
[Header].[Payload].[Signature]
```

All three parts are **Base64URL-encoded** and separated by dots (`.`).

**Example Token**<br>
*<small>with line breaks for display purposes only</small>*

```python
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  # (1)
.
eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzM0MTM0NDAwfQ  # (2)
.
OpOSSw7e485LOP5PrzScxHb7SR6sAOMRckfFwi4rp7o # (3)
```

1. this is the **Header** (base64url decoded):
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

2. this is the **Payload** (base64url decoded)
```json
{
  "sub": "user123",
  "iat": 1734134400
}
```

3. this is the **Signature** (binary data encoded as base64url)

This decodes to:

**Header** (base64url decoded):
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload** (base64url decoded):
```json
{
  "sub": "user123",
  "iat": 1734134400
}
```

**Signature** (binary data encoded as base64url):
```
OpOSSw7e485LOP5PrzScxHb7SR6sAOMRckfFwi4rp7o
```

## How JWT/JWS Works

### Token Creation (Encode)


```mermaid
graph TB
    A["*headers* 
    (JSON)"] --> B("Base64URL encode()")
    C["*payload*
    (JSON)"] --> D("Base64URL encode()")
    D --> F["*payload*
    (bytes)"]
    B --> E["*headers*
    (bytes)"]
    E --> H("Algorithm.sign(
      *headers*.*payload*, Key)")
    F --> H
    G["Key"] --> H
    Y["Algorithm"] --> H
    H --> I["*signature*
    (bytes)"]
    I --> J["Final token
    *header.payload.signature*
    (bytes)"]
    F --> J
    E --> J
```

**Steps:**

1. Create the JOSE header (algorithm and token type)
2. Create the payload with JWT claims
3. Base64URL encode both header and payload
4. Concatenate them with a dot: `encoded_header.encoded_payload`
5. Sign this string using the algorithm specified in the header
6. Base64URL encode the signature
7. Concatenate all three parts: `header.payload.signature`

### Token Verification (Decode)

```mermaid
graph TD
    A[*header.payload.signature*] --> B[Split by dots]
    B --> C[*header*]
    B --> D[*payload*]
    B --> E[*signature*]
    C --> F["Base64URL decode()"]
    D --> G["Base64URL decode()"]
    F --> H[Extract Algorithm]
    H --> I[Recreate Signature]
    G --> I
    I --> J[Compare Signatures]
    E --> J
    J --> K{Match?}
    K -->|Yes| L[Valid Token]
    K -->|No| M[Invalid - Tampered!]
```

**Steps:**

1. Split the token by dots (`.`) into three parts
2. Base64URL decode the header and payload
3. Extract the algorithm from the header
4. Recreate the signature using:
   - The decoded header and payload
   - The same secret key
   - The algorithm from the header
5. Compare the recreated signature with the provided signature
6. If they match → token is **valid and genuine**
7. If they don't match → token is **invalid and tampered**

## Security Model

##### What JWT/JWS Provides

✅ **Integrity** - Detects if the token has been tampered with  
✅ **Authentication** - Verifies the token was created by someone with the secret key  
✅ **Non-repudiation** - The signer cannot deny creating the token (with asymmetric keys)

##### What JWT/JWS Does NOT Provide

❌ **Confidentiality** - Payload is only Base64URL-encoded, **not encrypted**  
❌ **Encryption** - Anyone can decode and read the payload  
❌ **Privacy** - Don't store sensitive data in JWT claims

/// danger | Important Security Note
JWT tokens are **signed, not encrypted**. The payload is only Base64URL-encoded, which means anyone can decode and read it. Never store sensitive information like passwords, credit card numbers, or private keys in JWT claims.
    
If you need encryption, use **JWE (JSON Web Encryption)** instead, which SuperJWT may support in future versions.

///

## Base64URL Encoding

JWT uses **Base64URL encoding** (not standard Base64) which is URL-safe:

**Differences from standard Base64:**

- Replaces `+` with `-`
- Replaces `/` with `_`
- Removes padding `=` characters

This makes tokens safe to use in:

- URLs (query parameters)
- HTTP headers (Authorization header)
- Cookies
- POST form data

**Example:**

```python
# Standard Base64
"Hello World!" → "SGVsbG8gV29ybGQh"

# Base64URL (no padding)
"Hello World!" → "SGVsbG8gV29ybGQh"

# With special characters
"data+value/test=" → Standard: "ZGF0YSt2YWx1ZS90ZXN0PQ=="
                   → Base64URL: "ZGF0YSt2YWx1ZS90ZXN0"
```

## Common Use Cases

### 1. Authentication

```
User Login → Server Issues JWT → Client Stores Token → 
Client Sends Token with Requests → Server Verifies Token → Access Granted
```

### 2. Single Sign-On (SSO)

One JWT token can authenticate across multiple services without additional authentication:

```
Login at Service A → Get JWT → 
Access Service B (same JWT) → Access Service C (same JWT)
```

### 3. API Authorization

Include JWT in the `Authorization` header:

```http
GET /api/user/profile HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 4. Secure Information Exchange

Safely transmit information between parties:

```python
# Party A creates and signs a JWT
token = superjwt.encode(claims={"data": "sensitive_info"}, key=secret_key)

# Party B receives and verifies
claims = superjwt.decode(token, key=secret_key)
# If verification succeeds, Party B knows:
# 1. The token came from someone with the secret key
# 2. The data hasn't been tampered with
```

## When to Use JWT

**✅ Use JWT when:**

- Building stateless, scalable APIs (see [Integrations with FastAPI](../integrations/fastapi.md)).
- Implementing microservices architecture
- Need to share authentication across domains
- Want to avoid server-side session storage
- Building Single Page Applications (SPAs)
- Implementing mobile app authentication

**❌ Consider alternatives when:**

- Need instant token revocation
- Storing large amounts of data
- Requiring high security for sensitive operations
- Managing long-lived sessions
- Building traditional server-rendered applications

## Next Steps

Now that you understand the basics of JWT and JWS:

- Learn about [JWT Content](content.md) - Standard claims, JOSE headers, and payload structure
- Explore [Signing Algorithms](signing-algorithms.md) - HMAC, RSA, and Ed25519 keys
- Check the [Getting Started Guide](../index.md) - Practical usage with SuperJWT

## References

- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [jwt.io](https://jwt.io/) - JWT debugger and introduction
- [JOSE Working Group](https://datatracker.ietf.org/wg/jose/about/) - IETF standards body
