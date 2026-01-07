✅ **Do**

&#x22D9; **Always** verify JWT with `decode()` in production.

&#x22D9; Set an **expiration time** to limit token lifetime, see [Set Token Expiration](user-guide.md#set-expiration-exp).

&#x22D9; Use **appropriate** keys for a specific algorithm, see [Generate Keys](algorithms.md#how-to-generate-keys).

&#x22D9; **Validate** your claims by using JWT Pydantic models, see [Custom Validation](user-guide.md#custom-models).

&#x22D9; Handle SuperJWT **exceptions** in your code to catch tampering attempts or claims alignment issues, see [Error Handling](error-handling.md#exceptions).

&#x22D9; Keep **secrets secure** by storing them in secret management systems / environment variables.

---

❌ **Don't**

&#x22D9; Don't store sensitive data in a JWT/JWS. Since tokens are not encrypted, their content can be read by anyone.

&#x22D9; Don't share or reuse secret keys across environments.

&#x22D9; Never use data from `inspect()` in production as it bypasses signature verification.

&#x22D9; Never trust client-provided tokens until signature verification is done.
