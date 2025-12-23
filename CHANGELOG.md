# Changelog

## Unreleased

### :gear: Changes

- State, data integrity and consistency of JWT and JWS instances improved ([#15])
  - A JWT instance now should always have consistent token and jws data every time an operation of encode / decode is performed successfully
  - `JWT.token` is now a `JWSToken`
  - `JWTCompliantClaims` replace `JWTClaims` for default claim validation with all registered claims marked optional, use `JWTClaims` if you still want iat claim to be set automatically
- `disable_headers_validation` parameter was missing in `encode()` and `decode()`
- b64=false in header will raise an `InvalidHeaderError` as this is not a supported feature ([#13])
- Add compatibility for python 3.10 & 3.11, was working only for python 3.12-3.14 previously
- Better tests for datetime claims
- `SecondDatetime` renamed to `JWTDatetime` ([#6])

### :bug: Fixes

- validation for custom datetime claims is now working properly ([#7])
- `HeaderValidationError` exception no longer throws IndexError ([#14])
- `inspect()` now works with detached payload

## v0.1.0 (2025-12-08)

### :sparkles: New

- JWT/JWS encode + decode + inspect
- HMAC with SHA256/384/512 signature
- Automatic claims validation with Pydantic
- Custom claims definition with Pydantic
- CI workflow: lint, test, validate-release, release
- PyPI workflow: publish to testPyPI & PyPI upon release

## v0.0.0

:tada: superjwt repository initialization


[#15]: /../../issues/15
[#14]: /../../issues/14
[#13]: /../../issues/13
[#7]: /../../issues/7
[#6]: /../../issues/6
