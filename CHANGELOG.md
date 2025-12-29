# Changelog

## Unreleased

### :sparkles: New

- validate claims or headers with custom pydantic models for `decode()` ([#21])
- expired token now raises `TokenExpiredError` upon validation ([#24])

### :gear: Changes

- Refactoring of `JWTClaims` pydantic model ([#17])
    - defaulting with no `'iat'` set
    - `with_issued_at()` method added
    - modular model with reusable mixins
- Refactoring of claims and headers validation ([#21])
    - `encode()` and `decode()` have now the same validation behavior with `claims_validation_model` and `headers_validation_model` parameters. Disable it by setting to `None`

## v0.2.0 (2025-12-27)

### :gear: Changes

- State, data integrity and consistency of JWT and JWS instances improved ([#15])
- `disable_headers_validation` parameter was missing in `encode()` and `decode()`
- b64=false in header will raise an `InvalidHeaderError` as this is not a supported feature ([#13])
- Add compatibility for python 3.10 & 3.11, was working only for python 3.12-3.14 previously
- Better tests for datetime claims
- `SecondDatetime` renamed to `JWTDatetime` ([#6])

### :bug: Fixes

- validation for custom datetime claims is now working properly ([#7])
- `HeaderValidationError` exception no longer throws `IndexError` ([#14])
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

[#24]: /../../issues/24
[#21]: /../../issues/21
[#17]: /../../issues/17
[#15]: /../../issues/15
[#14]: /../../issues/14
[#13]: /../../issues/13
[#7]: /../../issues/7
[#6]: /../../issues/6
