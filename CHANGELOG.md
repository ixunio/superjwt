# Changelog

## Unreleased

### :sparkles: New

- default validation behavior for claims and headers can now be customized with `JWTValidationModelConfig` ([#38])

## v0.3.0 (2025-12-30)

### :sparkles: New

- validate claims or headers with custom pydantic models for `decode()` ([#34])
- expired token now raises `TokenExpiredError` upon claims validation ([#24])
- new exception `AlgorithmMismatchError` is raised during decoding when `'alg'` is valid but not declared as processable by the JWS instance ([#31])

### :gear: Changes

- Refactoring of `JWTClaims` pydantic model ([#17])
    - defaulting with no `'iat'` set
    - `with_issued_at()` method added
    - modular model with reusable mixins
- Refactoring of claims and headers validation ([#34])
    - `encode()` new validation default behavior:
        - when `claims` is passed as a pydantic instance, do validation with the pydantic model automatically
        - when `claims` is passed as a dict or empty, no automatic validation
        - when `headers` (optional) is passed as a pydantic instance, do validation with the pydantic model automatically
        - when `headers` (optional) is passed as a dict, validate against `JOSEHeader`
    - `decode()` new validation default behavior:
        - no automatic validation for claims by default, `validation_claims` must be specified to a pydantic model
        - headers are automatically validated against `JOSEHeader`
    - claims & headers validation can be overridden by passing a pydantic model to `validation_claims` & `validation_headers` params in `encode()` / `decode()`
    - claims & headers validation can be disabled by passing `None` to `validation_claims` & `validation_headers` params in `encode()` / `decode()`
    - claims data sent as dict are no longer serialized with Pydantic (datetime object will no longer work). Usage of Pydantic models is recommended instead.

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

[#38]: /../../issues/38
[#34]: /../../issues/34
[#31]: /../../issues/31
[#24]: /../../issues/24
[#17]: /../../issues/17
[#15]: /../../issues/15
[#14]: /../../issues/14
[#13]: /../../issues/13
[#7]: /../../issues/7
[#6]: /../../issues/6
