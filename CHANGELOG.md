# Changelog

## v0.4.0 (2026-01-02)

### :sparkles: New

- `Validation` flag can be passed to choose between two modes: ([#39])
    - Validation.DEFAULT (default when nothing is specified)
    - Validation.DISABLE
- Default validation behavior for claims and headers can now be customized with `JWTValidationModelConfig` ([#38])
- `JWT` can receive a `max_token_bytes` parameter to control the allowed max token size ([#40])
- `JWTClaims` now raises `TokenNotYetValidError` if `'nbf'` > `'iat'` (or present time) ([#41])

## :gear: Changes

- Refactoring of public and private interfaces ([#39])
    - module-level `encode()`, `decode()` and `inspect()` are now thread safe and written as functions instead of a local stateful `JWT` instance
    - `token` param in `decode()` is renamed `compact`
    - `JWT` methods now always return a `JWSToken`
- Refactoring of exception handling ([#40])
    - base exception is now `SuperJWTError`
    - improved exceptions hierarchy

## Fixes

- `'exp'` and `'nbf'` validation is now performed against `'iat'` if exists, otherwise present time ([#42])

## v0.3.0 (2025-12-30)

### :sparkles: New

- Validate claims or headers with custom pydantic models for `decode()` ([#34])
- Expired token now raises `TokenExpiredError` upon claims validation ([#24])
- New exception `AlgorithmMismatchError` is raised during decoding when `'alg'` is valid but not declared as processable by the JWS instance ([#31])

### :gear: Changes

- Refactoring of `JWTClaims` pydantic model ([#17])
    - defaulting with no `'iat'` set
    - `with_issued_at()` method added
- Refactoring of claims and headers validation ([#34])
    - `encode()` new validation default behavior:
        - when `claims` is passed as a pydantic instance, validate against it automatically
        - when `claims` is passed as a dict or empty, no automatic validation
        - when `headers` (optional) is passed as a pydantic instance, validate against it automatically
        - when `headers` (optional) is passed as a dict, validate against `JOSEHeader`
    - `decode()` new validation default behavior:
        - no automatic validation for claims by default
        - headers are automatically validated against `JOSEHeader`
    - claims & headers default validation can be overridden by passing a pydantic model to the validation params in `encode()` / `decode()`

## v0.2.0 (2025-12-27)

### :gear: Changes

- State, data integrity and consistency of JWT and JWS instances improved ([#15])
- b64=false in header will raise an `InvalidHeaderError` as this is not a supported feature ([#13])
- Add compatibility for python 3.10 & 3.11, was working only for python 3.12-3.14 previously
- Better tests for datetime claims
- `SecondDatetime` renamed to `JWTDatetime` ([#6])

### :bug: Fixes

- Validation for custom datetime claims is now working properly ([#7])
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


[#42]: /../../issues/42
[#41]: /../../issues/41
[#40]: /../../issues/40
[#39]: /../../issues/39
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
