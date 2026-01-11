# Changelog

## Unreleased

### :sparkles: New

#### Algorithms & Keys

- Asymmetric JWS signature algorithms support
    - RSA PKCS1 v1.5 (`RS256`, `RS384`, `RS512`) ([#68])
    - RSA PSS (`PS256`, `PS384`, `PS512`) ([#69])
    - ECDSA (`ES256`, `ES256K`, `ES384`, `ES512`) ([#71])
    - EdDSA (`Ed25519`, `Ed448`) ([#71])
- Asymmetric keys support
    - RSA key pair ([#67])
    - EC (Elliptic Curve) key pair for ECDSA ([#70])
    - OKP (Octet Key Pair) for EdDSA ([#70])
- Key generation ([#72])
- Pick algorithm from `Alg` str Enum ([#57])

#### Validation

- Validation can be configured via `ValidationConfig` and supports internal params (leeway, now, allow_future_iat) ([#62]) ([#75])
- Choose timestamp serialization format (`int` or `float`) ([#53])
    - Configure `JWTDatetime` default behavior (default `int`)
    - New `JWTDatetimeInt` field type to serialize as `int` timestamp
    - New `JWTDatetimeFloat` field type to serialize as `float` timestamp
- Time integrity validation update ([#55])
    - add leeway support for `'iat'`, `'exp'`, and `'nbf'` comparison against *now*
    - new check that `'iat'` is not in the future. Can be disabled via validation config.
- Time spoofing for validation and testing purposes ([#51])

### :gear: Changes

- `.with_issued_at()` and `.with_expiration()` now preserve time delta with `'iat'` ([#49])

## v0.4.1 (2026-01-03)

### :bug: Fixes

- `'exp'` and `'nbf'` incorrect validation when `'iat'` was present ([#47])

## v0.4.0 (2026-01-02)

### :sparkles: New

- `Validation` flag can be passed to choose between two modes: ([#39])
    - Validation.DEFAULT (default when nothing is specified)
    - Validation.DISABLE
- `JWT` can receive a `max_token_bytes` parameter to control the allowed max token size ([#40])
- `JWTClaims` now raises `TokenNotYetValidError` if `'nbf'` > `'iat'` (or present time) ([#41])

### :gear: Changes

- Refactoring of public and private interfaces ([#39])
    - module-level `encode()`, `decode()` and `inspect()` are now thread safe and written as functions instead of a local stateful `JWT` instance
    - `token` param in `decode()` is renamed `compact`
    - `JWT` methods now always return a `JWSToken`
- Refactoring of exception handling ([#40])
    - base exception is now `SuperJWTError`
    - improved exceptions hierarchy

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


[#75]: https://github.com/ixunio/superjwt/issues/75
[#72]: https://github.com/ixunio/superjwt/issues/72
[#71]: https://github.com/ixunio/superjwt/issues/71
[#70]: https://github.com/ixunio/superjwt/issues/70
[#69]: https://github.com/ixunio/superjwt/issues/69
[#68]: https://github.com/ixunio/superjwt/issues/68
[#67]: https://github.com/ixunio/superjwt/issues/67
[#62]: https://github.com/ixunio/superjwt/issues/62
[#57]: https://github.com/ixunio/superjwt/issues/57
[#55]: https://github.com/ixunio/superjwt/issues/55
[#53]: https://github.com/ixunio/superjwt/issues/53
[#51]: https://github.com/ixunio/superjwt/issues/51
[#49]: https://github.com/ixunio/superjwt/issues/49
[#47]: https://github.com/ixunio/superjwt/issues/47
[#42]: https://github.com/ixunio/superjwt/issues/42
[#41]: https://github.com/ixunio/superjwt/issues/41
[#40]: https://github.com/ixunio/superjwt/issues/40
[#39]: https://github.com/ixunio/superjwt/issues/39
[#34]: https://github.com/ixunio/superjwt/issues/34
[#31]: https://github.com/ixunio/superjwt/issues/31
[#24]: https://github.com/ixunio/superjwt/issues/24
[#17]: https://github.com/ixunio/superjwt/issues/17
[#15]: https://github.com/ixunio/superjwt/issues/15
[#14]: https://github.com/ixunio/superjwt/issues/14
[#13]: https://github.com/ixunio/superjwt/issues/13
[#7]: https://github.com/ixunio/superjwt/issues/7
[#6]: https://github.com/ixunio/superjwt/issues/6
