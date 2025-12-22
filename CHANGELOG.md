# Changelog

## Unreleased

### Changes

- Add compatibility for python 3.10 & 3.11 (was working only for python 3.12-3.14 previously)
- Better tests for datetime claims
- SecondDatetime renamed to JWTDatetime

### :bug: Fix

- datetime validation for custom claims is now working properly

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
