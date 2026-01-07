# Versioning Policy

SuperJWT follows [Semantic Versioning](https://semver.org/).

**Current Status:** Production Ready (Pre-1.0)

While we are working towards a stable `v1.0.0` release, the library is already robust and used in production environments. We strive to maintain stability, but please note that versions before 1.0.0 may introduce breaking changes in minor updates.

However, we are committed to minimizing disruption:

- **Patch versions** (e.g., `0.5.0` -> `0.5.1`) contain only bug fixes and are safe to upgrade.
- **Minor versions** (e.g., `0.5.x` -> `0.6.x`) may contain new features or breaking changes.<br>We will document these clearly in the [Changelog](../changelog).

## Pinning Strategy

To ensure stability in your application, we strongly recommend pinning your dependency on SuperJWT. This prevents unexpected breaking changes from affecting your deployments.

If you are using a `pyproject.toml` or `requirements.txt` file, `uv`, `poetry`, or `pip`, you should restrict the version range to the current minor version.

**Example:**
If you start using SuperJWT at version `0.5.0`, pin it like this:

```txt
superjwt>=0.5.0,<0.6.0
```

This configuration allows you to automatically receive bug fixes (e.g., `0.5.1`, `0.5.2`) but prevents upgrading to `0.6.0`, which might require code changes on your end.

## How to Upgrade

When you decide to upgrade to a new minor version (e.g., from `0.5.x` to `0.6.x`):

1.  **Check the [Changelog](../changelog)** for any breaking changes or migration guides.
2.  **Update your dependency pin** (e.g., change `superjwt>=0.5.0,<0.6.0` to `superjwt>=0.6.0,<0.7.0`).
3.  **Run your test suite**. SuperJWT has extensive test coverage, and we recommend you do the same for your integration code.
4.  If tests pass, you are good to go!

## Library Dependencies

SuperJWT is designed to be lightweight, but it stands on the shoulders of giants:

### ⇨ [Pydantic v2](https://docs.pydantic.dev/latest/)
Core validation logic relies on **Pydantic**:

- **Required**: `pydantic>=2.0.0`
- SuperJWT is fully compatible with Pydantic v2.

### ⇨ [pyca/cryptography](https://cryptography.io/en/latest/)

*(optional)*

Asymmetric support (RSA, ECDSA, EdDSA) relies on `cryptography` library:

- **Required**: `cryptography>=43.0.0`
- Install via: `pip install "superjwt[asymmetric]"`
