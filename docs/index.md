<style>
/* Hide the h1 title in the main content area */
.md-content h1 {
    display: none;
}

/* Replace unordered list bullets with an arrow glyph */
.md-content ul {
    list-style: none;
    padding-left: 1.25rem;
}
.md-content ul li::before {
    content: "⇨";
    display: inline-block;
    width: 1.25rem;
    margin-left: -1.25rem;
    color: inherit;
    font-weight: 600;
}

</style>

/// html | div

<img alt="SuperJWT logo" src="https://raw.githubusercontent.com/ixunio/superjwt/main/docs/assets/logo-full-superjwt.png">

<p align="center">
<em>
A modern implementation of JSON Web Token (JWT) for Python.
<br />
With powerful Pydantic validation features.
</em>
</p>

<div align="center">
<a href="https://github.com/ixunio/superjwt/actions?query=event%3Apush+workflow%3ACI+branch%3Amain++"><img alt="GitHub Actions workflow status on main branch" src="https://img.shields.io/github/actions/workflow/status/ixunio/superjwt/ci.yml?branch=main&logo=github-actions&logoColor=white&label=CI"></a>
<a href="https://codecov.io/github/ixunio/superjwt"><img src="https://codecov.io/github/ixunio/superjwt/graph/badge.svg?token=RF0O8W5LKG"/></a>
</div>
<div align="center">
<a href="https://pypi.org/project/superjwt/#history"><img alt="PyPI - Version" src="https://img.shields.io/pypi/v/superjwt?color=blue"></a>
<a href="https://pypi.org/project/superjwt/#history"><img alt="Supported Python versions" src="https://img.shields.io/pypi/pyversions/superjwt.svg?logo=python&logoColor=white"></a>
</div>

///

---

## Overview

SuperJWT is a minimalist JWT library for Python 3.10+ that combines the simplicity of JWT encoding/decoding with the power of [Pydantic](https://docs.pydantic.dev/latest/) validation. It supports JWS (JSON Web Signature) format with HMAC or various asymmetric algorithms and includes advanced features like enhanced time integrity checks, compact token inspection, custom timestamp serialization, detached payload mode, time spoofing, and more.<br>*[Learn more about JWT](./jwt/basics)*.

---

## Installation

HMAC support only (default)
```bash
pip install superjwt
```

With support for asymmetric algorithms
```bash
pip install superjwt[asymmetric]
```

---

## Features

### 🔏 JWT Secure Encoding & Decoding

- Sign and verify your JWT/JWS content with the algorithm of your choice!<br>All current state-of-the-art [algorithms](./algorithms.md) are implemented: `HMAC`, `RSA-PKCS1`, `RSA-PSS`, `ECDSA`, and `EdDSA`.
- Inspect your token without verification or validation for testing and debugging purposes.
- Generate your own keys, compatible with the selected algorithms.
- Use detached mode to send your JWT payload separately, while still being able to verify content integrity.

### 🕰️ Enhanced Time Integrity

- Check expiration and time integrity automatically.
- Configure leeway to account for clock skew.
- Use time spoofing for refined testing.

### ✔️ Custom Content Validation

- Validate the content of your JWT against ready-made, Pydantic-compliant models or extend them to your liking, beyond the standard registered claims.
- Serialize timestamps as either integers or floats.

### 🩵 Modern Codebase

- SuperJWT is written for Python 3.10+ with full type hints support in your IDE. Every function, method, and Pydantic model has autocompletion.
- Clean, modular, and lightweight codebase: thanks to Pydantic and the optional `cryptography` library, the whole library consists of less than 3,000 lines of code and is easily readable.

### 🤖 Heavily Tested

- SuperJWT maintains comprehensive unit tests and integration tests across all the intertwined features of the library: key generation and derivation, JWS signature and verification, and JWT content validation.

---

<p align="center">
Start building now: go to <a href="./user-guide/">User Guide</a>!
</p>
