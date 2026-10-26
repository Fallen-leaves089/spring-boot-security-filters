# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SECURITY.md` security policy
- `CODE_OF_CONDUCT.md` contributor covenant
- Maven wrapper for reproducible builds
- `RealIpFilter`, `CsrfTokenFilter`, and `MagicBytesValidator`
- JitPack publishing instructions and dependency coordinates

### Changed

- README adds a 30-second overview, shortest demo, scope limits, and a link to the aggregator starter
- Release tags are documented as `v1.0.0`; the JitPack coordinate remains `1.0.0`

## [1.0.0] - 2026-08-12

### Added

- Security headers filter: CSP / HSTS / X-Frame-Options / X-Content-Type-Options (8 headers)
- IP-based sliding-window rate limiting: `RateLimitFilter` with 429 responses
- Configurable via `security.rate-limit.*` / `security.security-headers.*`
- Unit tests for `SecurityHeadersFilter` and `RateLimitFilter`
