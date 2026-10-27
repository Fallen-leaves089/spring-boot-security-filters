# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-10-27

### Fixed

- Rate-limit and CSRF path matching now strips `server.servlet.context-path` before matching.
- Rate-limit patterns compile safely, treating only `*` as a wildcard so `+`, `(` and other regex metacharacters are literal.
- CSRF prefixes match on path-segment boundaries (`/admin` no longer protects `/administrator`).
- CSRF token comparison now hashes both values before the constant-time comparison.

### Added

- Rate-limit responses include `Retry-After`.

### Changed

- Rate-limit `capacity` and `window-seconds` must be at least 1.

## [1.1.0] - 2026-10-27

### Added

- `SECURITY.md` security policy
- `CODE_OF_CONDUCT.md` contributor covenant
- Maven wrapper for reproducible builds
- `RealIpFilter`, `CsrfTokenFilter`, and `MagicBytesValidator`
- JitPack publishing instructions and dependency coordinates

### Security

- Rate limiting now resolves the client IP through the same trusted-proxy rules as `RealIpFilter`, preventing direct clients from bypassing limits with a forged `X-Forwarded-For`.
- CSRF tokens are compared in constant time.

### Fixed

- `RateLimitFilter` evicts expired counters instead of growing the in-memory map for the lifetime of the process.
- `CsrfTokenFilter` reuses one token per session instead of rotating it on every safe request. Safe responses expose the token through `X-CSRF-TOKEN` and the `CSRF_TOKEN` request attribute; protected requests without a session are rejected with `403`.

### Changed

- README adds a 30-second overview, shortest demo, scope limits, and a link to the aggregator starter
- Rate limiting is documented as fixed-window rather than sliding-window.
- `MagicBytesValidator` documents that `matches` consumes up to 12 bytes from the supplied stream without resetting it.

## [1.0.0] - 2026-08-12

### Added

- Security headers filter: CSP / HSTS / X-Frame-Options / X-Content-Type-Options (8 headers)
- IP-based rate limiting: `RateLimitFilter` with 429 responses
- Configurable via `security.rate-limit.*` / `security.security-headers.*`
- Unit tests for `SecurityHeadersFilter` and `RateLimitFilter`
