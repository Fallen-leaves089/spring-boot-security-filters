# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SECURITY.md` security policy
- `CODE_OF_CONDUCT.md` contributor covenant
- Maven wrapper for reproducible builds

## [1.0.0] - 2026-08-12

### Added

- Security headers filter: CSP / HSTS / X-Frame-Options / X-Content-Type-Options (8 headers)
- IP-based sliding-window rate limiting: `RateLimitFilter` with 429 responses
- Configurable via `security.rate-limit.*` / `security.security-headers.*`
- Unit tests for `SecurityHeadersFilter` and `RateLimitFilter`
