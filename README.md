# spring-boot-security-filters

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/fallen-leaves089/spring-boot-security-filters/ci.yml?branch=main&logo=github)](https://github.com/fallen-leaves089/spring-boot-security-filters/actions)

Spring Boot security filters: **rate limiting, security headers, trusted-proxy IP resolution, CSRF protection, and magic-byte validation**, zero code integration.

MIT License. Copyright (c) 2024 fallen-leaves089.

[中文说明](README.zh-CN.md)

> Need JWT authentication too? Use
> [`spring-boot-security-starter`](https://github.com/fallen-leaves089/spring-boot-security-starter).

## 30-second overview

- **Problem solved:** adds reusable security filters to a Spring MVC app without writing each `Filter` yourself.
- **What you get:** security headers, fixed-window rate limiting, trusted-proxy real IP resolution, session CSRF tokens, and magic-byte validation.
- **Use it when:** you want a small server-side baseline for a Spring Boot 3.2.x / Java 17 servlet app.
- **Not for:** replacing a WAF/API gateway. Rate limiting is per JVM, CSRF is session-based, and `MagicBytesValidator` is a utility you call from upload handling.

## Shortest demo

```yaml
security:
  rate-limit:
    paths:
      - /api/login
    capacity: 60
    window-seconds: 60
```

Add the dependency, start the app, and inspect a response:

```bash
curl -I http://localhost:8080/api/login
```

The response includes the security headers; the 61st request from the same IP returns `429`. See [Quick start](#quick-start) for the full configuration.

---

## Features

| Filter | Purpose | Order |
|--------|---------|-------|
| `SecurityHeadersFilter` | Automatically injects 8 HTTP security response headers (CSP / HSTS / X-Frame-Options, etc.) to protect against XSS, clickjacking, and MIME sniffing. | 1 |
| `RateLimitFilter` | Fixed-window API rate limiting with independent counters by IP + path pattern. Returns 429 when the limit is exceeded. | 2 |
| `RealIpFilter` | Resolves the real client IP only when the direct remote address is a trusted private proxy, preventing forged `X-Forwarded-For`. | 1 |
| `CsrfTokenFilter` | Session-bound CSRF tokens for configurable path prefixes, validating `X-CSRF-TOKEN` or `_csrf`. | 3 |
| `MagicBytesValidator` | Pure utility that validates image/video magic bytes against the claimed extension. | utility |

## Scope and limits

- `RateLimitFilter` stores counters in JVM memory and evicts expired windows lazily. For multiple instances, use a shared store or a gateway.
- `RateLimitFilter` resolves the client IP through the same trusted-proxy rules as `RealIpFilter`; a direct client cannot bypass the limit by setting `X-Forwarded-For`.
- `CsrfTokenFilter` is session-bound. It is not a replacement for token-based CSRF defenses in stateless APIs.
- `RealIpFilter` only trusts loopback/private proxy addresses. Make sure the network boundary prevents clients from reaching the app directly with a forged `X-Forwarded-For`.
- `MagicBytesValidator` is a utility; call it when handling uploads. It does not scan files automatically, and `matches` consumes up to 12 bytes from the supplied stream without resetting it.

---

## CSRF token flow

`CsrfTokenFilter` protects the configured path prefixes (default: `/admin`). On a safe request (`GET`, `HEAD`, `OPTIONS`) it creates a session if needed, reuses the token for that session, exposes it as the `X-CSRF-TOKEN` response header and the `CSRF_TOKEN` request attribute, and marks the response `Cache-Control: no-store`. Unsafe requests must send the same value in `X-CSRF-TOKEN` or `_csrf`; a protected request without a session is rejected with `403`. The token is not rotated on every request.

---

## Dependency coordinates

This project is published through [JitPack](https://jitpack.io). Add the JitPack repository first.

### Maven

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.fallen-leaves089</groupId>
    <artifactId>spring-boot-security-filters</artifactId>
    <version>1.1.0</version>
</dependency>
```

### Gradle

```gradle
dependencyResolutionManagement {
    repositories {
        maven("https://jitpack.io")
    }
}

dependencies {
    implementation("com.github.fallen-leaves089:spring-boot-security-filters:1.1.0")
}
```

> Requires Spring Boot 3.2.x and Java 17.

---

## Quick start

The filters take effect after the dependency is added. The default configuration works out of the box:

```yaml
# application.yml
security:
  rate-limit:
    enabled: true
    paths:
      - /api/login
      - /api/sms/*
    capacity: 60
    window-seconds: 60
  security-headers:
    enabled: true
    csp-policy: "default-src 'self'"
  real-ip:
    enabled: true
  csrf:
    enabled: true
    protected-paths:
      - /admin
```

No Java code is required. Start the application and the security headers will be present.

Use curl to verify the behavior:

```bash
# Inspect the injected security headers
curl -sI http://localhost:8080/api/hello | grep -iE 'content-security-policy|x-frame-options|x-content-type-options'

# Trigger rate limiting (default 60 requests/minute/IP; the next request returns 429)
for i in $(seq 1 61); do curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/login; done | sort | uniq -c
```

---

## Full configuration reference

```yaml
security:
  # ── API rate limiting ──
  rate-limit:
    # Whether rate limiting is enabled. Default: true.
    enabled: true

    # Path patterns to rate limit (supports * wildcards).
    paths:
      - /api/login
      - /api/sms/*
      - /api/captcha

    # Maximum requests per IP within the time window. Default: 60.
    capacity: 60

    # Time window size in seconds. Default: 60.
    window-seconds: 60

    # HTTP status returned when the limit is triggered. Default: 429.
    http-status: 429

    # Message returned when the limit is triggered.
    message: "请求过于频繁，请稍后再试"

  # ── HTTP security headers ──
  security-headers:
    # Whether security headers are enabled. Default: true.
    enabled: true

    # Content-Security-Policy value.
    csp-policy: "default-src 'self'; script-src 'self' cdn.example.com"

    # Whether HSTS is enabled. Only applies to HTTPS requests.
    hsts-enabled: true

    # HSTS max-age in seconds. Default: 31536000 (1 year).
    hsts-max-age: 31536000

    # Whether to prevent iframe embedding (clickjacking protection).
    prevent-click-jacking: true

  # ---------- Trusted proxy real IP ----------
  real-ip:
    # Whether trusted-proxy IP resolution is enabled. Default: true.
    enabled: true

  # ---------- Session CSRF protection ----------
  csrf:
    # Whether CSRF protection is enabled. Default: true.
    enabled: true

    # Path prefixes that require CSRF tokens. Default: /admin.
    protected-paths:
      - /admin
```

---

## Injected security headers

After adding the dependency, every HTTP response automatically includes:

| Header | Default value |
|--------|---------------|
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Content-Security-Policy` | configurable |
| `X-Download-Options` | `noopen` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(self)` |
| `X-Frame-Options` | `DENY` (configurable) |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (HTTPS only) |

---

## Disable an individual filter

```yaml
# Disable only rate limiting
security.rate-limit.enabled=false

# Disable only security headers
security.security-headers.enabled=false

# Disable only trusted-proxy IP resolution
security.real-ip.enabled=false

# Disable only session CSRF protection
security.csrf.enabled=false
```

---

## Custom rate-limiting logic

If you only need security headers and not rate limiting (or vice versa), set the corresponding `enabled: false`. Filters are assembled with `@ConditionalOnProperty`, so a disabled filter bean is not created.

---

## Architecture

```
spring-boot-security-filters
├── SecurityFiltersProperties      -- @ConfigurationProperties; manages all configuration
├── SecurityHeadersFilter          -- Filter: injects security headers
├── RateLimitFilter                -- Filter: fixed-window API rate limiting
├── RealIpFilter                   -- Filter: trusted-proxy real IP resolution
├── CsrfTokenFilter                -- Filter: session-bound CSRF validation
├── MagicBytesValidator            -- Utility: image/video magic-byte validation
└── SecurityFiltersAutoConfiguration -- @AutoConfiguration; auto-configures the filters
```

Loaded automatically through `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`; no `@ComponentScan` required.

---

## Releasing

JitPack builds a release automatically from a Git tag. Use the `v` prefix for the tag; the dependency coordinate above remains `1.1.0`.

```bash
git tag v1.1.0
git push origin v1.1.0
```

Then use:

```text
https://jitpack.io/#fallen-leaves089/spring-boot-security-filters/1.1.0
```

Publishing to Maven Central requires repository credentials, signed artifacts, and source/javadoc jars.

---

## GitHub About

`Spring Boot security filters | Rate limiting | Security headers | Trusted-proxy IP | CSRF | Magic-byte validation`
