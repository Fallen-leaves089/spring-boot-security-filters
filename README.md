# spring-boot-security-filters

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-fallen-leaves089%2Fspring--boot--security--filters-lightgrey?logo=github)](https://github.com/fallen-leaves089/spring-boot-security-filters)
[![Build](https://img.shields.io/github/actions/workflow/status/fallen-leaves089/spring-boot-security-filters/ci.yml?branch=main&logo=github)](https://github.com/fallen-leaves089/spring-boot-security-filters/actions)

Spring Boot security filters: **rate limiting, security headers, trusted-proxy IP resolution, CSRF protection, and magic-byte validation**, zero code integration.

MIT License. Copyright (c) 2024 fallen-leaves089.

[中文说明](README.zh-CN.md)

---

## Features

| Filter | Purpose | Order |
|--------|---------|-------|
| `SecurityHeadersFilter` | Automatically injects 8 HTTP security response headers (CSP / HSTS / X-Frame-Options, etc.) to protect against XSS, clickjacking, and MIME sniffing. | 1 |
| `RateLimitFilter` | Sliding-window API rate limiting with independent counters by IP + path pattern. Returns 429 when the limit is exceeded. | 2 |
| `RealIpFilter` | Resolves the real client IP only when the direct remote address is a trusted private proxy, preventing forged `X-Forwarded-For`. | 1 |
| `CsrfTokenFilter` | Session-bound CSRF tokens for configurable path prefixes, validating `X-CSRF-TOKEN` or `_csrf`. | 3 |
| `MagicBytesValidator` | Pure utility that validates image/video magic bytes against the claimed extension. | utility |

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
    <version>1.0.0</version>
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
    implementation("com.github.fallen-leaves089:spring-boot-security-filters:1.0.0")
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
├── RateLimitFilter                -- Filter: sliding-window API rate limiting
├── RealIpFilter                   -- Filter: trusted-proxy real IP resolution
├── CsrfTokenFilter                -- Filter: session-bound CSRF validation
├── MagicBytesValidator            -- Utility: image/video magic-byte validation
└── SecurityFiltersAutoConfiguration -- @AutoConfiguration; auto-configures the filters
```

Loaded automatically through `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`; no `@ComponentScan` required.

---

## Releasing

JitPack builds a release automatically from a Git tag.

```bash
git tag 1.0.0
git push origin 1.0.0
```

Then use:

```text
https://jitpack.io/#fallen-leaves089/spring-boot-security-filters/1.0.0
```

Maven Central publishing requires OSSRH credentials, signed artifacts, and source/javadoc jars.

---

## GitHub About

`Spring Boot security filters: rate limiting + security headers, zero code integration`
