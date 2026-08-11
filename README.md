# spring-boot-security-filters

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-Fallen-leaves089%2Fspring--boot--security--filters-lightgrey?logo=github)](https://github.com/Fallen-leaves089/spring-boot-security-filters)
[![Build](https://img.shields.io/github/actions/workflow/status/Fallen-leaves089/spring-boot-security-filters/ci.yml?branch=main&logo=github)](https://github.com/Fallen-leaves089/spring-boot-security-filters/actions)

Spring Boot 安全过滤器：限流 + 安全头，零代码接入。

MIT License. Copyright (c) 2024 Fallen-leaves089.

---

## 功能

| 过滤器 | 功能 | Order |
|--------|------|-------|
| `SecurityHeadersFilter` | 自动注入 8 类 HTTP 安全响应头（CSP / HSTS / X-Frame-Options 等），防御 XSS、点击劫持、MIME 嗅探 | 1 |
| `RateLimitFilter` | 基于滑动窗口的 API 限流，按 IP + 路径模式独立计数，触发后返回 429 | 2 |

---

## 依赖坐标

### Maven

```xml
<dependency>
    <groupId>io.github.Fallen-leaves089</groupId>
    <artifactId>spring-boot-security-filters</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

```gradle
implementation 'io.github.Fallen-leaves089:spring-boot-security-filters:1.0.0'
```

> 需要 Spring Boot 3.2.x + Java 17。

---

## 快速开始

引入依赖后即可生效，默认配置开箱即用：

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
```

无需任何 Java 代码，启动项目即可看到安全响应头。

启动项目后，可以用 curl 验证效果：

```bash
# 查看注入的安全响应头
curl -sI http://localhost:8080/api/hello | grep -iE 'content-security-policy|x-frame-options|x-content-type-options'

# 连续请求触发限流（默认 60 次/分钟/IP，超过返回 429）
for i in $(seq 1 61); do curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/login; done | sort | uniq -c
```

---

## 完整配置参考

```yaml
security:
  # ── API 限流 ──
  rate-limit:
    # 是否启用，默认 true
    enabled: true

    # 需要限流的路径模式（支持 * 通配符）
    paths:
      - /api/login
      - /api/sms/*
      - /api/captcha

    # 每个 IP 在时间窗口内的最大请求数，默认 60
    capacity: 60

    # 时间窗口大小（秒），默认 60
    window-seconds: 60

    # 触发限流的 HTTP 状态码，默认 429
    http-status: 429

    # 触发限流时的提示消息
    message: "请求过于频繁，请稍后再试"

  # ── HTTP 安全响应头 ──
  security-headers:
    # 是否启用，默认 true
    enabled: true

    # Content-Security-Policy 策略值
    csp-policy: "default-src 'self'; script-src 'self' cdn.example.com"

    # 是否启用 HSTS（仅在 HTTPS 请求时生效）
    hsts-enabled: true

    # HSTS max-age（秒），默认 31536000（1 年）
    hsts-max-age: 31536000

    # 是否禁止 iframe 嵌入（防点击劫持）
    prevent-click-jacking: true
```

---

## 注入的安全响应头

引入依赖后，每个 HTTP 响应将自动包含：

| 响应头 | 默认值 |
|--------|--------|
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Content-Security-Policy` | 可配置 |
| `X-Download-Options` | `noopen` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(self)` |
| `X-Frame-Options` | `DENY`（可配置） |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains`（仅 HTTPS） |

---

## 单独关闭某个过滤器

```yaml
# 只关限流
security.rate-limit.enabled=false

# 只关安全响应头
security.security-headers.enabled=false
```

---

## 自定义限流逻辑

如果你只需要安全响应头而不需要限流（或反之），只需设置对应的 `enabled: false` 即可。Filter 通过 `@ConditionalOnProperty` 条件装配，关闭后对应的 Filter Bean 不会被创建。

---

## 架构说明

```
spring-boot-security-filters
├── SecurityFiltersProperties      -- @ConfigurationProperties，统一管理所有配置
├── SecurityHeadersFilter          -- Filter: 注入安全响应头
├── RateLimitFilter                -- Filter: 滑动窗口 API 限流
└── SecurityFiltersAutoConfiguration -- @AutoConfiguration，自动装配
```

通过 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` 机制自动加载，无需 `@ComponentScan`。

---

## GitHub About 建议

`Spring Boot 安全过滤器：限流 + 安全头，零代码接入`
