# spring-boot-security-filters

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/fallen-leaves089/spring-boot-security-filters/ci.yml?branch=main&logo=github)](https://github.com/fallen-leaves089/spring-boot-security-filters/actions)

Spring Boot 安全过滤器：限流 + 安全头，零代码接入。

MIT License. Copyright (c) 2024 fallen-leaves089.

> 需要 JWT 鉴权一起用？使用
> [`spring-boot-security-starter`](https://github.com/fallen-leaves089/spring-boot-security-starter)。

## 30 秒看懂

- **解决什么**：给 Spring MVC 项目加一层可复用的安全过滤，不用自己逐个实现 `Filter`。
- **你能得到**：安全响应头、固定窗口限流、可信代理真实 IP、Session CSRF、文件魔数校验。
- **适合**：Spring Boot 3.2.x / Java 17 的 Servlet 应用，需要快速建立基础防护。
- **不适合**：替代 WAF/API 网关。限流是单 JVM 内存计数，CSRF 基于 Session，`MagicBytesValidator` 需要在上传处理中手动调用。

## 最短演示

```yaml
security:
  rate-limit:
    paths:
      - /api/login
    capacity: 60
    window-seconds: 60
```

加依赖、启动应用后检查响应：

```bash
curl -I http://localhost:8080/api/login
```

响应会带上安全响应头；同一 IP 的第 61 次请求返回 `429`。完整配置见[快速开始](#快速开始)。

---

## 功能

| 过滤器 | 功能 | Order |
|--------|------|-------|
| `SecurityHeadersFilter` | 自动注入 8 类 HTTP 安全响应头（CSP / HSTS / X-Frame-Options 等），防御 XSS、点击劫持、MIME 嗅探 | 1 |
| `RateLimitFilter` | 基于固定窗口的 API 限流，按 IP + 路径模式独立计数，触发后返回 429 | 2 |
| `RealIpFilter` | 仅当直连地址是可信内网代理时解析真实客户端 IP，避免伪造 `X-Forwarded-For` | 1 |
| `CsrfTokenFilter` | 为可配置路径前缀提供 Session 级 CSRF Token 校验，支持 `X-CSRF-TOKEN` 或 `_csrf` | 3 |
| `MagicBytesValidator` | 校验图片/视频文件魔数与声称扩展名是否一致 | utility |

## 边界与限制

- `RateLimitFilter` 计数存在 JVM 内存中，并会惰性清理过期窗口；多实例部署请使用共享存储或网关限流。
- `RateLimitFilter` 与 `RealIpFilter` 使用相同的可信代理规则解析客户端 IP；直连客户端无法通过伪造 `X-Forwarded-For` 绕过限流。
- `CsrfTokenFilter` 基于 Session，不适用于完全无状态的 Token API。
- `RealIpFilter` 只信任回环/私有代理地址；必须确保网络边界不允许客户端直接伪造 `X-Forwarded-For` 访问应用。
- `MagicBytesValidator` 是工具类，需要在文件上传处理中显式调用，不会自动扫描上传文件；`matches` 会从传入的流读取最多 12 字节且不会自动重置流位置。

---

## CSRF Token 流程

`CsrfTokenFilter` 保护配置的路径前缀（默认 `/admin`）。安全请求（`GET`、`HEAD`、`OPTIONS`）会按需创建 Session，同一 Session 复用同一个 Token，并通过 `X-CSRF-TOKEN` 响应头和 `CSRF_TOKEN` request attribute 暴露；响应会带 `Cache-Control: no-store`。非安全请求必须在 `X-CSRF-TOKEN` 或 `_csrf` 中带上同一个值；受保护请求如果没有 Session 会直接返回 `403`。Token 不会在每次请求时轮换。

---

## 依赖坐标

本项目通过 [JitPack](https://jitpack.io) 发布，使用时先添加 JitPack 仓库。

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
  real-ip:
    enabled: true
  csrf:
    enabled: true
    protected-paths:
      - /admin
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

# 只关可信代理真实 IP 解析
security.real-ip.enabled=false

# 只关 Session CSRF 防护
security.csrf.enabled=false
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
├── RateLimitFilter                -- Filter: 固定窗口 API 限流
├── RealIpFilter                   -- Filter: 可信代理真实 IP 解析
├── CsrfTokenFilter                -- Filter: Session 级 CSRF 校验
├── MagicBytesValidator            -- 工具类: 图片/视频魔数校验
└── SecurityFiltersAutoConfiguration -- @AutoConfiguration，自动装配
```

通过 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` 机制自动加载，无需 `@ComponentScan`。

---

## 发布

JitPack 会根据 Git tag 自动构建发布。Git tag 使用 `v1.1.0`，上面的依赖坐标仍使用 `1.1.0`。

```bash
git tag v1.1.0
git push origin v1.1.0
```

随后可使用：

```text
https://jitpack.io/#fallen-leaves089/spring-boot-security-filters/1.1.0
```

发布到 Maven Central 需要仓库凭据、签名制品以及 source/javadoc jar。

---

## GitHub About 建议

`Spring Boot 安全过滤器 | 限流 | 安全响应头 | 可信代理 IP | CSRF | 文件魔数校验`
