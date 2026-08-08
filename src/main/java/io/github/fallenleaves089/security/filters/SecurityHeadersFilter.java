package io.github.fallenleaves089.security.filters;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;

import java.io.IOException;

/**
 * HTTP 安全响应头过滤器 —— 防止 XSS、点击劫持、MIME 嗅探等常见 Web 攻击。
 * <p>
 * 与 {@link SecurityFiltersProperties.SecurityHeaders} 自动绑定，支持以下配置：
 * <ul>
 *   <li>{@code security.security-headers.csp-policy} — Content-Security-Policy 策略</li>
 *   <li>{@code security.security-headers.hsts-enabled} — 是否启用 HSTS</li>
 *   <li>{@code security.security-headers.prevent-click-jacking} — 是否禁止 iframe 嵌入</li>
 * </ul>
 */
@Order(1)
public class SecurityHeadersFilter implements Filter {

    private final SecurityFiltersProperties.SecurityHeaders config;

    public SecurityHeadersFilter(SecurityFiltersProperties properties) {
        this.config = properties.getSecurityHeaders();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!config.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse res = (HttpServletResponse) response;
        HttpServletRequest req = (HttpServletRequest) request;

        // X-Content-Type-Options — 防止 MIME 嗅探
        res.setHeader("X-Content-Type-Options", "nosniff");

        // X-XSS-Protection — 启用浏览器 XSS 过滤器
        res.setHeader("X-XSS-Protection", "1; mode=block");

        // Content-Security-Policy — 限制资源加载来源
        res.setHeader("Content-Security-Policy", config.getCspPolicy());

        // X-Download-Options — 禁止 IE 自动执行下载文件
        res.setHeader("X-Download-Options", "noopen");

        // Referrer-Policy — 控制 Referer 头
        res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // Permissions-Policy — 限制浏览器功能权限
        res.setHeader("Permissions-Policy",
                "camera=(), microphone=(), geolocation=(self)");

        // X-Frame-Options — 防止点击劫持
        if (config.isPreventClickJacking()) {
            res.setHeader("X-Frame-Options", "DENY");
            // 同时在 CSP 中追加 frame-ancestors（更现代的方案）
            String existingCsp = res.getHeader("Content-Security-Policy");
            if (existingCsp != null && !existingCsp.contains("frame-ancestors")) {
                res.setHeader("Content-Security-Policy",
                        existingCsp + "; frame-ancestors 'none'");
            }
        }

        // Strict-Transport-Security — HSTS（仅在 HTTPS 时生效）
        if (config.isHstsEnabled() && req.isSecure()) {
            res.setHeader("Strict-Transport-Security",
                    "max-age=" + config.getHstsMaxAge() + "; includeSubDomains");
        }

        chain.doFilter(request, response);
    }
}
