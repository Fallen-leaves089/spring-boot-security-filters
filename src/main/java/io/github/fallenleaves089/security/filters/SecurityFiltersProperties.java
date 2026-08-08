package io.github.fallenleaves089.security.filters;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 安全过滤器配置属性。
 * 所有配置项均以前缀 {@code security} 开头，在 application.yml 中配置。
 */
@ConfigurationProperties(prefix = "security")
public class SecurityFiltersProperties {

    private final RateLimit rateLimit = new RateLimit();
    private final SecurityHeaders securityHeaders = new SecurityHeaders();

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public SecurityHeaders getSecurityHeaders() {
        return securityHeaders;
    }

    /**
     * API 限流配置。
     */
    public static class RateLimit {

        /** 是否启用限流，默认 true */
        private boolean enabled = true;

        /** 需要限流的路径模式列表（支持通配符 *），未匹配的路径不受限流影响 */
        private List<String> paths = new ArrayList<>();

        /** 每个 IP 在时间窗口内的最大请求数，默认 60 */
        private int capacity = 60;

        /** 时间窗口大小（秒），默认 60 */
        private int windowSeconds = 60;

        /** 触发限流时响应的 HTTP 状态码，默认 429 */
        private int httpStatus = 429;

        /** 触发限流时的提示消息 */
        private String message = "请求过于频繁，请稍后再试";

        // ── getters / setters ──

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getPaths() {
            return paths;
        }

        public void setPaths(List<String> paths) {
            this.paths = paths;
        }

        public int getCapacity() {
            return capacity;
        }

        public void setCapacity(int capacity) {
            this.capacity = capacity;
        }

        public int getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(int windowSeconds) {
            this.windowSeconds = windowSeconds;
        }

        public int getHttpStatus() {
            return httpStatus;
        }

        public void setHttpStatus(int httpStatus) {
            this.httpStatus = httpStatus;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }

    /**
     * HTTP 安全响应头配置。
     */
    public static class SecurityHeaders {

        /** 是否启用安全响应头，默认 true */
        private boolean enabled = true;

        /** Content-Security-Policy 策略值，默认 "default-src 'self'" */
        private String cspPolicy = "default-src 'self'";

        /** 是否启用 HSTS（仅在 HTTPS 时生效），默认 true */
        private boolean hstsEnabled = true;

        /** HSTS max-age 秒数，默认 31536000（1年） */
        private long hstsMaxAge = 31536000L;

        /** 是否在 CSP 中限制 iframe 嵌入（frame-ancestors 'none'），默认 true */
        private boolean preventClickJacking = true;

        // ── getters / setters ──

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getCspPolicy() {
            return cspPolicy;
        }

        public void setCspPolicy(String cspPolicy) {
            this.cspPolicy = cspPolicy;
        }

        public boolean isHstsEnabled() {
            return hstsEnabled;
        }

        public void setHstsEnabled(boolean hstsEnabled) {
            this.hstsEnabled = hstsEnabled;
        }

        public long getHstsMaxAge() {
            return hstsMaxAge;
        }

        public void setHstsMaxAge(long hstsMaxAge) {
            this.hstsMaxAge = hstsMaxAge;
        }

        public boolean isPreventClickJacking() {
            return preventClickJacking;
        }

        public void setPreventClickJacking(boolean preventClickJacking) {
            this.preventClickJacking = preventClickJacking;
        }
    }
}
