package io.github.labui09.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * API 限流过滤器 —— 基于滑动窗口算法，每个 IP + 路径模式的请求独立计数。
 * <p>
 * 与 {@link SecurityFiltersProperties.RateLimit} 自动绑定，支持以下配置：
 * <ul>
 *   <li>{@code security.rate-limit.paths} — 需要限流的路径模式列表（如 /api/login, /api/sms/*）</li>
 *   <li>{@code security.rate-limit.capacity} — 每个 IP 在时间窗口内的最大请求数</li>
 *   <li>{@code security.rate-limit.window-seconds} — 时间窗口大小</li>
 * </ul>
 */
@Order(2)
public class RateLimitFilter implements Filter {

    private final SecurityFiltersProperties.RateLimit config;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** key = "pathPattern:clientIp", value = 计数条目 */
    private final ConcurrentHashMap<String, RateLimitEntry> rateLimitMap = new ConcurrentHashMap<>();

    public RateLimitFilter(SecurityFiltersProperties properties) {
        this.config = properties.getRateLimit();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!config.isEnabled() || config.getPaths().isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String path = req.getRequestURI();
        String clientIp = getClientIp(req);

        // 检查请求路径是否命中限流模式
        String matchedPattern = matchPattern(path, config.getPaths());
        if (matchedPattern == null) {
            chain.doFilter(request, response);
            return;
        }

        String key = matchedPattern + ":" + clientIp;
        long windowMs = config.getWindowSeconds() * 1000L;

        if (isRateLimited(key, config.getCapacity(), windowMs)) {
            res.setStatus(config.getHttpStatus());
            res.setContentType("application/json;charset=utf-8");
            res.getWriter().write(objectMapper.writeValueAsString(
                    Map.of("code", config.getHttpStatus(), "msg", config.getMessage())));
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * 判断是否触发限流。使用 {@link ConcurrentHashMap#compute} 保证原子性。
     */
    private boolean isRateLimited(String key, int maxRequests, long windowMs) {
        long now = System.currentTimeMillis();
        RateLimitEntry entry = rateLimitMap.compute(key, (k, v) -> {
            if (v == null || now - v.startTime > windowMs) {
                return new RateLimitEntry(now, 1);
            }
            v.count++;
            return v;
        });
        return entry.count > maxRequests;
    }

    /**
     * 简单路径模式匹配：支持 {@code *} 通配符。
     * 例如模式 "/api/sms/*" 匹配 "/api/sms/send"。
     */
    private String matchPattern(String path, List<String> patterns) {
        for (String pattern : patterns) {
            if (pattern.contains("*")) {
                String regex = pattern.replace(".", "\\.").replace("*", ".*");
                if (path.matches(regex)) {
                    return pattern;
                }
            } else if (path.equals(pattern)) {
                return pattern;
            }
        }
        return null;
    }

    /** 获取客户端真实 IP（优先从 X-Forwarded-For 取） */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        } else {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }

    /** 内部计数条目 */
    private static class RateLimitEntry {
        final long startTime;
        int count;

        RateLimitEntry(long startTime, int count) {
            this.startTime = startTime;
            this.count = count;
        }
    }
}
