package io.github.fallenleaves089.security.filters;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * 安全过滤器自动配置类。
 * <p>
 * 通过 Spring Boot 的 {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * 机制自动加载，无需用户手动添加 {@code @ComponentScan}。
 * <p>
 * 两个过滤器均可通过属性独立开关：
 * <ul>
 *   <li>{@code security.rate-limit.enabled=false} 关闭限流</li>
 *   <li>{@code security.security-headers.enabled=false} 关闭安全响应头</li>
 * </ul>
 */
@AutoConfiguration
@EnableConfigurationProperties(SecurityFiltersProperties.class)
public class SecurityFiltersAutoConfiguration {

    /**
     * 注册 {@link RateLimitFilter}。
     * 仅当 {@code security.rate-limit.enabled} 为 true（默认）时生效。
     * 由于 Filter 不由 Spring MVC 管理，此处手动 new。
     */
    @Bean
    @ConditionalOnProperty(prefix = "security.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = true)
    public RateLimitFilter rateLimitFilter(SecurityFiltersProperties properties) {
        return new RateLimitFilter(properties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "security.real-ip", name = "enabled", havingValue = "true", matchIfMissing = true)
    public RealIpFilter realIpFilter() {
        return new RealIpFilter();
    }

    @Bean
    @ConditionalOnProperty(prefix = "security.csrf", name = "enabled", havingValue = "true", matchIfMissing = true)
    public CsrfTokenFilter csrfTokenFilter(SecurityFiltersProperties properties) {
        return new CsrfTokenFilter(properties.getCsrf().getProtectedPaths());
    }

    /**
     * 注册 {@link SecurityHeadersFilter}。
     * 仅当 {@code security.security-headers.enabled} 为 true（默认）时生效。
     */
    @Bean
    @ConditionalOnProperty(prefix = "security.security-headers", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SecurityHeadersFilter securityHeadersFilter(SecurityFiltersProperties properties) {
        return new SecurityHeadersFilter(properties);
    }
}
