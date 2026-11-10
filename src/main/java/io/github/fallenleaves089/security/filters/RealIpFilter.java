package io.github.fallenleaves089.security.filters;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.annotation.Order;

import java.io.IOException;
import java.util.Objects;

/**
 * Resolves the real client IP for trusted proxy deployments.
 */
@Order(1)
public class RealIpFilter implements Filter {

    public static final String ATTR_REAL_IP = "realClientIp";

    private final ClientIpResolver clientIpResolver;

    /**
     * Creates a filter using the secure default policy (loopback-only proxies).
     * Prefer the auto-configured constructor when using the starter.
     */
    public RealIpFilter() {
        this(ClientIpResolver.defaults());
    }

    public RealIpFilter(ClientIpResolver clientIpResolver) {
        this.clientIpResolver = Objects.requireNonNull(clientIpResolver, "clientIpResolver must not be null");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        req.setAttribute(ATTR_REAL_IP, clientIpResolver.resolve(req));
        chain.doFilter(request, response);
    }

    /**
     * Compatibility entry point using the secure default policy. The filter's
     * configured resolver is authoritative when it runs in the chain.
     */
    public static String resolve(HttpServletRequest request) {
        return ClientIpResolver.defaults().resolve(request);
    }

    static String normalize(String ip) {
        return ClientIpResolver.normalize(ip);
    }
}
