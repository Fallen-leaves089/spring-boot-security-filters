package io.github.fallenleaves089.security.filters;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.core.annotation.Order;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/**
 * Session-bound CSRF protection for configurable path prefixes.
 */
@Order(3)
public class CsrfTokenFilter implements Filter {

    private static final String CSRF_TOKEN_ATTR = "CSRF_TOKEN";
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";
    private static final String CSRF_PARAM = "_csrf";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final List<String> protectedPaths;

    public CsrfTokenFilter(List<String> protectedPaths) {
        this.protectedPaths = protectedPaths == null ? List.of() : List.copyOf(protectedPaths);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        String path = req.getRequestURI();
        if (!isProtected(path)) {
            chain.doFilter(request, response);
            return;
        }

        String method = req.getMethod().toUpperCase();
        if ("GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method)) {
            HttpSession session = req.getSession(true);
            String token = (String) session.getAttribute(CSRF_TOKEN_ATTR);
            if (token == null) {
                token = generateToken();
                session.setAttribute(CSRF_TOKEN_ATTR, token);
            }
            req.setAttribute(CSRF_TOKEN_ATTR, token);
            resp.setHeader(CSRF_HEADER, token);
            // The token is per-session data; do not let shared caches store it.
            resp.setHeader("Cache-Control", "no-store");
            chain.doFilter(request, response);
            return;
        }

        HttpSession session = req.getSession(false);
        if (session == null) {
            resp.sendError(403, "CSRF session missing");
            return;
        }

        String sessionToken = (String) session.getAttribute(CSRF_TOKEN_ATTR);
        if (sessionToken == null) {
            resp.sendError(403, "CSRF token missing from session");
            return;
        }

        String requestToken = req.getHeader(CSRF_HEADER);
        if (requestToken == null || requestToken.isBlank()) {
            requestToken = req.getParameter(CSRF_PARAM);
        }
        if (requestToken == null || !constantTimeEquals(sessionToken, requestToken)) {
            resp.sendError(403, "Invalid CSRF token");
            return;
        }

        req.setAttribute(CSRF_TOKEN_ATTR, sessionToken);
        chain.doFilter(request, response);
    }

    private boolean isProtected(String path) {
        if (path == null) {
            return false;
        }
        for (String prefix : protectedPaths) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static String generateToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}
