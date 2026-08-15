package io.github.fallenleaves089.security.filters;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.annotation.Order;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves the real client IP for trusted proxy deployments.
 */
@Order(1)
public class RealIpFilter implements Filter {

    public static final String ATTR_REAL_IP = "realClientIp";

    private static final Pattern IPV4_WITH_PORT = Pattern.compile("^(\\d{1,3}(\\.\\d{1,3}){3}):\\d+$");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        req.setAttribute(ATTR_REAL_IP, resolve(req));
        chain.doFilter(request, response);
    }

    public static String resolve(HttpServletRequest request) {
        Object attr = request.getAttribute(ATTR_REAL_IP);
        if (attr != null) {
            return attr.toString();
        }
        String remote = normalize(request.getRemoteAddr());
        if (isTrustedProxy(remote)) {
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                String leftmost = xff.split(",")[0].trim();
                if (!leftmost.isEmpty()) {
                    return normalize(leftmost);
                }
            }
        }
        return remote;
    }

    static String normalize(String ip) {
        if (ip == null) {
            return "";
        }
        String s = ip.trim();
        if (s.startsWith("[") && s.contains("]")) {
            return s.substring(1, s.indexOf(']'));
        }
        Matcher m = IPV4_WITH_PORT.matcher(s);
        if (m.matches()) {
            return m.group(1);
        }
        return s;
    }

    static boolean isTrustedProxy(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        if ("::1".equals(ip) || "localhost".equalsIgnoreCase(ip)) {
            return true;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        long value = 0;
        try {
            for (String part : parts) {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
                value = (value << 8) | octet;
            }
        } catch (NumberFormatException e) {
            return false;
        }
        return (value & 0xFF000000L) == 0x7F000000L
                || (value & 0xFF000000L) == 0x0A000000L
                || (value & 0xFFF00000L) == 0xAC100000L
                || (value & 0xFFFF0000L) == 0xC0A80000L;
    }
}
