package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class SecurityHeadersFilterTest {

    private final SecurityFiltersProperties properties = new SecurityFiltersProperties();

    @Test
    void shouldInjectSecurityHeaders() throws Exception {
        SecurityHeadersFilter filter = new SecurityHeadersFilter(properties);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
        assertEquals("1; mode=block", response.getHeader("X-XSS-Protection"));
        assertEquals("default-src 'self'; frame-ancestors 'none'", response.getHeader("Content-Security-Policy"));
        assertEquals("DENY", response.getHeader("X-Frame-Options"));
        assertNull(response.getHeader("Strict-Transport-Security"));
    }

    @Test
    void shouldInjectHstsOnHttpsRequest() throws Exception {
        SecurityHeadersFilter filter = new SecurityHeadersFilter(properties);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertNotNull(response.getHeader("Strict-Transport-Security"));
    }

    @Test
    void shouldSkipWhenDisabled() throws Exception {
        properties.getSecurityHeaders().setEnabled(false);
        SecurityHeadersFilter filter = new SecurityHeadersFilter(properties);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());

        assertNull(response.getHeader("X-Content-Type-Options"));
    }
}