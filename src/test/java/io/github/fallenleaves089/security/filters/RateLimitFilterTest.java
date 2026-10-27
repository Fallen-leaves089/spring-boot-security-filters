package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RateLimitFilterTest {

    @Test
    void shouldReturn429WhenLimitExceeded() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/login"));
        properties.getRateLimit().setCapacity(2);
        RateLimitFilter filter = new RateLimitFilter(properties);

        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/login");
            request.setRemoteAddr("1.2.3.4");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new MockFilterChain());
            assertEquals(200, response.getStatus());
        }

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/login");
        request.setRemoteAddr("1.2.3.4");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals(429, response.getStatus());
    }

    @Test
    void shouldNotRateLimitDifferentIp() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/login"));
        properties.getRateLimit().setCapacity(1);
        RateLimitFilter filter = new RateLimitFilter(properties);

        for (String ip : List.of("1.2.3.4", "5.6.7.8", "9.9.9.9")) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/login");
            request.setRemoteAddr(ip);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new MockFilterChain());
            assertEquals(200, response.getStatus());
        }
    }

    @Test
    void shouldTreatRegexCharactersInPatternLiterally() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/a+b"));
        properties.getRateLimit().setCapacity(1);
        RateLimitFilter filter = new RateLimitFilter(properties);

        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/a+b");
            request.setRemoteAddr("1.2.3.4");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new MockFilterChain());
            assertEquals(i == 0 ? 200 : 429, response.getStatus());
        }
    }

    @Test
    void shouldMatchPathWithoutContextPrefix() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/login"));
        properties.getRateLimit().setCapacity(1);
        RateLimitFilter filter = new RateLimitFilter(properties);

        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/api/login");
            request.setContextPath("/app");
            request.setRemoteAddr("1.2.3.4");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new MockFilterChain());
            assertEquals(i == 0 ? 200 : 429, response.getStatus());
            if (i == 1) {
                assertEquals("60", response.getHeader("Retry-After"));
            }
        }
    }

    @Test
    void shouldNotRateLimitUnmatchedPath() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/login"));
        properties.getRateLimit().setCapacity(1);
        RateLimitFilter filter = new RateLimitFilter(properties);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/public");
        request.setRemoteAddr("1.2.3.4");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertEquals(200, response.getStatus());
    }

    @Test
    void shouldIgnoreForwardedForFromUntrustedClient() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/login"));
        properties.getRateLimit().setCapacity(1);
        RateLimitFilter filter = new RateLimitFilter(properties);

        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/login");
            request.setRemoteAddr("203.0.113.10");
            request.addHeader("X-Forwarded-For", "198.51.100." + (i + 1));
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new MockFilterChain());
            assertEquals(i == 0 ? 200 : 429, response.getStatus());
        }
    }

    @Test
    void shouldUseForwardedForFromTrustedProxy() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/login"));
        properties.getRateLimit().setCapacity(1);
        RateLimitFilter filter = new RateLimitFilter(properties);

        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/login");
            request.setRemoteAddr("127.0.0.1");
            request.addHeader("X-Forwarded-For", "198.51.100.7");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new MockFilterChain());
            assertEquals(i == 0 ? 200 : 429, response.getStatus());
        }
    }

    @Test
    void shouldRemoveExpiredCounters() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/login"));
        properties.getRateLimit().setCapacity(100);
        properties.getRateLimit().setWindowSeconds(1);
        RateLimitFilter filter = new RateLimitFilter(properties);

        for (int i = 0; i < 50; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/login");
            request.setRemoteAddr("198.51.100." + i);
            filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        }
        assertEquals(50, filter.trackedKeyCount());

        Thread.sleep(1100);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/login");
        request.setRemoteAddr("203.0.113.99");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        assertEquals(1, filter.trackedKeyCount());
    }
}
