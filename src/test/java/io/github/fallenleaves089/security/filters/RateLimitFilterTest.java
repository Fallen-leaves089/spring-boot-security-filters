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
}