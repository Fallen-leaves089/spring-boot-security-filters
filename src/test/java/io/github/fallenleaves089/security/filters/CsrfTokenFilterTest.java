package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CsrfTokenFilterTest {

    @Test
    void shouldGenerateTokenOnGetAndAcceptItOnPost() throws Exception {
        CsrfTokenFilter filter = new CsrfTokenFilter(List.of("/admin"));

        MockHttpServletRequest get = new MockHttpServletRequest("GET", "/admin");
        MockHttpServletResponse getResponse = new MockHttpServletResponse();
        filter.doFilter(get, getResponse, new MockFilterChain());
        String token = (String) get.getSession().getAttribute("CSRF_TOKEN");
        assertNotNull(token);
        assertEquals(token, getResponse.getHeader("X-CSRF-TOKEN"));
        assertEquals(token, get.getAttribute("CSRF_TOKEN"));
        assertEquals("no-store", getResponse.getHeader("Cache-Control"));

        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/admin");
        post.setSession(get.getSession());
        post.addHeader("X-CSRF-TOKEN", token);
        MockHttpServletResponse postResponse = new MockHttpServletResponse();
        filter.doFilter(post, postResponse, new MockFilterChain());
        assertEquals(200, postResponse.getStatus());

        MockHttpServletRequest secondGet = new MockHttpServletRequest("GET", "/admin");
        secondGet.setSession(get.getSession());
        MockHttpServletResponse secondGetResponse = new MockHttpServletResponse();
        filter.doFilter(secondGet, secondGetResponse, new MockFilterChain());
        assertEquals(token, secondGetResponse.getHeader("X-CSRF-TOKEN"));
    }

    @Test
    void shouldRejectInvalidToken() throws Exception {
        CsrfTokenFilter filter = new CsrfTokenFilter(List.of("/admin"));

        MockHttpServletRequest get = new MockHttpServletRequest("GET", "/admin");
        filter.doFilter(get, new MockHttpServletResponse(), new MockFilterChain());

        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/admin");
        post.setSession(get.getSession());
        post.addHeader("X-CSRF-TOKEN", "wrong-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(post, response, new MockFilterChain());
        assertEquals(403, response.getStatus());
    }

    @Test
    void shouldRejectProtectedRequestWithoutSession() throws Exception {
        CsrfTokenFilter filter = new CsrfTokenFilter(List.of("/admin"));

        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/admin");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(post, response, new MockFilterChain());

        assertEquals(403, response.getStatus());
    }
}
