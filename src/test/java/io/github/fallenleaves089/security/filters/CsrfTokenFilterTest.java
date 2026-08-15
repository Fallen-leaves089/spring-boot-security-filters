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

        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/admin");
        post.setSession(get.getSession());
        post.addHeader("X-CSRF-TOKEN", token);
        MockHttpServletResponse postResponse = new MockHttpServletResponse();
        filter.doFilter(post, postResponse, new MockFilterChain());
        assertEquals(200, postResponse.getStatus());
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
}
