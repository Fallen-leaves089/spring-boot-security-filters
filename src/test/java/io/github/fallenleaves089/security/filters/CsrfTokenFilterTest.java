package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

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

    @Test
    void shouldProtectDescendantsButNotSimilarPathPrefix() throws Exception {
        CsrfTokenFilter filter = new CsrfTokenFilter(List.of("/admin"));

        MockHttpServletRequest descendant = new MockHttpServletRequest("GET", "/admin/users");
        filter.doFilter(descendant, new MockHttpServletResponse(), new MockFilterChain());
        assertNotNull(descendant.getSession(false));

        MockHttpServletRequest similar = new MockHttpServletRequest("GET", "/administrator");
        filter.doFilter(similar, new MockHttpServletResponse(), new MockFilterChain());
        assertNull(similar.getSession(false));
    }

    @Test
    void shouldStripContextPathBeforeMatching() throws Exception {
        CsrfTokenFilter filter = new CsrfTokenFilter(List.of("/admin"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/admin/users");
        request.setContextPath("/app");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());

        assertNotNull(request.getSession(false));
        assertNotNull(response.getHeader("X-CSRF-TOKEN"));
    }

    @Test
    void shouldSupportWildcardPatterns() throws Exception {
        CsrfTokenFilter filter = new CsrfTokenFilter(List.of("/api/*/write"));

        MockHttpServletRequest matching = new MockHttpServletRequest("GET", "/api/v1/write");
        filter.doFilter(matching, new MockHttpServletResponse(), new MockFilterChain());
        assertNotNull(matching.getSession(false));

        MockHttpServletRequest nonMatching = new MockHttpServletRequest("GET", "/api/v1/read");
        filter.doFilter(nonMatching, new MockHttpServletResponse(), new MockFilterChain());
        assertNull(nonMatching.getSession(false));
    }

    @Test
    void shouldAcceptTrailingSlashInPrefix() throws Exception {
        CsrfTokenFilter filter = new CsrfTokenFilter(List.of("/admin/"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertNotNull(request.getSession(false));
    }
}
