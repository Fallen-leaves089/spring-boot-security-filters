package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class PathNormalizationTest {

    @Test
    void shouldNormalizePathParametersBeforeMatching() {
        assertPath("/admin/users", "/admin;foo/users");
        assertPath("/admin/users", "/admin%3Bfoo/users");
        assertPath("/admin/users", "/admin;jsessionid=abc/users");
        assertPath("/admin/users", "//admin//users");
    }

    @Test
    void csrfFilterShouldRejectMatrixParameterVariantsWithoutToken() throws Exception {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TestController())
                .addFilters(new CsrfTokenFilter(List.of("/admin")))
                .build();

        mvc.perform(post("/admin;foo/users"))
                .andExpect(status().isForbidden());
        mvc.perform(post(URI.create("/admin%3Bfoo/users")))
                .andExpect(status().isForbidden());
    }

    @Test
    void rateLimitShouldNotBeBypassedWithMatrixParameterVariants() throws Exception {
        SecurityFiltersProperties properties = new SecurityFiltersProperties();
        properties.getRateLimit().setPaths(List.of("/api/login"));
        properties.getRateLimit().setCapacity(1);
        RateLimitFilter filter = new RateLimitFilter(properties);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TestController())
                .addFilters(filter)
                .build();

        mvc.perform(get("/api/login;foo"))
                .andExpect(status().isOk());
        mvc.perform(get(URI.create("/api/login%3Bfoo")))
                .andExpect(status().isTooManyRequests());
    }

    private static void assertPath(String expected, String requestUri) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
        assertEquals(expected, PathMatcher.requestPath(request), requestUri);
    }

    @RestController
    static class TestController {

        @PostMapping("/admin/users")
        String admin() {
            return "admin";
        }

        @GetMapping("/api/login")
        String login() {
            return "login";
        }
    }
}
