package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RealIpFilterTest {

    @Test
    void shouldTrustXffOnlyFromPrivateProxy() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.5");
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertEquals("1.2.3.4", RealIpFilter.resolve(request));
    }

    @Test
    void shouldIgnoreForgedXffFromPublicRemote() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("8.8.8.8");
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertEquals("8.8.8.8", RealIpFilter.resolve(request));
    }

    @Test
    void shouldNormalizeIpv4WithPort() {
        assertEquals("10.0.0.5", RealIpFilter.normalize("10.0.0.5:52341"));
    }
}
