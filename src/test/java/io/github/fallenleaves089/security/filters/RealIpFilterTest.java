package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RealIpFilterTest {

    @Test
    void shouldTrustXffOnlyFromLoopbackByDefault() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertEquals("1.2.3.4", RealIpFilter.resolve(request));
    }

    @Test
    void shouldNotTrustPrivateRemoteByDefault() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.5");
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertEquals("10.0.0.5", RealIpFilter.resolve(request));
    }

    @Test
    void shouldUseConfiguredProxyCidr() {
        ClientIpResolver resolver = new ClientIpResolver(true, List.of("10.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.5");
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertEquals("1.2.3.4", resolver.resolve(request));
    }

    @Test
    void shouldIgnoreForgedLeftmostXff() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "198.51.100.99, 203.0.113.7");

        assertEquals("203.0.113.7", ClientIpResolver.defaults().resolve(request));
    }

    @Test
    void shouldWalkRightToLeftAcrossMultipleTrustedProxies() {
        ClientIpResolver resolver = new ClientIpResolver(
                true, List.of("127.0.0.0/8", "10.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "198.51.100.7, 10.0.0.8, 127.0.0.2");

        assertEquals("198.51.100.7", resolver.resolve(request));
    }

    @Test
    void shouldFallbackToRemoteForMalformedRightmostHop() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "198.51.100.7, not-an-ip");

        assertEquals("127.0.0.1", ClientIpResolver.defaults().resolve(request));
    }

    @Test
    void shouldIgnoreMalformedLeftmostHopWhenRightmostIsValid() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "not-an-ip, 198.51.100.7");

        assertEquals("198.51.100.7", ClientIpResolver.defaults().resolve(request));
    }

    @Test
    void shouldResolveIpv6WithPort() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("0:0:0:0:0:0:0:1");
        request.addHeader("X-Forwarded-For", "[2001:db8::42]:443");

        assertEquals("2001:db8::42", ClientIpResolver.defaults().resolve(request));
    }

    @Test
    void shouldTreatIpv4MappedIpv6AsIpv4() {
        ClientIpResolver resolver = new ClientIpResolver(true, List.of("10.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("::ffff:10.0.0.5");
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertEquals("1.2.3.4", resolver.resolve(request));
    }

    @Test
    void shouldMatchCidrPrefixThatDoesNotEndOnByteBoundary() {
        ClientIpResolver resolver = new ClientIpResolver(true, List.of("10.0.0.0/9"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.1.2.3");
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertEquals("1.2.3.4", resolver.resolve(request));
    }

    @Test
    void shouldNotTrustXffWhenRealIpIsDisabled() {
        ClientIpResolver resolver = new ClientIpResolver(false, List.of("127.0.0.0/8"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "1.2.3.4");

        assertEquals("127.0.0.1", resolver.resolve(request));
    }

    @Test
    void shouldFallbackToRemoteWhenAllHopsAreTrusted() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "127.0.0.2, 127.0.0.3");

        assertEquals("127.0.0.1", ClientIpResolver.defaults().resolve(request));
    }

    @Test
    void shouldNormalizeIpv4WithPort() {
        assertEquals("10.0.0.5", RealIpFilter.normalize("10.0.0.5:52341"));
    }

    @Test
    void shouldRejectInvalidTrustedProxyConfiguration() {
        assertThrows(IllegalArgumentException.class,
                () -> new ClientIpResolver(true, List.of("proxy.internal")));
        assertThrows(IllegalArgumentException.class,
                () -> new ClientIpResolver(true, List.of("10.0.0.0/33")));
        assertThrows(IllegalArgumentException.class,
                () -> new ClientIpResolver(true, List.of("10.0.0.0:443/8")));
    }
}
