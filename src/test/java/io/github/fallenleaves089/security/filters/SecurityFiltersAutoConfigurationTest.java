package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityFiltersAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SecurityFiltersAutoConfiguration.class));

    @Test
    void shouldBindTrustedProxiesAndShareResolver() {
        contextRunner
                .withPropertyValues(
                        "security.real-ip.trusted-proxies[0]=10.0.0.0/8",
                        "security.rate-limit.paths[0]=/api/login")
                .run(context -> {
                    assertThat(context).hasSingleBean(ClientIpResolver.class);
                    ClientIpResolver resolver = context.getBean(ClientIpResolver.class);

                    MockHttpServletRequest request = new MockHttpServletRequest();
                    request.setRemoteAddr("10.0.0.5");
                    request.addHeader("X-Forwarded-For", "1.2.3.4");

                    assertThat(resolver.resolve(request)).isEqualTo("1.2.3.4");
                });
    }

    @Test
    void shouldAllowApplicationToReplaceResolverBean() {
        contextRunner
                .withUserConfiguration(CustomResolverConfiguration.class)
                .run(context -> assertThat(context.getBean(ClientIpResolver.class))
                        .isSameAs(CustomResolverConfiguration.RESOLVER));
    }

    @Test
    void shouldKeepResolverWhenRealIpFilterIsDisabled() {
        contextRunner
                .withPropertyValues("security.real-ip.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(RealIpFilter.class);
                    assertThat(context).hasSingleBean(ClientIpResolver.class);
                    assertThat(context).hasSingleBean(RateLimitFilter.class);
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomResolverConfiguration {

        static final ClientIpResolver RESOLVER = new ClientIpResolver(false, List.of());

        @Bean
        ClientIpResolver customClientIpResolver() {
            return RESOLVER;
        }
    }
}
