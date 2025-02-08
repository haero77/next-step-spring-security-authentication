package nextstep.security.config;

import jakarta.servlet.Filter;
import nextstep.security.FilterChainProxy;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * DelegatingFilterProxy를 FilterChainProxy를 참조하게 한 후 빈으로 등록한다.
 */
@Configuration
public class SecurityFilterAutoConfiguration {

    @Bean
    @ConditionalOnBean(name = FilterChainProxy.FILTER_CHAIN_PROXY_BEAN_NAME)
    public FilterRegistrationBean<Filter> springSecurityFilterChainRegistration() {
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();

        registration.setFilter(new DelegatingFilterProxy(FilterChainProxy.FILTER_CHAIN_PROXY_BEAN_NAME));

        return registration;
    }
}
