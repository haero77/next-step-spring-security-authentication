package nextstep.security.config;

import nextstep.security.filter.FilterChainProxy;
import nextstep.security.filter.SecurityFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * "springSecurityFilterChain"이라는 이름으로 FilterChainProxy를 빈으로 등록한다.
 */
@Configuration
public class WebSecurityConfiguration {

    @Bean(name = FilterChainProxy.FILTER_CHAIN_PROXY_BEAN_NAME)
    public FilterChainProxy filterChainProxy(List<SecurityFilterChain> securityFilterChains) {
        return new FilterChainProxy(securityFilterChains);
    }
}
