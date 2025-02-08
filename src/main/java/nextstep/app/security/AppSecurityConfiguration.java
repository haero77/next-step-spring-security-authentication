package nextstep.app.security;

import nextstep.security.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class AppSecurityConfiguration {

    private final UserDetailsService userDetailsService;

    public AppSecurityConfiguration(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain formLoginSecurityFilterChain() {
        return new DefaultSecurityFilterChain(
                (httpServletRequest) -> httpServletRequest.getRequestURI().equals("/login"),
                List.of(
                        new FormLoginFilter(userDetailsService)
                )
        );
    }

    @Bean
    public SecurityFilterChain basicAuthenticationSecurityFilterChain() {
        return new DefaultSecurityFilterChain(
                (httpServletRequest) -> httpServletRequest.getRequestURI().equals("/members"),
                List.of(
                        new BasicAuthenticationFilter(userDetailsService)
                )
        );
    }
}
