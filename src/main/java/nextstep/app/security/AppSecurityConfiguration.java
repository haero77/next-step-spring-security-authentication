package nextstep.app.security;

import nextstep.security.filter.*;
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
                List.of(
                        new UsernamePasswordAuthenticationFilter(userDetailsService),
                        new BasicAuthenticationFilter(userDetailsService)
                )
        );
    }
}
