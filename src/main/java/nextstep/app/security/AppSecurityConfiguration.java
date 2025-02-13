package nextstep.app.security;

import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContextHolderFilter;
import nextstep.security.context.SecurityContextRepository;
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
        SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();

        return new DefaultSecurityFilterChain(
                List.of(
                        new SecurityContextHolderFilter(contextRepository),
                        new UsernamePasswordAuthenticationFilter(userDetailsService, contextRepository),
                        new BasicAuthenticationFilter(userDetailsService, contextRepository)
                )
        );
    }
}
