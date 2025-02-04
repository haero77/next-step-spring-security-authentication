package nextstep.app.config;

import nextstep.security.BasicAuthenticationInterceptor;
import nextstep.security.FormLoginInterceptor;
import nextstep.security.UserDetailsService;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final UserDetailsService userDetailsService;

    public WebConfig(final UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new FormLoginInterceptor(userDetailsService))
                .addPathPatterns("/login");

        registry.addInterceptor(new BasicAuthenticationInterceptor(userDetailsService))
                .addPathPatterns("/members");
    }
}
