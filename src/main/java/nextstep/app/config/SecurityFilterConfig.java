package nextstep.app.config;

import jakarta.servlet.Filter;
import nextstep.security.BasicAuthenticationFilter;
import nextstep.security.FormLoginFilter;
import nextstep.security.UserDetailsService;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityFilterConfig {

    private final UserDetailsService userDetailsService;

    public SecurityFilterConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public FilterRegistrationBean<Filter> formLoginFilter() {
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();

        registrationBean.setFilter(new FormLoginFilter(userDetailsService));
        registrationBean.addUrlPatterns("/login");

        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<Filter> basicAuthenticationFilter() {
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();

        registrationBean.setFilter(new BasicAuthenticationFilter(userDetailsService));
        registrationBean.addUrlPatterns("/members");

        return registrationBean;
    }
}
