package nextstep.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({
        WebSecurityConfiguration.class,
        SecurityFilterAutoConfiguration.class,
})
public class SecurityAutoConfiguration {

}
