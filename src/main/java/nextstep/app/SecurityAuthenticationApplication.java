package nextstep.app;

import nextstep.security.config.SecurityFilterAutoConfiguration;
import nextstep.security.config.WebSecurityConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({SecurityFilterAutoConfiguration.class, WebSecurityConfiguration.class})
public class SecurityAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityAuthenticationApplication.class, args);
    }

}
