package nextstep.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.util.Base64Convertor;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Optional;

public class BasicAuthenticationInterceptor implements HandlerInterceptor {

    private final UserDetailsService userDetailsService;

    public BasicAuthenticationInterceptor(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean preHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler
    ) {
        try {
            String authorization = request.getHeader("Authorization");
            String credentials = authorization.split(" ")[1]; // "Basic " 뒤의 문자열
            String decodedString = Base64Convertor.decode(credentials);
            String[] usernameAndPassword = decodedString.split(":");
            String username = usernameAndPassword[0];
            String password = usernameAndPassword[1];

            Optional<UserDetails> userDetailsOpt = userDetailsService.findUserDetailsByUsername(username);
            if (userDetailsOpt.isEmpty()) {
                throw new AuthenticationException();
            }

            UserDetails userDetails = userDetailsOpt.get();
            if (!userDetails.matchesPassword(password)) {
                throw new AuthenticationException();
            }

            return true;
        } catch (RuntimeException e) {
            throw new AuthenticationException();
        }
    }
}
