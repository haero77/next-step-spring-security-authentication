package nextstep.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Map;
import java.util.Optional;

public class FormLoginInterceptor implements HandlerInterceptor {

    public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    private final UserDetailsService userDetailsService;

    public FormLoginInterceptor(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public boolean preHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler
    ) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        String username = parameterMap.get("username")[0];
        String password = parameterMap.get("password")[0];

        Optional<UserDetails> userDetailsOpt = userDetailsService.findUserDetailsByUsername(username);
        if (userDetailsOpt.isEmpty()) {
            throw new AuthenticationException();
        }

        UserDetails userDetails = userDetailsOpt.get();
        if (!userDetails.matchesPassword(password)) {
            throw new AuthenticationException();
        }

        HttpSession session = request.getSession();
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, userDetails);

        return false;
    }
}
