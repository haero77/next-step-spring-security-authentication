package nextstep.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

public class FormLoginFilter implements Filter {

    private static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    private final UserDetailsService userDetailsService;

    public FormLoginFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public void doFilter(
            ServletRequest servletRequest,
            ServletResponse servletResponse,
            FilterChain filterChain
    ) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        Map<String, String[]> parameterMap = httpRequest.getParameterMap();
        String username = parameterMap.get("username")[0];
        String password = parameterMap.get("password")[0];

        Optional<UserDetails> userDetailsOpt = userDetailsService.findUserDetailsByUsername(username);
        if (userDetailsOpt.isEmpty()) {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found");
            return;
        }

        UserDetails userDetails = userDetailsOpt.get();
        if (!userDetails.matchesPassword(password)) {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Password mismatch");
            return;
        }

        HttpSession session = httpRequest.getSession();
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, userDetails);

        // '/login'는 존재하지 않으므로 filterChain.doFilter()를 호출하지 않는다. 필요시 redirect 처리.
        // filterChain.doFilter(servletRequest, servletResponse);
    }
}
