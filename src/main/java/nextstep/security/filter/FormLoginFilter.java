package nextstep.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import nextstep.security.AuthenticationException;
import nextstep.security.authentication.*;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;

// 인증 정보를 추출하고, AuthenticationManager 에게 비밀번호 맞고 틀리는 것을 검증하는 책임을 위임한다.
public class FormLoginFilter implements Filter {

    private static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    private static final List<String> AUTHENTICATION_NEED_PATHS = List.of("/login");

    private final AuthenticationManager authenticationManager;

    public FormLoginFilter(UserDetailsService userDetailsService1) {
        this.authenticationManager = new ProviderManager(
                List.of(new DaoAuthenticationProvider(userDetailsService1))
        );
    }

    @Override
    public void doFilter(
            ServletRequest servletRequest,
            ServletResponse servletResponse,
            FilterChain filterChain
    ) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        if (!AUTHENTICATION_NEED_PATHS.contains(httpRequest.getRequestURI())) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        // extract username and password
        Map<String, String[]> parameterMap = httpRequest.getParameterMap();
        String username = parameterMap.get("username")[0];
        String password = parameterMap.get("password")[0];

        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "username or password is empty");
            return;
        }

        Authentication authRequest = UsernamePasswordAuthenticationToken.unAuthenticated(username, password);

        try {
            Authentication authenticated = this.authenticationManager.authenticate(authRequest);
            HttpSession session = httpRequest.getSession();
            session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, authenticated);
        } catch (AuthenticationException e) {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "username or password is empty");
        }
    }
}
