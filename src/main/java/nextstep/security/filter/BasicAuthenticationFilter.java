package nextstep.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.AuthenticationException;
import nextstep.security.authentication.*;
import nextstep.security.util.Base64Convertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

public class BasicAuthenticationFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(BasicAuthenticationFilter.class);

    private static final List<String> AUTHENTICATION_NEED_PATHS = List.of("/members");

    private final AuthenticationManager authenticationManager;

    public BasicAuthenticationFilter(UserDetailsService userDetailsService) {
        this.authenticationManager = new ProviderManager(
                List.of(new DaoAuthenticationProvider(userDetailsService))
        );
    }

    @Override
    public void doFilter(
            ServletRequest servletRequest,
            ServletResponse servletResponse,
            FilterChain filterChain
    ) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;

        if (!AUTHENTICATION_NEED_PATHS.contains(httpRequest.getRequestURI())) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        try {
            String authorization = httpRequest.getHeader("Authorization");
            String credentials = authorization.split(" ")[1]; // "Basic " 뒤의 문자열
            String decodedString = Base64Convertor.decode(credentials);
            String[] usernameAndPassword = decodedString.split(":");
            String username = usernameAndPassword[0];
            String password = usernameAndPassword[1];

            Authentication authRequest = UsernamePasswordAuthenticationToken.unAuthenticated(username, password);
            Authentication authenticated = this.authenticationManager.authenticate(authRequest);

            httpRequest.setAttribute("userDetails", authenticated); // 이후 필터에서 사용 가능하도록 인증된 사용자 정보를 저장

            filterChain.doFilter(servletRequest, servletResponse);
        } catch (AuthenticationException | RuntimeException e) {
            log.debug("Authentication failed", e);
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
        }
    }
}
