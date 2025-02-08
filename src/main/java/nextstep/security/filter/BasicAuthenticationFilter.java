package nextstep.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.util.Base64Convertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Optional;

public class BasicAuthenticationFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(BasicAuthenticationFilter.class);

    private final UserDetailsService userDetailsService;

    public BasicAuthenticationFilter(UserDetailsService userDetailsService) {
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

        try {
            String authorization = httpRequest.getHeader("Authorization");
            String credentials = authorization.split(" ")[1]; // "Basic " 뒤의 문자열
            String decodedString = Base64Convertor.decode(credentials);
            String[] usernameAndPassword = decodedString.split(":");
            String username = usernameAndPassword[0];
            String password = usernameAndPassword[1];

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

            httpRequest.setAttribute("userDetails", userDetails); // 이후 필터에서 사용 가능하도록 인증된 사용자 정보를 저장

            filterChain.doFilter(servletRequest, servletResponse);
        } catch (RuntimeException e) {
            log.debug("Authentication failed", e);
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
        }
    }
}
