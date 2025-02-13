package nextstep.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.AuthenticationException;
import nextstep.security.authentication.*;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.context.SecurityContextRepository;
import nextstep.security.util.Base64Convertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class BasicAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BasicAuthenticationFilter.class);

    private static final List<String> AUTHENTICATION_NEED_PATHS = List.of("/members");

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository; // 실제로는 RequestAttributeSecurityContextRepository 사용.

    public BasicAuthenticationFilter(UserDetailsService userDetailsService, SecurityContextRepository contextRepository) {
        this.authenticationManager = new ProviderManager(
                List.of(new DaoAuthenticationProvider(userDetailsService))
        );
        this.securityContextRepository = contextRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // '/members' 에 대한 요청이 아니면 필터링 하지 말라는 의미. 즉, '/members'에 대한 요청만 필터링
        return !AUTHENTICATION_NEED_PATHS.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        // '/members' 경로에 대한 인증과, 인가를 현재 필터에서 같이 처리하고 있으므로 Authentication에 접근.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authenticated = attemptAuthentication(request);

            SecurityContextHolder.getContext().setAuthentication(authenticated);
            securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);

            filterChain.doFilter(request, response);
        } catch (AuthenticationException | RuntimeException e) {
            log.debug("Authentication failed", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
        }
    }

    private Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        String authorization = request.getHeader("Authorization");
        String credentials = authorization.split(" ")[1];
        String decodedString = Base64Convertor.decode(credentials);
        String[] usernameAndPassword = decodedString.split(":");

        Authentication authRequest = UsernamePasswordAuthenticationToken.unAuthenticated(
                usernameAndPassword[0],
                usernameAndPassword[1]
        );

        return this.authenticationManager.authenticate(authRequest);
    }
}
