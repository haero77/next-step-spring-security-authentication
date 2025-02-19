package nextstep.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.AuthenticationException;
import nextstep.security.authentication.*;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.context.SecurityContextRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

// 인증 정보를 추출하고, AuthenticationManager 에게 비밀번호 맞고 틀리는 것을 검증하는 책임을 위임한다.
public class UsernamePasswordAuthenticationFilter extends OncePerRequestFilter {

    private static final List<String> AUTHENTICATION_NEED_PATHS = List.of("/login");

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository; // 실제로는 RequestAttributeSecurityContextRepository 사용.

    public UsernamePasswordAuthenticationFilter(
            UserDetailsService userDetailsService1,
            SecurityContextRepository contextRepository
    ) {
        this.authenticationManager = new ProviderManager(
                List.of(new DaoAuthenticationProvider(userDetailsService1))
        );
        this.securityContextRepository = contextRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !AUTHENTICATION_NEED_PATHS.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws IOException {
        try {
            Authentication authenticated = attemptAuthentication(request);

            SecurityContextHolder.getContext().setAuthentication(authenticated);
            securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);
        } catch (AuthenticationException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "username or password is invalid");
        }
    }

    private Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        Map<String, String[]> parameterMap = request.getParameterMap();
        String username = parameterMap.get("username")[0];
        String password = parameterMap.get("password")[0];

        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw new AuthenticationException("username or password is empty");
        }

        Authentication authRequest = UsernamePasswordAuthenticationToken.unAuthenticated(username, password);
        return this.authenticationManager.authenticate(authRequest);
    }
}
