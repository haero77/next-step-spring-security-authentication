package nextstep.security.context;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class SecurityContextHolderFilter extends OncePerRequestFilter {

    private final SecurityContextRepository securityContextRepository;

    public SecurityContextHolderFilter(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        // contextRepository를 통해 SecurityContext를 가져온다. 없을 경우 empty context.
        SecurityContext context = this.securityContextRepository.loadContext(request);

        try {
            SecurityContextHolder.setContext(context);
            filterChain.doFilter(request, response);
        } finally {
            // 요청이 끝나고 SecurityContext를 clear. (HTTP Session에는 SecurityContext가 남아있을 수 있음)
            SecurityContextHolder.clearContext();
        }
    }
}
