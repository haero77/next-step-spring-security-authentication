package nextstep.app;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.app.domain.MemberRepository;
import nextstep.app.ui.AuthenticationException;
import nextstep.app.util.Base64Convertor;
import org.springframework.web.servlet.HandlerInterceptor;

public class BasicAuthenticationInterceptor implements HandlerInterceptor {

    private final MemberRepository memberRepository;

    public BasicAuthenticationInterceptor(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
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

            memberRepository.findByEmail(username)
                    .filter(it -> it.matchPassword(password))
                    .orElseThrow(AuthenticationException::new);

            return true;
        } catch (RuntimeException e) {
            throw new AuthenticationException();
        }
    }
}
