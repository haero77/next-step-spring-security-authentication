package nextstep.security.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

public class HttpSessionSecurityContextRepository implements SecurityContextRepository {

    public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    // todo: SecurityContextRepository의 loadContext와 saveContext 동작을 각각 테스트.
    @Override
    public SecurityContext loadContext(HttpServletRequest request) {
        SecurityContext securityContext = readSecurityContextFromSession(request.getSession());

        if (securityContext == null) {
            return SecurityContextHolder.createEmptyContext();
        }

        return securityContext;
    }

    @Override
    public void saveContext(
            SecurityContext context,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        HttpSession session = request.getSession();
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, context);
    }

    private SecurityContext readSecurityContextFromSession(HttpSession session) {
        if (session == null) {
            return null;
        }

        // Session Exists.
        Object securityContextFromSession = session.getAttribute(SPRING_SECURITY_CONTEXT_KEY);
        if (securityContextFromSession == null) {
            return null;
        }

        if (!(securityContextFromSession instanceof SecurityContext)) {
            return null;
        }

        // Everything Cool! SecurityContext Exists.
        return (SecurityContext) securityContextFromSession;
    }
}
