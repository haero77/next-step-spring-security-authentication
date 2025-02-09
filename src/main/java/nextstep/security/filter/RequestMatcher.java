package nextstep.security.filter;

import jakarta.servlet.http.HttpServletRequest;

public interface RequestMatcher {

    boolean matches(HttpServletRequest request);
}
