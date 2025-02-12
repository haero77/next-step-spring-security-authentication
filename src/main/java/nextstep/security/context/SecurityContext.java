package nextstep.security.context;

import nextstep.security.authentication.Authentication;

import java.io.Serializable;

public interface SecurityContext extends Serializable {

    Authentication getAuthentication();

    void setAuthentication(Authentication authentication);
}
