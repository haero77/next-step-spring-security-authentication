package nextstep.security.authentication;

import nextstep.security.AuthenticationException;

public interface AuthenticationProvider {

    /**
     * Performs authentication with the same contract as AuthenticationManager.authenticate(Authentication).
     * @param authentication the authentication request object.
     * @return a fully authenticated object including credentials.
     * @throws AuthenticationException if authentication fails.
     */
    Authentication authenticate(Authentication authentication) throws AuthenticationException;

    boolean supports(Class<?> authentication);
}
