package nextstep.security.authentication;

import nextstep.security.AuthenticationException;

@FunctionalInterface
public interface AuthenticationManager {

    /**
     * Attempts to authenticate the passed {@link Authentication} object, returning a
     * fully populated <code>Authentication</code> object if successful.
     * @param authentication the authentication request object
     * @return a fully authenticated object including credentials
     * @throws AuthenticationException if authentication fails
     */
    Authentication authenticate(Authentication authentication) throws AuthenticationException;
}
