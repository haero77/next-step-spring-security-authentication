package nextstep.security.authentication;

import nextstep.security.AuthenticationException;
import nextstep.security.filter.UserDetails;
import nextstep.security.filter.UserDetailsService;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Optional;

public class DaoAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    public DaoAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication, "Only UsernamePasswordAuthenticationToken is supported");

        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        if (!StringUtils.hasLength(username) || !StringUtils.hasLength(password)) {
            throw new AuthenticationException("username or password is empty");
        }

        Optional<UserDetails> userDetailsOpt = userDetailsService.findUserDetailsByUsername(username);
        if (userDetailsOpt.isEmpty()) {
            throw new AuthenticationException("User not found");
        }

        UserDetails userDetails = userDetailsOpt.get();
        if (!userDetails.matchesPassword(password)) {
            throw new AuthenticationException("username or password invalid");
        }

        // matches password. authenticated.
        return UsernamePasswordAuthenticationToken.authenticated(authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
