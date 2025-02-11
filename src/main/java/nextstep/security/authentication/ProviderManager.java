package nextstep.security.authentication;

import nextstep.security.AuthenticationException;

import java.util.List;

public class ProviderManager implements AuthenticationManager {

    private final List<AuthenticationProvider> providers;

    public ProviderManager(List<AuthenticationProvider> providers) {
        this.providers = providers;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        for (AuthenticationProvider provider : providers) {
            if (provider.supports(authentication.getClass())) {
                return provider.authenticate(authentication);
            }
        }

        return authentication;
    }
}
