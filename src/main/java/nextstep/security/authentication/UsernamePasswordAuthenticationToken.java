package nextstep.security.authentication;

public class UsernamePasswordAuthenticationToken implements Authentication {

    private final String username;
    private final String password;
    private final boolean authenticated;

    private UsernamePasswordAuthenticationToken(String username, String password, boolean authenticated) {
        this.username = username;
        this.password = password;
        this.authenticated = authenticated;
    }

    public static UsernamePasswordAuthenticationToken unAuthenticated(String username, String password) {
        return new UsernamePasswordAuthenticationToken(username, password, false);
    }

    public static UsernamePasswordAuthenticationToken authenticated(Authentication authentication) {
        return new UsernamePasswordAuthenticationToken(
                (String) authentication.getPrincipal(),
                (String) authentication.getCredentials(),
                true
        );
    }

    @Override
    public Object getCredentials() {
        return this.password;
    }

    @Override
    public Object getPrincipal() {
        return this.username;
    }

    @Override
    public boolean isAuthenticated() {
        return this.authenticated;
    }
}
