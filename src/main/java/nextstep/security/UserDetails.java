package nextstep.security;

import java.util.Objects;

public record UserDetails(
        String username,
        String password
) {

    public boolean matchesPassword(String password) {
        return Objects.nonNull(this.password) && this.password.equals(password);
    }
}
