package nextstep.security.authentication;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class UsernamePasswordAuthenticationTokenTest {

    @Test
    void unAuthenticated() {
        UsernamePasswordAuthenticationToken actual = UsernamePasswordAuthenticationToken.unAuthenticated("username", "password");

        Assertions.assertAll(
                () -> assertEquals("username", actual.getPrincipal()),
                () -> assertEquals("password", actual.getCredentials()),
                () -> assertFalse(actual.isAuthenticated())
        );
    }
}
