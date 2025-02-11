package nextstep.security.authentication;

import nextstep.security.AuthenticationException;
import nextstep.security.filter.UserDetails;
import nextstep.security.filter.UserDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class DaoAuthenticationProviderTest {

    @Mock
    private UserDetailsService userDetailsService;

    private DaoAuthenticationProvider sut;

    @BeforeEach
    void setUp() {
        sut = new DaoAuthenticationProvider(userDetailsService);
    }

    @DisplayName("DaoAuthenticationProvider는 UsernamePasswordAuthenticationToken의 인증을 지원한다")
    @Test
    void supports() {
        Class<? extends Authentication> authenticationClass = UsernamePasswordAuthenticationToken.unAuthenticated("username", "password")
                .getClass();

        assertTrue(sut.supports(authenticationClass));
    }

    @DisplayName("올바른 인증 정보로 인증에 성공 시 authentication.isAuthenticated는 true")
    @Test
    void authenticate_WithValidCredentials_ShouldReturnAuthenticatedToken() throws AuthenticationException {
        // given
        UserDetails userDetails = new UserDetails("testUser", "password123");
        given(userDetailsService.findUserDetailsByUsername("testUser"))
                .willReturn(Optional.of(userDetails));

        Authentication authRequest = UsernamePasswordAuthenticationToken.unAuthenticated("testUser", "password123");

        // when
        Authentication authentication = sut.authenticate(authRequest);

        // then
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getPrincipal()).isEqualTo("testUser");
    }

    @DisplayName("존재하지 않는 사용자로 인증 시 예외 발생")
    @Test
    void authenticate_WithNonExistentUser_ShouldThrowException() {
        // given
        given(userDetailsService.findUserDetailsByUsername("nonexistent"))
                .willReturn(Optional.empty());

        Authentication authRequest = UsernamePasswordAuthenticationToken.unAuthenticated("nonexistent", "password123");

        // when, then
        assertThatThrownBy(() -> sut.authenticate(authRequest))
                .isInstanceOf(AuthenticationException.class);
    }

    @DisplayName("잘못된 비밀번호로 인증 시 예외 발생")
    @Test
    void authenticate_WithInvalidPassword_ShouldThrowException() {
        // given
        UserDetails userDetails = new UserDetails("testUser", "correctPassword");
        given(userDetailsService.findUserDetailsByUsername("testUser"))
                .willReturn(Optional.of(userDetails));

        Authentication authRequest = UsernamePasswordAuthenticationToken.unAuthenticated("testUser", "wrongPassword");

        // when, then
        assertThatThrownBy(() -> sut.authenticate(authRequest))
                .isInstanceOf(AuthenticationException.class);
    }
}
