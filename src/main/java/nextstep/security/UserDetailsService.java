package nextstep.security;

import java.util.Optional;

public interface UserDetailsService {

    Optional<UserDetails> findUserDetailsByUsername(String username);
}
