package nextstep.security.filter;

import java.util.Optional;

public interface UserDetailsService {

    Optional<UserDetails> findUserDetailsByUsername(String username);
}
