package nextstep.app.security;

import nextstep.app.domain.MemberRepository;
import nextstep.security.filter.UserDetails;
import nextstep.security.filter.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final MemberRepository memberRepository;

    public UserDetailsServiceImpl(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public Optional<UserDetails> findUserDetailsByUsername(String username) {
        if (!StringUtils.hasLength(username)) {
            return Optional.empty();
        }

        return memberRepository.findByEmail(username)
                .map(member -> new UserDetails(member.getEmail(), member.getPassword()));
    }
}
