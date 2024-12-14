package com.intern.onesync.service;

import com.intern.onesync.entity.Member;
import com.intern.onesync.repository.MemberRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Slf4j
@Transactional
@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member user = getUserByUsername(username);
        System.out.println(user.getId()+"불러와짐 "+user.getPassword());
        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .disabled(!user.getEnabled())
                .accountExpired(!user.getAccountNonExpired())
                .accountLocked(!user.getAccountNonLocked())
                .credentialsExpired(!user.getCredentialsNonExpired())
                .authorities(user.getSimpleAuthorities())
                .build();
    }


    public Member getUserByUsername(String username) throws UsernameNotFoundException {
        Member user=memberRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return user;
    }

}