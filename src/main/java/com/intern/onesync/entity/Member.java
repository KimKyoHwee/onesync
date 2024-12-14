package com.intern.onesync.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.intern.onesync.dto.BasicJoinDto;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Entity
@Getter
@Setter
@Table
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class Member implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    //로그인시 아이디로 사용
    @Column(name = "member_username")
    private String username;

    @Column(name="member_email")
    private String email;

    @Column(name="member_password")
    private String password;

//    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "member_info", referencedColumnName = "info_id")
    private Info info;

    //    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "member_auth_code", referencedColumnName = "auth_code_id")
    private AuthorizationCodes authorizationCodes;

    @OneToMany(mappedBy = "member")
    private List<MemberRoles> memberRolesList = new ArrayList<>();

    @JsonIgnore
    @OneToMany(mappedBy = "member", fetch = FetchType.EAGER)
    private List<Authority> authorities = new ArrayList<>();
    private Boolean accountNonExpired;
    private Boolean accountNonLocked;
    private Boolean credentialsNonExpired;
    private Boolean enabled;

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    public static Member from(BasicJoinDto dto) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return Member.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .email(dto.getEmail())
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .enabled(true)
                .build();
    }

    public List<SimpleGrantedAuthority> getSimpleAuthorities() {
        return this.authorities.stream().map(authority -> new SimpleGrantedAuthority(authority.getAuthority())).toList();
    }
}
