package com.intern.onesync.config;


import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;

@Getter
public class CustomAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final String clientId;

    public CustomAuthenticationToken(Object principal, Object credentials, String clientId, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.clientId = clientId;
    }

}
