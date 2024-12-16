package com.intern.onesync.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

@Component
public class JWTUtil {

    /**
     * JWT에서 "sub" 값을 추출합니다.
     */
    public Object getSubject(String token) {
        return getClaims(token).get("sub");
    }

    /**
     * JWT에서 "aud" 값을 추출합니다.
     */
    public Object getAudience(String token) {
        return getClaims(token).get("aud");
    }

    /**
     * JWT에서 "scope" 값을 추출합니다.
     */
    public Object getScope(String token) {
        return getClaims(token).get("scope");
    }

    /**
     * JWT에서 "id" 값을 추출합니다.
     */
    public Long getId(String token) {
        return getClaims(token).get("id", Long.class);
    }

    /**
     * JWT에서 "iss" 값을 추출합니다.
     */
    public String getIssuer(String token) {
        return getClaims(token).getIssuer();
    }

    /**
     * JWT를 파싱하여 Claims를 반환합니다.
     */
    private Claims getClaims(String token) {
        return Jwts.parser()
                .build()
                .parseClaimsJwt(token) // Signature 없는 JWT 토큰을 처리
                .getBody();
    }
}

