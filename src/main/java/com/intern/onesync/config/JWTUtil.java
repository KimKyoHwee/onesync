package com.intern.onesync.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.Map;

import org.springframework.stereotype.Component;

@Component
public class JWTUtil {

    /**
     * JWT에서 Payload 부분만 추출하여 디코딩합니다.
     */
    private Map<String, Object> getPayload(String token) {
        try {
            // 토큰 분리 (Header, Payload, Signature)
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT format");
            }

            // Base64 URL 디코딩
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            // JSON을 Map으로 변환
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(payload, Map.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JWT payload", e);
        }
    }

    /**
     * JWT에서 "sub" 값을 추출합니다.
     */
    public String getSubject(String token) {
        return (String) getPayload(token).get("sub");
    }

    /**
     * JWT에서 "aud" 값을 추출합니다.
     */
    public String getAudience(String token) {
        return (String) getPayload(token).get("aud");
    }

    /**
     * JWT에서 "scope" 값을 추출합니다.
     */
    public Object getScope(String token) {
        return getPayload(token).get("scope");
    }

    /**
     * JWT에서 "id" 값을 추출합니다.
     */
    public Long getId(String token) {
        return Long.valueOf(getPayload(token).get("id").toString());
    }

    /**
     * JWT에서 "iss" 값을 추출합니다.
     */
    public String getIssuer(String token) {
        return (String) getPayload(token).get("iss");
    }
}
