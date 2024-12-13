package com.intern.onesync.util;

import lombok.Getter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Getter
public class TokenSettingsSerializer {
    private final TokenSettings tokenSettings;

    // 기존 생성자: Map<String, Object>에서 TokenSettings 생성
    public TokenSettingsSerializer(Map<String, Object> settings) {
        this.tokenSettings = buildTokenSettings(settings);
    }

    // 새 생성자: TokenSettings에서 Map<String, Object> 생성
    public TokenSettingsSerializer(TokenSettings tokenSettings) {
        this.tokenSettings = tokenSettings;
    }

    // TokenSettings -> Map<String, Object>
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("authorization_code_time_to_live", tokenSettings.getAuthorizationCodeTimeToLive().getSeconds());
        map.put("access_token_time_to_live", tokenSettings.getAccessTokenTimeToLive().getSeconds());
        map.put("device_code_time_to_live", tokenSettings.getDeviceCodeTimeToLive().getSeconds());
        map.put("refresh_token_time_to_live", tokenSettings.getRefreshTokenTimeToLive().getSeconds());
        map.put("reuse_refresh_tokens", tokenSettings.isReuseRefreshTokens());
        map.put("id_token_signature_algorithm", tokenSettings.getIdTokenSignatureAlgorithm().getName());

        // AccessTokenFormat을 Map<String, Object>로 변환
        OAuth2TokenFormat accessTokenFormat = tokenSettings.getAccessTokenFormat();
        Map<String, Object> tokenFormatMap = new HashMap<>();
        tokenFormatMap.put("value", accessTokenFormat.getValue());
        map.put("access_token_format", tokenFormatMap);

        return map;
    }

    // Map<String, Object> -> TokenSettings
    private TokenSettings buildTokenSettings(Map<String, Object> settings) {
        return TokenSettings.builder()
                .authorizationCodeTimeToLive(
                        durationConverter((Number) settings.get("authorization_code_time_to_live"))
                )
                .accessTokenTimeToLive(
                        durationConverter((Number) settings.get("access_token_time_to_live"))
                )
                .deviceCodeTimeToLive(
                        durationConverter((Number) settings.get("device_code_time_to_live"))
                )
                .refreshTokenTimeToLive(
                        durationConverter((Number) settings.get("refresh_token_time_to_live"))
                )
                .reuseRefreshTokens(
                        Boolean.TRUE.equals(settings.get("reuse_refresh_tokens"))
                )
                .idTokenSignatureAlgorithm(
                        signatureAlgorithmConverter((String) settings.get("id_token_signature_algorithm"))
                )
                .accessTokenFormat(
                        tokenFormatConverter((Map<String, Object>) settings.get("access_token_format"))
                )
                .build();
    }

    private Duration durationConverter(Number value) {
        return Duration.ofSeconds(value.longValue());
    }

    private OAuth2TokenFormat tokenFormatConverter(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            throw new IllegalArgumentException("Invalid token format map.");
        }
        String format = (String) map.get("value");
        if (OAuth2TokenFormat.SELF_CONTAINED.getValue().equals(format)) {
            return OAuth2TokenFormat.SELF_CONTAINED;
        } else if (OAuth2TokenFormat.REFERENCE.getValue().equals(format)) {
            return OAuth2TokenFormat.REFERENCE;
        }
        throw new IllegalArgumentException("Unknown token format: " + format);
    }

    private SignatureAlgorithm signatureAlgorithmConverter(String algorithm) {
        switch (algorithm) {
            case "RS256":
                return SignatureAlgorithm.RS256;
            case "RS512":
                return SignatureAlgorithm.RS512;
            case "ES256":
                return SignatureAlgorithm.ES256;
            case "ES512":
                return SignatureAlgorithm.ES512;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }
}
