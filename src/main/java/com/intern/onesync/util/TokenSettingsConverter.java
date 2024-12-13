package com.intern.onesync.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

public class TokenSettingsConverter implements AttributeConverter<TokenSettings, String> {
    private final ObjectMapper objectMapper;

    public TokenSettingsConverter() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    public String convertToDatabaseColumn(TokenSettings tokenSettings) {
        try {
            return objectMapper.writeValueAsString(tokenSettings);
        } catch (Exception e) {
            throw new IllegalArgumentException("Error converting TokenSettings to JSON", e);
        }
    }

    @Override
    public TokenSettings convertToEntityAttribute(String dbData) {
        try {
            return objectMapper.readValue(dbData, TokenSettings.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Error converting JSON to TokenSettings", e);
        }
    }
}
