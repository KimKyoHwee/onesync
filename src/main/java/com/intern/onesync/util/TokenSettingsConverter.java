package com.intern.onesync.util;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import com.fasterxml.jackson.databind.ObjectMapper;

@Converter
public class TokenSettingsConverter implements AttributeConverter<TokenSettings, String> {

    private final ObjectMapper objectMapper = new ObjectMapper();

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
