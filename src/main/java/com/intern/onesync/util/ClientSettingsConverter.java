package com.intern.onesync.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

public class ClientSettingsConverter implements AttributeConverter<ClientSettings, String> {
    private final ObjectMapper objectMapper;

    public ClientSettingsConverter() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    public String convertToDatabaseColumn(ClientSettings clientSettings) {
        try {
            return objectMapper.writeValueAsString(clientSettings);
        } catch (Exception e) {
            throw new IllegalArgumentException("Error converting ClientSettings to JSON", e);
        }
    }

    @Override
    public ClientSettings convertToEntityAttribute(String dbData) {
        try {
            return objectMapper.readValue(dbData, ClientSettings.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Error converting JSON to ClientSettings", e);
        }
    }
}
