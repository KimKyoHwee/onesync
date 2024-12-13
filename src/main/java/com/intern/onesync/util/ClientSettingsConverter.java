package com.intern.onesync.util;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import com.fasterxml.jackson.databind.ObjectMapper;

@Converter
public class ClientSettingsConverter implements AttributeConverter<ClientSettings, String> {

    private final ObjectMapper objectMapper = new ObjectMapper();

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
