package com.intern.onesync.util;

import lombok.Getter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.HashMap;
import java.util.Map;

@Getter
public class ClientSettingsSerializer {
    private final ClientSettings clientSettings;

    public ClientSettingsSerializer(Map<String, Object> settings) {
        this.clientSettings = buildClientSettings(settings);
    }

    public ClientSettingsSerializer(ClientSettings clientSettings) {
        this.clientSettings = clientSettings;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("requireProofKey", clientSettings.isRequireProofKey());
        map.put("requireAuthorizationConsent", clientSettings.isRequireAuthorizationConsent());
        return map;
    }

    private ClientSettings buildClientSettings(Map<String, Object> settings) {
        return ClientSettings.builder()
                .requireProofKey((Boolean) settings.get("requireProofKey"))
                .requireAuthorizationConsent((Boolean) settings.get("requireAuthorizationConsent"))
                .build();
    }
}
