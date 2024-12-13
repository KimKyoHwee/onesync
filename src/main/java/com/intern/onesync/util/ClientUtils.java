package com.intern.onesync.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.intern.onesync.entity.Client;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.*;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.*;
import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;
import static org.springframework.util.StringUtils.commaDelimitedListToSet;

@Component
@RequiredArgsConstructor
public class ClientUtils {
    private static final Logger logger = LoggerFactory.getLogger(ClientUtils.class);

    public RegisteredClient toObject(Client client) {
        logger.info("Converting Client to RegisteredClient: {}", client);

        Set<String> clientAuthenticationMethods = commaDelimitedListToSet(client.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = commaDelimitedListToSet(client.getAuthorizationGrantTypes());
        Set<String> redirectUris = commaDelimitedListToSet(client.getRedirectUris());
        Set<String> clientScopes = commaDelimitedListToSet(client.getScopes());
        Set<String> postLogoutUris = commaDelimitedListToSet(client.getPostLogoutRedirectUris());

        // Deserialize TokenSettings
        Map<String, Object> tokenSettingsMap = parseMap(client.getTokenSettings());
        TokenSettingsSerializer tokenSettingsSerializer = new TokenSettingsSerializer(tokenSettingsMap);

        // Deserialize ClientSettings
        Map<String, Object> clientSettingsMap = parseMap(client.getClientSettings());
        ClientSettingsSerializer clientSettingsSerializer = new ClientSettingsSerializer(clientSettingsMap);

        RegisteredClient.Builder registeredClient = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())
                .clientAuthenticationMethods(authenticationMethods ->
                        clientAuthenticationMethods.forEach(authenticationMethod ->
                                authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))
                        )
                )
                .authorizationGrantTypes(grantTypes ->
                        authorizationGrantTypes.forEach(grantType ->
                                grantTypes.add(resolveAuthorizationGrantType(grantType))
                        )
                )
                .redirectUris(uris -> uris.addAll(redirectUris))
                .postLogoutRedirectUris(uris -> uris.addAll(postLogoutUris))
                .scopes(scopes -> scopes.addAll(clientScopes))
                .clientSettings(clientSettingsSerializer.getClientSettings())
                .tokenSettings(tokenSettingsSerializer.getTokenSettings());

        return registeredClient.build();
    }

    public Client toEntity(RegisteredClient registeredClient) {
        logger.info("Converting RegisteredClient to Client: {}", registeredClient);

        List<String> clientAuthenticationMethods = new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
        registeredClient.getClientAuthenticationMethods().forEach(clientAuthenticationMethod ->
                clientAuthenticationMethods.add(clientAuthenticationMethod.getValue())
        );

        List<String> authorizationGrantTypes = new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
        registeredClient.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
                authorizationGrantTypes.add(authorizationGrantType.getValue())
        );

        // Use ClientSettings and TokenSettings directly
        Client entity = new Client();
        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        entity.setClientName(registeredClient.getClientName());
        entity.setClientAuthenticationMethods(collectionToCommaDelimitedString(clientAuthenticationMethods));
        entity.setAuthorizationGrantTypes(collectionToCommaDelimitedString(authorizationGrantTypes));
        entity.setRedirectUris(collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        entity.setPostLogoutRedirectUris(collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()));
        entity.setScopes(collectionToCommaDelimitedString(registeredClient.getScopes()));
        entity.setClientSettings(registeredClient.getClientSettings());
        entity.setTokenSettings(registeredClient.getTokenSettings());

        return entity;
    }


    private AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AUTHORIZATION_CODE;
        } else if (CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return CLIENT_CREDENTIALS;
        } else if (REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }

    private ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return CLIENT_SECRET_BASIC;
        } else if (CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return CLIENT_SECRET_POST;
        } else if (NONE.getValue().equals(clientAuthenticationMethod)) {
            return NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }

    private Map<String, Object> parseMap(String json) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Error parsing JSON to Map", e);
        }
    }

    private String mapToJson(Map<String, Object> map) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(map);
        } catch (Exception e) {
            throw new IllegalArgumentException("Error converting Map to JSON", e);
        }
    }
}
