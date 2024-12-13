package com.intern.onesync.util;

import com.intern.onesync.entity.Client;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.*;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.*;
import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;
import static org.springframework.util.StringUtils.commaDelimitedListToSet;

@Component
@RequiredArgsConstructor
public class ClientUtils {

    /**
     * Converts Client entity to RegisteredClient object.
     *
     * @param client Client entity from database
     * @return RegisteredClient for Spring Security
     */
    public RegisteredClient toObject(Client client) {
        Set<String> clientAuthenticationMethods = commaDelimitedListToSet(client.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = commaDelimitedListToSet(client.getAuthorizationGrantTypes());
        Set<String> redirectUris = commaDelimitedListToSet(client.getRedirectUris());
        Set<String> clientScopes = commaDelimitedListToSet(client.getScopes());
        Set<String> postLogoutUris = commaDelimitedListToSet(client.getPostLogoutRedirectUris());

        return RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())
                .clientAuthenticationMethods(authMethods ->
                        clientAuthenticationMethods.forEach(authMethod ->
                                authMethods.add(resolveClientAuthenticationMethod(authMethod))))
                .authorizationGrantTypes(grantTypes ->
                        authorizationGrantTypes.forEach(grantType ->
                                grantTypes.add(resolveAuthorizationGrantType(grantType))))
                .redirectUris(redirectUris::addAll)
                .postLogoutRedirectUris(postLogoutUris::addAll)
                .scopes(clientScopes::addAll)
                .clientSettings(client.getClientSettings())  // JSON 직렬화/역직렬화 자동 처리
                .tokenSettings(client.getTokenSettings())    // JSON 직렬화/역직렬화 자동 처리
                .build();
    }

    /**
     * Converts RegisteredClient object to Client entity.
     *
     * @param registeredClient RegisteredClient for Spring Security
     * @return Client entity for database
     */
    public Client toEntity(RegisteredClient registeredClient) {
        List<String> clientAuthenticationMethods = new ArrayList<>();
        registeredClient.getClientAuthenticationMethods().forEach(authMethod ->
                clientAuthenticationMethods.add(authMethod.getValue()));

        List<String> authorizationGrantTypes = new ArrayList<>();
        registeredClient.getAuthorizationGrantTypes().forEach(grantType ->
                authorizationGrantTypes.add(grantType.getValue()));

        return Client.builder()
                .id(registeredClient.getId())
                .clientId(registeredClient.getClientId())
                .clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
                .clientSecret(registeredClient.getClientSecret())
                .clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt())
                .clientName(registeredClient.getClientName())
                .clientAuthenticationMethods(collectionToCommaDelimitedString(clientAuthenticationMethods))
                .authorizationGrantTypes(collectionToCommaDelimitedString(authorizationGrantTypes))
                .redirectUris(collectionToCommaDelimitedString(registeredClient.getRedirectUris()))
                .postLogoutRedirectUris(collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()))
                .scopes(collectionToCommaDelimitedString(registeredClient.getScopes()))
                .clientSettings(registeredClient.getClientSettings())  // JSON 직렬화/역직렬화 자동 처리
                .tokenSettings(registeredClient.getTokenSettings())    // JSON 직렬화/역직렬화 자동 처리
                .build();
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
}
