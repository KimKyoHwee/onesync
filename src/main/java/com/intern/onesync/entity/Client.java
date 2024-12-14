package com.intern.onesync.entity;

import com.intern.onesync.dto.BasicJoinDto;
import com.intern.onesync.dto.CreateClientDto;
import com.intern.onesync.util.ClientSettingsConverter;
import com.intern.onesync.util.TokenSettingsConverter;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Instant;
import java.util.UUID;


@Getter
@Entity
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name="client_pk")
    private String id;
    @Column(unique = true)
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    @Column(length = 1000)
    private String clientAuthenticationMethods;
    @Column(length = 1000)
    private String authorizationGrantTypes;
    @Column(length = 1000)
    private String redirectUris;
    @Column(length = 1000)
    private String postLogoutRedirectUris;
    @Column(length = 1000)
    private String scopes;
    /*
    @Column(length = 2000)
    @Convert(converter = ClientSettingsConverter.class)
    private ClientSettings clientSettings;
    @Column(length = 2000)
    @Convert(converter = TokenSettingsConverter.class)
    private TokenSettings tokenSettings;
     */
    public static Client from(CreateClientDto dto, UUID uuid) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(passwordEncoder.encode(uuid.toString()))
                .clientName(dto.getClientName())
                .clientAuthenticationMethods(dto.getClientAuthenticationMethods())
                .authorizationGrantTypes(dto.getAuthorizationGrantTypes())
                .redirectUris(dto.getRedirectUris())
                .postLogoutRedirectUris(dto.getPostLogoutRedirectUris())
                .scopes(dto.getScopes())
                .build();
    }
}
