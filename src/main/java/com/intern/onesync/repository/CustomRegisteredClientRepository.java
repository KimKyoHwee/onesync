package com.intern.onesync.repository;

import com.intern.onesync.entity.Client;
import com.intern.onesync.util.ClientUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;


@Component
@RequiredArgsConstructor
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final ClientUtils clientUtils;

    @Override
    public void save(RegisteredClient registeredClient) {
        Client entity = clientUtils.toEntity(registeredClient);
        clientRepository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findById(id).orElseThrow();
        return clientUtils.toObject(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId).orElseThrow();
        return clientUtils.toObject(client);
    }
}
