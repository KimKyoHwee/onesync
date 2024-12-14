package com.intern.onesync.service;

import com.intern.onesync.dto.CreateClientDto;
import com.intern.onesync.entity.Client;
import com.intern.onesync.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ClientService {
    private final ClientRepository clientRepository;


    public String saveClient(CreateClientDto createClientDto) {
        UUID uuid=UUID.randomUUID();
        Client client= Client.from(createClientDto, uuid);
        clientRepository.save(client);
        return uuid.toString();
    }
}
