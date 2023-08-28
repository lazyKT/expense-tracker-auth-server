package com.example.authserver.services;

import com.example.authserver.entities.Client;
import com.example.authserver.repositories.ClientRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;


/**
 * This service class is to register and manage the client for the Security
 * Definition of this class (implementing RegisteredClientRepository)
 * removes `registeredClientRepository()` Bean in Security Config
 */
@Service
@Transactional
public class CustomClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    @Autowired
    public CustomClientService (ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }


    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.save(Client.from(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findById(Integer.valueOf(id)).orElseThrow();
        return Client.from(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow();
        return Client.from(client);
    }
}
