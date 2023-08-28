package com.example.authserver.entities;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Entity
@Table(name = "clients")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String clientId;
    private String secret;
    private String redirectUri;
    private String grantType;
    private String scope;
    private String authMethod;

    public void setId(int id) {
        this.id = id;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public int getId() {
        return id;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSecret() {
        return secret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getScope() {
        return scope;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public static Client from (RegisteredClient registeredClient) {
        Client client = new Client();
        client.setClientId(registeredClient.getClientId());
        client.setSecret(registeredClient.getClientSecret());
        client.setRedirectUri(
            // in real world application, we will have multiple redirect URIs
            // in this case, for simplicity, we will just use like below
            registeredClient.getRedirectUris().stream().findAny().get()
        );
        client.setScope(
            registeredClient.getScopes().stream().findAny().get()
        );
        client.setGrantType(
            registeredClient.getAuthorizationGrantTypes().stream().findAny().get().getValue()
        );
        client.setAuthMethod(
            registeredClient.getClientAuthenticationMethods().stream().findAny().get().getValue()
        );
        return client;
    }

    public static RegisteredClient from (Client client) {
        return RegisteredClient.withId(String.valueOf(client.getId()))
                .clientId(client.getClientId())
                .clientSecret(client.getSecret())
                .scope(client.getScope())
                .redirectUri(client.getRedirectUri())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuthMethod()))
                .authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
                .build();
    }
}
