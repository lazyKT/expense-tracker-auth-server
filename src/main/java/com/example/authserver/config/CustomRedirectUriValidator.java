package com.example.authserver.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.function.Consumer;


// Custom RedirectURI validator for OAuth2
// By Default, OAuth2 does not allow localhost(127.0.0.1) as the valid RedirectURI
// However, we can customize the validator to allow localhost for dev purposes
public class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {


    @Override
    public void accept (OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken token = context.getAuthentication();
        RegisteredClient client = context.getRegisteredClient();
        String uri = token.getRedirectUri();

        if (!client.getRedirectUris().contains(uri)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
    }
}
