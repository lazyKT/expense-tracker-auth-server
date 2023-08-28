package com.example.authserver.config;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

@Configuration
public class SecurityConfig {

    // GET: http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id={value}&scope={value}
    // &redirect_uri={uri}&code_challenge={challenge}&code_challenge_method=S256 => to get authorization_code

    //  POST: http:127.0.0.1:8080/oauth2/token?client_id={value}&redirect_uri={uri}&grant_type={value}
    //  &code={authorization_code}&code_verifier={verifier} => {access_token, refresh_token, id_token}

    // Security Filter Chain for Authorization Server
    @Bean
    @Order(1)
    public SecurityFilterChain authSecurityFilterChain (HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            // Custom Authentication Providers
            .authorizationEndpoint(
                endpoint -> endpoint.authenticationProviders(getAuthorizationProviders())
            )
            .oidc(Customizer.withDefaults()); // Open ID
        // if user is not authenticated yet, redirect to login page
        http.exceptionHandling(
            e -> e.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")
            )
        );

        return http.build();
    }


    // get all authorization validators
    private Consumer<List<AuthenticationProvider>> getAuthorizationProviders() {
        return providers -> {
          for (AuthenticationProvider provider: providers) {
              if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider x) {
                  x.setAuthenticationValidator(new CustomRedirectUriValidator());
              }
          }
        };
    }


    // Application Security Filter Chain
    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain (HttpSecurity http) throws Exception {
        // secure all endpoints
        http.authorizeHttpRequests(
            auth -> auth.anyRequest().authenticated()
        ).formLogin(Customizer.withDefaults());
        return http.build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {

        return NoOpPasswordEncoder.getInstance();
    }


    @Bean
    public AuthorizationServerSettings authorizationServerSettings () {
        return AuthorizationServerSettings.builder().build();
    }


    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey key = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet set = new JWKSet(key);
        return new ImmutableJWKSet<>(set);
    }


    // customize Claims in jwt access token
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> {
            context.getClaims().claim("test", "test");
        };
    }
}
