package dev.hjosugi.authlab.spring.security;

import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;

public final class OidcDecoderFactory {

    private OidcDecoderFactory() {
    }

    public static JwtDecoderFactory<ClientRegistration> create(
            AuthLabSecurityProperties properties) {
        properties.requireComplete();
        OidcIdTokenDecoderFactory factory = new OidcIdTokenDecoderFactory();
        factory.setJwsAlgorithmResolver(registration -> SignatureAlgorithm.RS256);
        factory.setJwtValidatorFactory(registration ->
                validators(properties, registration));
        return factory;
    }

    static OAuth2TokenValidator<Jwt> validators(
            AuthLabSecurityProperties properties,
            ClientRegistration registration) {
        return new DelegatingOAuth2TokenValidator<>(
                new OidcIdTokenValidator(registration),
                new JwtIssuerValidator(properties.issuer().toString()));
    }
}
