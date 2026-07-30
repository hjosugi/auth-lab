package dev.hjosugi.authlab.spring.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;

@Configuration
public class SecurityBeans {

    @Bean
    JwtDecoder authLabJwtDecoder(AuthLabSecurityProperties properties) {
        return JwtDecoderFactory.create(properties);
    }

    @Bean
    org.springframework.security.oauth2.jwt.JwtDecoderFactory<ClientRegistration>
            authLabOidcIdTokenDecoderFactory(
            AuthLabSecurityProperties properties) {
        return OidcDecoderFactory.create(properties);
    }

    @Bean
    OpaqueTokenIntrospector authLabOpaqueTokenIntrospector(
            AuthLabSecurityProperties properties) {
        properties.requireComplete();
        OpaqueTokenIntrospector remote = SpringOpaqueTokenIntrospector
                .withIntrospectionUri(properties.introspectionUri().toString())
                .clientId(properties.introspectionClientId())
                .clientSecret(properties.introspectionClientSecret())
                .build();
        return new ValidatingOpaqueTokenIntrospector(
                remote,
                properties.issuer().toString(),
                properties.audience());
    }
}
