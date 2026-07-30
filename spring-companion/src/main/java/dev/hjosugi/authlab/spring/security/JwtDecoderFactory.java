package dev.hjosugi.authlab.spring.security;

import java.time.Duration;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

public final class JwtDecoderFactory {

    private JwtDecoderFactory() {
    }

    public static NimbusJwtDecoder create(AuthLabSecurityProperties properties) {
        properties.requireComplete();
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri(properties.jwkSetUri().toString())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .validateType(false)
                .build();
        decoder.setJwtValidator(validators(properties));
        return decoder;
    }

    public static OAuth2TokenValidator<Jwt> validators(
            AuthLabSecurityProperties properties) {
        JwtTimestampValidator timestamps = new JwtTimestampValidator(Duration.ofSeconds(60));
        timestamps.setAllowEmptyExpiryClaim(false);
        JwtTypeValidator accessTokenType = new JwtTypeValidator("at+jwt");
        accessTokenType.setAllowEmpty(false);
        return new DelegatingOAuth2TokenValidator<>(
                timestamps,
                new JwtIssuerValidator(properties.issuer().toString()),
                new JwtAudienceValidator(properties.audience()),
                accessTokenType);
    }
}
