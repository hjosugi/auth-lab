package dev.hjosugi.authlab.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

class JwtValidationTest {

    private static final String ISSUER = "https://issuer.auth-lab.test";
    private static final String AUDIENCE = "auth-lab-api";

    private final OAuth2TokenValidator<Jwt> validator =
            JwtDecoderFactory.validators(properties());

    @Test
    void acceptsExpectedIssuerAudienceTypeAndLifetime() {
        assertThat(validator.validate(jwt(ISSUER, AUDIENCE, "at+jwt")).hasErrors())
                .isFalse();
    }

    @Test
    void rejectsWrongIssuer() {
        assertThat(validator.validate(
                jwt("https://attacker.invalid", AUDIENCE, "at+jwt")).hasErrors())
                .isTrue();
    }

    @Test
    void rejectsWrongAudience() {
        assertThat(validator.validate(
                jwt(ISSUER, "another-api", "at+jwt")).hasErrors())
                .isTrue();
    }

    @Test
    void rejectsIdTokenTypeAtTheApi() {
        assertThat(validator.validate(jwt(ISSUER, AUDIENCE, "JWT")).hasErrors())
                .isTrue();
    }

    @Test
    void rejectsExpiredToken() {
        Instant now = Instant.now();
        Jwt expired = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .header("typ", "at+jwt")
                .issuer(ISSUER)
                .audience(List.of(AUDIENCE))
                .subject("alice")
                .issuedAt(now.minusSeconds(600))
                .expiresAt(now.minusSeconds(120))
                .build();
        assertThat(validator.validate(expired).hasErrors()).isTrue();
    }

    private static Jwt jwt(String issuer, String audience, String type) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .header("typ", type)
                .issuer(issuer)
                .audience(List.of(audience))
                .subject("alice")
                .issuedAt(now.minusSeconds(5))
                .expiresAt(now.plusSeconds(300))
                .claim("scope", "documents.read")
                .build();
    }

    static AuthLabSecurityProperties properties() {
        return new AuthLabSecurityProperties(
                URI.create(ISSUER),
                AUDIENCE,
                URI.create("https://issuer.auth-lab.test/jwks"),
                URI.create("https://issuer.auth-lab.test/introspect"),
                "resource",
                "secret",
                List.of("https://app.auth-lab.test"));
    }
}
