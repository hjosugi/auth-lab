package dev.hjosugi.authlab.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;

class OidcValidationTest {

    private static final String CLIENT_ID = "auth-lab-web";

    @Test
    void acceptsExpectedIssuerAndClientAudience() {
        assertThat(OidcDecoderFactory.validators(properties(), registration())
                .validate(idToken(
                        "https://issuer.auth-lab.test",
                        List.of(CLIENT_ID)))
                .hasErrors())
                .isFalse();
    }

    @Test
    void rejectsWrongIssuerEvenWithoutMetadataDiscovery() {
        assertThat(OidcDecoderFactory.validators(properties(), registration())
                .validate(idToken(
                        "https://attacker.invalid",
                        List.of(CLIENT_ID)))
                .hasErrors())
                .isTrue();
    }

    @Test
    void rejectsTokenIssuedForAnotherClient() {
        assertThat(OidcDecoderFactory.validators(properties(), registration())
                .validate(idToken(
                        "https://issuer.auth-lab.test",
                        List.of("another-client")))
                .hasErrors())
                .isTrue();
    }

    private static Jwt idToken(String issuer, List<String> audience) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .issuer(issuer)
                .subject("alice")
                .audience(audience)
                .issuedAt(now.minusSeconds(5))
                .expiresAt(now.plusSeconds(300))
                .build();
    }

    private static ClientRegistration registration() {
        return ClientRegistration.withRegistrationId("authlab")
                .clientId(CLIENT_ID)
                .clientSecret("fixture-only")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile")
                .authorizationUri("https://issuer.auth-lab.test/authorize")
                .tokenUri("https://issuer.auth-lab.test/token")
                .jwkSetUri("https://issuer.auth-lab.test/jwks")
                .userInfoUri("https://issuer.auth-lab.test/userinfo")
                .userNameAttributeName("sub")
                .clientName("auth-lab")
                .build();
    }

    private static AuthLabSecurityProperties properties() {
        return JwtValidationTest.properties();
    }
}
