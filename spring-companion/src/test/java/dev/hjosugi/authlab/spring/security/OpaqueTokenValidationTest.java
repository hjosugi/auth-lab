package dev.hjosugi.authlab.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

class OpaqueTokenValidationTest {

    private static final String ISSUER = "https://issuer.auth-lab.test";
    private static final String AUDIENCE = "auth-lab-api";

    @Test
    void acceptsActiveAccessTokenForThisIssuerAndAudience() {
        var expected = principal(ISSUER, List.of(AUDIENCE), "access_token");
        OpaqueTokenIntrospector introspector =
                new ValidatingOpaqueTokenIntrospector(token -> expected, ISSUER, AUDIENCE);
        assertThat(introspector.introspect("opaque").getName()).isEqualTo("alice");
    }

    @Test
    void rejectsWrongIssuerAudienceAndType() {
        assertRejected(principal("https://attacker.invalid", List.of(AUDIENCE), "access_token"));
        assertRejected(principal(ISSUER, List.of("another-api"), "access_token"));
        assertRejected(principal(ISSUER, List.of(AUDIENCE), "refresh_token"));
    }

    @Test
    void preservesRemoteIntrospectionFailure() {
        OpaqueTokenIntrospector remote = token -> {
            throw new BadOpaqueTokenException("inactive");
        };
        OpaqueTokenIntrospector introspector =
                new ValidatingOpaqueTokenIntrospector(remote, ISSUER, AUDIENCE);
        assertThatThrownBy(() -> introspector.introspect("revoked"))
                .isInstanceOf(BadOpaqueTokenException.class)
                .hasMessageContaining("inactive");
    }

    private static void assertRejected(DefaultOAuth2AuthenticatedPrincipal principal) {
        OpaqueTokenIntrospector introspector =
                new ValidatingOpaqueTokenIntrospector(token -> principal, ISSUER, AUDIENCE);
        assertThatThrownBy(() -> introspector.introspect("opaque"))
                .isInstanceOf(BadOpaqueTokenException.class);
    }

    private static DefaultOAuth2AuthenticatedPrincipal principal(
            String issuer,
            List<String> audience,
            String tokenType) {
        return new DefaultOAuth2AuthenticatedPrincipal(
                "alice",
                Map.of(
                        "sub", "alice",
                        "iss", issuer,
                        "aud", audience,
                        "token_type", tokenType,
                        "scope", "documents.read"),
                List.of(new SimpleGrantedAuthority("SCOPE_documents.read")));
    }
}
