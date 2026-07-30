package dev.hjosugi.authlab.spring.security;

import java.net.URI;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth-lab.security")
public record AuthLabSecurityProperties(
        URI issuer,
        String audience,
        URI jwkSetUri,
        URI introspectionUri,
        String introspectionClientId,
        String introspectionClientSecret,
        List<String> allowedOrigins) {

    public AuthLabSecurityProperties {
        allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
    }

    public void requireComplete() {
        if (issuer == null || audience == null || audience.isBlank() || jwkSetUri == null) {
            throw new IllegalStateException(
                    "issuer, audience, and jwk-set-uri are required");
        }
        if (introspectionUri == null
                || introspectionClientId == null
                || introspectionClientSecret == null) {
            throw new IllegalStateException(
                    "opaque-token introspection endpoint and credentials are required");
        }
    }
}
