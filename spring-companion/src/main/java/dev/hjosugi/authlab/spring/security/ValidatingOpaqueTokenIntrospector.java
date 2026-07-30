package dev.hjosugi.authlab.spring.security;

import java.util.Collection;

import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

public final class ValidatingOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector delegate;
    private final String issuer;
    private final String audience;

    public ValidatingOpaqueTokenIntrospector(
            OpaqueTokenIntrospector delegate,
            String issuer,
            String audience) {
        this.delegate = delegate;
        this.issuer = issuer;
        this.audience = audience;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
        if (!issuer.equals(principal.<String>getAttribute("iss"))) {
            throw new BadOpaqueTokenException("opaque token issuer mismatch");
        }
        Object rawAudience = principal.getAttribute("aud");
        boolean audienceMatches = rawAudience instanceof Collection<?> audiences
                ? audiences.contains(audience)
                : audience.equals(rawAudience);
        if (!audienceMatches) {
            throw new BadOpaqueTokenException("opaque token audience mismatch");
        }
        if (!"access_token".equals(principal.<String>getAttribute("token_type"))) {
            throw new BadOpaqueTokenException("opaque token type must be access_token");
        }
        return principal;
    }
}
