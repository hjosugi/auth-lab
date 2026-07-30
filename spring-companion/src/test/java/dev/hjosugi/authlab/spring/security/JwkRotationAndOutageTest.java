package dev.hjosugi.authlab.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

class JwkRotationAndOutageTest {

    private static final String ISSUER = "https://metadata-outage.auth-lab.test";
    private static final String AUDIENCE = "auth-lab-api";

    private HttpServer server;
    private AtomicReference<RSAKey> publishedKey;
    private AtomicBoolean unavailable;
    private AtomicInteger requests;
    private URI jwkSetUri;

    @BeforeEach
    void startJwkEndpoint() throws IOException {
        publishedKey = new AtomicReference<>();
        unavailable = new AtomicBoolean();
        requests = new AtomicInteger();
        server = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/jwks", exchange -> {
            requests.incrementAndGet();
            if (unavailable.get()) {
                exchange.sendResponseHeaders(503, -1);
                exchange.close();
                return;
            }
            byte[] body = new JWKSet(publishedKey.get().toPublicJWK())
                    .toString()
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        jwkSetUri = URI.create(
                "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks");
    }

    @AfterEach
    void stopJwkEndpoint() {
        server.stop(0);
    }

    @Test
    void startsDuringMetadataOutageUsesCachedKeyAndRefreshesOnRotation()
            throws Exception {
        RSAKey first = new RSAKeyGenerator(2048).keyID("key-1").generate();
        RSAKey second = new RSAKeyGenerator(2048).keyID("key-2").generate();
        publishedKey.set(first);

        NimbusJwtDecoder decoder = JwtDecoderFactory.create(properties());

        // Factory creation must not discover metadata. The issuer host is
        // intentionally unreachable; only the explicit JWK Set URI is used.
        assertThat(requests).hasValue(0);
        assertThat(decoder.decode(token(first, "alice")).getSubject())
                .isEqualTo("alice");
        assertThat(requests).hasValue(1);

        unavailable.set(true);
        assertThat(decoder.decode(token(first, "alice-cached")).getSubject())
                .isEqualTo("alice-cached");
        assertThat(requests).hasValue(1);
        assertThatThrownBy(() -> decoder.decode(token(second, "unknown-during-outage")))
                .isInstanceOf(JwtException.class);

        unavailable.set(false);
        publishedKey.set(second);
        assertThat(decoder.decode(token(second, "alice-rotated")).getSubject())
                .isEqualTo("alice-rotated");
        assertThat(requests.get()).isGreaterThanOrEqualTo(3);
    }

    private AuthLabSecurityProperties properties() {
        return new AuthLabSecurityProperties(
                URI.create(ISSUER),
                AUDIENCE,
                jwkSetUri,
                URI.create("https://metadata-outage.auth-lab.test/introspect"),
                "resource",
                "secret",
                List.of("https://app.auth-lab.test"));
    }

    private static String token(RSAKey key, String subject) throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject(subject)
                .issueTime(Date.from(now.minusSeconds(5)))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("scope", "documents.read")
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(key.getKeyID())
                        .type(new JOSEObjectType("at+jwt"))
                        .build(),
                claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }
}
