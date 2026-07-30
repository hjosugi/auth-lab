package dev.hjosugi.authlab.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.opaqueToken;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityChainsTest {

    private static final String ALLOWED_ORIGIN = "https://app.auth-lab.local";

    @Autowired
    private MockMvc mvc;

    @Test
    void jwtApiRequiresScopeAndObjectOwnership() throws Exception {
        mvc.perform(get("/api/jwt/documents/budget")
                        .with(jwt()
                                .jwt(token -> token.subject("alice"))
                                .authorities(scope("documents.read"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("budget"));

        mvc.perform(get("/api/jwt/documents/budget")
                        .with(jwt()
                                .jwt(token -> token.subject("alice"))
                                .authorities(scope("another.scope"))))
                .andExpect(status().isForbidden());

        mvc.perform(get("/api/jwt/documents/budget")
                        .with(jwt()
                                .jwt(token -> token.subject("bob"))
                                .authorities(scope("documents.read"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void opaqueApiUsesTheSameMethodSecurityBoundary() throws Exception {
        mvc.perform(get("/api/opaque/documents/budget")
                        .with(opaqueToken()
                                .attributes(attributes -> attributes.put("sub", "alice"))
                                .authorities(scope("documents.read"))))
                .andExpect(status().isOk());

        mvc.perform(get("/api/opaque/documents/budget")
                        .with(opaqueToken()
                                .attributes(attributes -> attributes.put("sub", "bob"))
                                .authorities(scope("documents.read"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void statelessBearerApiDoesNotNeedCsrfOrCreateASession() throws Exception {
        var result = mvc.perform(post("/api/jwt/documents/budget/lock")
                        .with(jwt()
                                .jwt(token -> token.subject("alice"))
                                .authorities(scope("documents.write"))))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test
    void oidcBrowserSessionKeepsCsrfProtection() throws Exception {
        mvc.perform(get("/session/me")
                        .with(oidcLogin().idToken(token -> token.subject("alice"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("alice"));

        mvc.perform(post("/session/note")
                        .with(oidcLogin().idToken(token -> token.subject("alice"))))
                .andExpect(status().isForbidden());

        mvc.perform(post("/session/note")
                        .with(oidcLogin().idToken(token -> token.subject("alice")))
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    @Test
    void corsAllowsOnlyTheConfiguredOrigin() throws Exception {
        mvc.perform(options("/api/jwt/documents/budget")
                        .header("Origin", ALLOWED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN));

        mvc.perform(options("/api/jwt/documents/budget")
                        .header("Origin", "https://attacker.invalid")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    private static SimpleGrantedAuthority scope(String scope) {
        return new SimpleGrantedAuthority("SCOPE_" + scope);
    }
}
