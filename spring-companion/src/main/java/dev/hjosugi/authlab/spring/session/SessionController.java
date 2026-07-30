package dev.hjosugi.authlab.spring.session;

import java.security.Principal;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/session")
public class SessionController {

    @GetMapping("/me")
    public Map<String, String> me(Principal principal) {
        return Map.of("subject", principal.getName());
    }

    @PostMapping("/note")
    public Map<String, String> updateNote(Principal principal) {
        return Map.of("updatedBy", principal.getName());
    }
}
