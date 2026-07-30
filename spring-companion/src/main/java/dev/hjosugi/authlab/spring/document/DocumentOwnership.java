package dev.hjosugi.authlab.spring.document;

import java.util.Map;

import org.springframework.stereotype.Component;

@Component
public class DocumentOwnership {

    private final Map<String, String> owners = Map.of(
            "budget", "alice",
            "roadmap", "bob");

    public boolean isOwner(String documentId, String subject) {
        return subject != null && subject.equals(owners.get(documentId));
    }
}
