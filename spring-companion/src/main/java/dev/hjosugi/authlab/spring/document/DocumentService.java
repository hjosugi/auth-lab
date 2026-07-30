package dev.hjosugi.authlab.spring.document;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class DocumentService {

    @PreAuthorize("""
            hasAuthority('SCOPE_documents.read')
            and @documentOwnership.isOwner(#documentId, authentication.name)
            """)
    public Document read(String documentId) {
        return new Document(documentId, "educational content");
    }

    @PreAuthorize("""
            hasAuthority('SCOPE_documents.write')
            and @documentOwnership.isOwner(#documentId, authentication.name)
            """)
    public Document lock(String documentId) {
        return new Document(documentId, "locked");
    }

    public record Document(String id, String status) {
    }
}
