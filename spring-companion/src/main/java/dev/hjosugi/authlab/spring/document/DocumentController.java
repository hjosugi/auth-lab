package dev.hjosugi.authlab.spring.document;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DocumentController {

    private final DocumentService documents;

    public DocumentController(DocumentService documents) {
        this.documents = documents;
    }

    @GetMapping({
            "/api/jwt/documents/{documentId}",
            "/api/opaque/documents/{documentId}"
    })
    public DocumentService.Document read(@PathVariable String documentId) {
        return documents.read(documentId);
    }

    @PostMapping({
            "/api/jwt/documents/{documentId}/lock",
            "/api/opaque/documents/{documentId}/lock"
    })
    public DocumentService.Document lock(@PathVariable String documentId) {
        return documents.lock(documentId);
    }
}
