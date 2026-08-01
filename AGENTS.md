# Agent instructions

## Mission

Keep this repository a safe, dependency-free, executable learning lab for
authentication and authorization. Code should expose protocol state and trust
bindings instead of hiding them behind a framework.

## Boundaries

- Treat `authlab/` cryptography and protocol code as educational, not
  production-ready.
- Do not add real credentials, target external systems, or turn negative tests
  into exploitation tooling.
- Local attack regressions are expected and allowed when they prove that a
  dangerous input is rejected.
- Code comments and identifiers are English. Learner-facing prose is Japanese,
  except `docs/12_interview_english.md`, which is deliberately English because
  it is a script for answering these questions in an English interview.
- Preserve the standard-library-only runtime unless an issue explicitly creates
  an optional interoperability profile.

## Verification

Run all of the following before proposing a change. This list mirrors what
`.github/workflows/ci.yml` enforces; a shorter local run will pass while CI
fails.

```bash
# Python: unittest suite, every drill, every attack regression, property/fuzz
python scripts/verify.py

# Browser JavaScript: syntax, unit tests, and the real-browser ceremonies
for f in docs/assets/lab.js docs/assets/pyodide-lab.js \
         docs/assets/pyodide-policy.js docs/assets/pyodide-worker.js \
         docs/assets/sequences.js docs/assets/webauthn-lab.js site/app.js; do
  node --check "$f"
done
node --test tests/browser/*.test.js
node tests/browser/webauthn-e2e.mjs
node tests/browser/interop-gui-e2e.mjs

# Documentation site: fails on any broken internal link
pip install -r requirements-docs.txt
python -m mkdocs build --strict
```

`python scripts/build_pyodide_bundle.py` then `node tests/browser/pyodide-e2e.mjs`
covers the browser Python path, and `mvn --batch-mode --file spring-companion/pom.xml
verify` covers the Java companion; run those when you touch either.

`scripts/verify.py` prints the counts it actually ran rather than asserting a
number here -- a hard-coded total in this file goes stale the moment a drill or
a regression is added, which is what `tests/test_repo_docs.py` now guards.

If protocol behavior changes, add a success test and at least one relevant
negative test. Keep `docs/09_attack_matrix.md` and `docs/00_index.md`
synchronized.

Documentation is built by MkDocs (`mkdocs.yml`). Two consequences worth
remembering. First, a page is published at its name without the extension, so
`docs/03_saml.md` becomes `/03_saml/` and the `.md` file itself is not served --
a link spelled with the extension from the static `docs/index.html` would 404,
because MkDocs rewrites links inside Markdown but not inside static files.
Second, links to source files must be absolute GitHub URLs: a relative path out
of `docs/` resolves in the repository view but not on the site.
`tests/test_docs_site.py` enforces both.
