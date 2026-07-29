# Claude repository guide

Read `AGENTS.md` first and follow it as the repository-wide source of truth.

This is an educational authentication and authorization lab. Local token
tampering, replay, origin mismatch, assertion wrapping, and policy bypass tests
are defensive regression tests. They must stay self-contained and target only
the code in this repository.

When implementing:

1. Name the asset and trust boundary.
2. Make every binding check visible in code.
3. Reject unsafe defaults.
4. Add normal and negative tests.
5. Mark teaching primitives as non-production.
6. Run the complete verification commands from `AGENTS.md`.

