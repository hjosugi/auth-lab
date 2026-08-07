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

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
