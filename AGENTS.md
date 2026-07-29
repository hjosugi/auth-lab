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
  except `docs/interview-en.md`.
- Preserve the standard-library-only runtime unless an issue explicitly creates
  an optional interoperability profile.

## Verification

Run all of the following before proposing a change:

```bash
python scripts/verify.py
node --check docs/assets/lab.js
node --check site/app.js
```

`scripts/verify.py` runs 108 tests, 13 drills, and 15 attack regressions. If
protocol behavior changes, add a success test and at least one relevant negative
test. Keep `docs/09_attack_matrix.md` and `docs/00_index.md` synchronized.
