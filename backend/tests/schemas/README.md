# Vendored schemas

`sarif-schema-2.1.0.json` is the OASIS SARIF 2.1.0 JSON Schema, retrieved
2026-09-19 from:

    https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json

Vendored rather than fetched at test time for two reasons: the test suite must
not depend on network access, and a schema that can change under CI would make
a passing build unreproducible. `docs/BUILD_SPEC.md` §26 Phase 8 requires SARIF
output to validate against the 2.1.0 schema, so this is the real thing rather
than a hand-written approximation of it — an approximation would pass output
the spec rejects.
