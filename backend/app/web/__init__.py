"""The server-rendered dashboard (docs/BUILD_SPEC.md §26 Phase 17).

Jinja2 and HTMX, replacing the Next.js scaffold. See `queries.py` for the rule
that shapes the whole thing: every number on a page is a real query, and a page
that cannot answer a question says so rather than showing a zero.
"""
