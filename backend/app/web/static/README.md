# Dashboard static files

This directory is served at `/app/static`. It is empty of third-party code on
purpose.

## HTMX is not committed here

The dashboard's templates carry `hx-get` / `hx-target` attributes and the
handlers honour the `HX-Request` header, so HTMX works if you put it here:

```bash
curl -fsSL -o backend/app/web/static/htmx.min.js \
  https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js
shasum -a 384 backend/app/web/static/htmx.min.js   # record this
```

It is not committed for two reasons, and neither is "we forgot":

1. **It is not needed.** Every dashboard page is a complete server-rendered
   document reachable by an ordinary link. HTMX only replaces a fragment
   instead of the page. With no script present the dashboard works.
2. **Vendoring a minified third-party bundle into a security product is a
   supply-chain decision**, not a convenience. Whoever adds it should be the
   person who checked its hash against a source they trust — which is also
   why there is no CDN `<script>` tag in `base.html`: that would fetch
   unpinned third-party code onto the page where findings are read.

The base template renders the `<script>` tag only when this file exists, so
adding it is the whole installation step.
