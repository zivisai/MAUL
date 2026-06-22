#!/usr/bin/env bash
# Build the "production" front-end bundle for the source-map exposure lab.
#
# This intentionally ships BOTH the minified bundle and its source map into the
# same web-served directory — exactly the misconfiguration the lab demonstrates.
# In a real app you would set sourcemap to false (or keep .map files off the
# public web root). See README.md.
#
# Requires Node/npx (esbuild is fetched on demand; no install needed).
set -euo pipefail
cd "$(dirname "$0")"

npx --yes esbuild app.src.js \
  --bundle \
  --minify \
  --sourcemap \
  --outfile=app.min.js

echo "Built app.min.js + app.min.js.map"
echo "Note the trailing //# sourceMappingURL comment in app.min.js — that is the breadcrumb."
