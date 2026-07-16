#!/usr/bin/env bash
# Package Clikk for the Chrome Web Store.
# Zips ONLY runtime files — no training pipeline, no docs, no dev tools.
# Run from the repo root:  bash tools/package.sh
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=$(python3 -c "import json; print(json.load(open('manifest.json'))['version'])")
OUT="dist/clikk-v${VERSION}.zip"

mkdir -p dist
rm -f "$OUT"

zip -r "$OUT" \
  manifest.json \
  background.js \
  content.js \
  content.css \
  model.js \
  popup.html \
  popup.js \
  icons/icon16.png \
  icons/icon48.png \
  icons/icon128.png \
  model/linkguard_model_v1.json

echo
echo "package: $OUT"
unzip -l "$OUT"
