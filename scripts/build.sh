#!/bin/sh
# Build dist/sigma-audit: a single executable zipapp plus SHA256SUMS.
set -eu
cd "$(dirname "$0")/.."

rm -rf build dist
mkdir build dist
cp -R src/sigma_audit build/
find build -name __pycache__ -prune -exec rm -rf {} +

python3 -m zipapp build -m "sigma_audit.cli:entry" \
    -p "/usr/bin/env python3" -o dist/sigma-audit
chmod +x dist/sigma-audit

cd dist
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum sigma-audit > SHA256SUMS
else
    shasum -a 256 sigma-audit > SHA256SUMS
fi
rm -rf ../build
echo "built dist/sigma-audit"
