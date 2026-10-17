#!/bin/sh
# Build dist/mizar: a single executable zipapp plus SHA256SUMS.
set -eu
cd "$(dirname "$0")/.."

rm -rf build dist
mkdir build dist
cp -R src/mizar build/
find build -name __pycache__ -prune -exec rm -rf {} +

python3 -m zipapp build -m "mizar.cli:entry" \
    -p "/usr/bin/env python3" -o dist/mizar
chmod +x dist/mizar

cd dist
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum mizar > SHA256SUMS
else
    shasum -a 256 mizar > SHA256SUMS
fi
rm -rf ../build
echo "built dist/mizar"
