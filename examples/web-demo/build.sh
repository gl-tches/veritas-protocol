#!/bin/bash
# VERITAS Protocol Web Demo - Build Script
#
# This script builds the WASM package and copies it to the demo directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WASM_CRATE="$REPO_ROOT/crates/veritas-wasm"
DEMO_DIR="$SCRIPT_DIR"

echo "=== VERITAS Protocol Web Demo Build ==="
echo ""

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "Error: wasm-pack is not installed."
    echo "Install it with: cargo install wasm-pack"
    exit 1
fi

# Build WASM package
echo "Building WASM package..."
cd "$WASM_CRATE"
wasm-pack build --target web

# Copy to demo directory
echo "Copying WASM package to demo directory..."
rm -rf "$DEMO_DIR/pkg"
cp -r "$WASM_CRATE/pkg" "$DEMO_DIR/"

echo ""
echo "=== Build complete! ==="
echo ""
echo "To run the demo:"
echo "  cd $DEMO_DIR"
echo "  python3 -m http.server 8080"
echo ""
echo "Then open http://localhost:8080 in your browser."
