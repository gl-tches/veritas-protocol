# VERITAS Protocol Web Demo

A browser-based demonstration of the VERITAS Protocol WASM bindings. This demo showcases identity management and safety number computation using post-quantum cryptography.

## Features

- **Wallet Management**: Password-protected wallet with lock/unlock functionality
- **Identity Creation**: Create up to 3 identities per origin (protocol limit)
- **Identity Switching**: Switch between multiple identities
- **Identity Display**: View identity hash, label, state, and expiry information
- **Safety Numbers**: Compute and display safety numbers between identities for verification
  - Numeric format for verbal comparison (60 digits)
  - QR code format for scanning

## Prerequisites

1. **Rust toolchain** (1.70+)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **wasm-pack**
   ```bash
   cargo install wasm-pack
   ```

3. **Web server** (any of these work):
   - Python: `python3 -m http.server`
   - Node.js: `npx serve`
   - VS Code: Live Server extension

## Build Instructions

### Option 1: Using the build script

```bash
# From this directory (examples/web-demo)
./build.sh
```

### Option 2: Manual build

```bash
# From the repository root
cd crates/veritas-wasm

# Build the WASM package
wasm-pack build --target web

# Copy the output to the demo directory
cp -r pkg ../../examples/web-demo/
```

## Running the Demo

1. **Build the WASM module** (see above)

2. **Start a local web server** from this directory:
   ```bash
   # Python
   python3 -m http.server 8080

   # Or Node.js
   npx serve -p 8080
   ```

3. **Open in browser**: Navigate to `http://localhost:8080`

## Usage Guide

### 1. Unlock Wallet

Enter any password to unlock or create your wallet. This password encrypts your identities locally.

> **Note**: This demo uses in-memory storage. All data is lost when you refresh the page.

### 2. Create Identities

- Click "Create Identity" to generate a new identity
- Optionally provide a label (e.g., "Personal", "Work")
- You can create up to 3 identities (protocol limit)

### 3. Switch Identities

Click on any identity in the list to switch to it. The current identity is highlighted.

### 4. Copy Identity Hash

Click the "Copy" button next to the identity hash to copy it to your clipboard. Share this hash with others so they can contact you.

### 5. Compute Safety Numbers

Safety numbers allow you to verify you're communicating with the correct person:

1. Create at least 2 identities
2. Select a peer identity from the dropdown
3. Click "Compute Safety Number"
4. Compare the numeric or QR code with your peer

Both parties will see the same safety number regardless of who computes it first.

### 6. Lock Wallet

Click "Lock Wallet" to clear the encryption key from memory. You'll need to enter your password again to access your identities.

## File Structure

```
examples/web-demo/
├── index.html      # Main HTML page
├── style.css       # Styling
├── app.js          # JavaScript application logic
├── README.md       # This file
├── build.sh        # Build script
└── pkg/            # WASM output (generated, gitignored)
    ├── veritas_wasm.js
    ├── veritas_wasm_bg.wasm
    └── ...
```

## Browser Compatibility

This demo requires a modern browser with:

- WebAssembly support
- ES6 modules support
- Crypto.getRandomValues (for secure random number generation)

**Tested browsers:**
- Chrome 90+
- Firefox 90+
- Safari 15+
- Edge 90+

## Security Notes

- **In-memory only**: This demo does not persist data. Refreshing the page loses all identities.
- **Password-derived key**: Your password is used to derive an encryption key using Argon2.
- **Post-quantum crypto**: Uses ML-KEM (Kyber) for key exchange and ML-DSA (Dilithium) for signatures.
- **Local execution**: All cryptographic operations run locally in your browser via WASM.

## Troubleshooting

### "Failed to initialize" error

Make sure you've built the WASM module:
```bash
./build.sh
```

### "Failed to load module" error

Ensure you're running a local web server. Opening `index.html` directly (file://) won't work due to CORS restrictions on ES modules.

### Slow performance on first load

The WASM module needs to be compiled by the browser on first load. Subsequent loads will be faster.

## Development

To rebuild after making changes to the Rust code:

```bash
./build.sh
```

Then refresh the browser page.

## License

MIT - See the repository LICENSE file.
