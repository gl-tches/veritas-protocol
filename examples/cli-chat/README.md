# VERITAS CLI Chat Example

A simple command-line chat application demonstrating the VERITAS protocol API.

## Overview

This example showcases the core features of the VERITAS protocol:

- **Identity Management**: Create and manage cryptographic identities
- **Contact Management**: Store contacts by identity hash with human-readable names
- **Safety Numbers**: Verify contacts using cryptographic safety numbers
- **Message Sending**: Queue messages for sending (simulated in this demo)

## Building

```bash
# From the project root
cd examples/cli-chat

# Debug build
cargo build

# Release build (recommended)
cargo build --release
```

## Running

```bash
# From the examples/cli-chat directory
cargo run --release

# Or run directly
./target/release/veritas-chat
```

### Environment Variables

- `RUST_LOG`: Control logging verbosity (e.g., `RUST_LOG=debug`)

## Usage

Once the application starts, you'll see a command prompt. Type commands to interact with the chat system.

### Available Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `/identity` | `/id` | Show your identity hash and public keys |
| `/contacts` | `/c` | List all contacts |
| `/add <hash> <name>` | `/a` | Add a new contact by identity hash |
| `/remove <name>` | `/rm` | Remove a contact |
| `/msg <name> <message>` | `/m` | Send a message to a contact |
| `/safety <name>` | `/s` | Show safety number for contact verification |
| `/verify <name>` | `/v` | Mark a contact as verified |
| `/status` | - | Show application status |
| `/help` | `/h` | Show help message |
| `/quit` | `/q` | Exit the application |

### Example Session

```
> /identity
Your Identity
-------------
  Hash:       a1b2c3d4e5f67890...
  Short:      a1b2c3d4e5f67890...
  Exchange:   32 bytes

Identity Slots
--------------
  Used:       1/3
  Available:  2

> /add b1c2d3e4f5a67890... Alice
[OK] Added contact 'Alice'

> /contacts
Contacts (1)

  Alice
    b1c2d3e4f5a67890...

> /safety Alice
Safety Number for 'Alice'
------------------------

  Compare this number with your contact:

    12345  67890  12345  67890
    12345  67890  12345  67890
    12345  67890  12345  67890

QR Code Data
------------
  a1b2c3d4e5f67890...

[INFO] Use /verify <name> to mark this contact as verified.

> /verify Alice
[OK] Contact 'Alice' marked as verified

> /msg Alice Hello, how are you?
[OK] Message queued (id: 1) to 'Alice': Hello, how are you?
[WARN] Note: Message sending is simulated in this demo.

> /quit
[INFO] Goodbye!
```

## Data Storage

The application stores data in a platform-specific directory:

- **Linux**: `~/.local/share/veritas-chat/`
- **macOS**: `~/Library/Application Support/veritas-chat/`
- **Windows**: `C:\Users\<User>\AppData\Roaming\veritas-chat\`

### Files

- `contacts.json`: Your contact list

## Identity Hash

Every VERITAS user has a unique identity hash - a 64-character hexadecimal string derived from their public key. This hash is:

- **Unique**: No two users have the same hash
- **Shareable**: Safe to share publicly
- **Permanent**: Tied to your cryptographic identity

To add a contact, you need their identity hash. Share your hash via:
- QR code
- Secure messaging
- In person

## Safety Numbers

Safety numbers allow you to verify that you're communicating with the right person:

1. Both parties compute a safety number using each other's public keys
2. The safety number is identical for both parties
3. Compare the number out-of-band (in person, phone call, etc.)
4. If they match, mark the contact as verified

This protects against man-in-the-middle attacks.

## Limitations

This is a demonstration application with some limitations:

- **No actual network**: Messages are queued locally but not sent
- **Simulated safety numbers**: Uses generated keypairs for demonstration
- **Single identity**: Only uses the primary identity
- **No encryption demo**: The actual encryption happens in veritas-core

## Code Structure

```
src/main.rs
    |
    +-- Contact/ContactStore: Contact management and persistence
    |
    +-- MessageQueue: Simulated message queue
    |
    +-- ChatApp: Main application state and logic
    |
    +-- Command handlers: cmd_identity, cmd_contacts, etc.
    |
    +-- Terminal helpers: Colored output functions
```

## Integration Points

This example demonstrates usage of:

- `veritas_core::VeritasClient`: Main client API
- `veritas_core::SafetyNumber`: Safety number computation
- `veritas_core::ClientConfig`: Client configuration
- `veritas_identity::IdentityHash`: Identity hash type
- `veritas_identity::IdentityKeyPair`: Key pair management

## Security Notes

1. **Demo Password**: This example uses a hardcoded password for simplicity. In production, always prompt the user for a secure password.

2. **Contact Verification**: Always verify contacts using safety numbers before sending sensitive information.

3. **Identity Backup**: In production, implement identity backup and recovery mechanisms.

## License

MIT OR Apache-2.0 (same as VERITAS Protocol)
