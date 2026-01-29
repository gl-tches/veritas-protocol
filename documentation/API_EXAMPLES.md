# VERITAS API Examples

Practical code examples for using the VERITAS API.

## Table of Contents

- [Getting Started](#getting-started)
- [Client Lifecycle](#client-lifecycle)
- [Identity Management](#identity-management)
- [Messaging](#messaging)
- [Safety Numbers](#safety-numbers)
- [Groups](#groups)
- [Error Handling](#error-handling)
- [Advanced Usage](#advanced-usage)

## Getting Started

### Add Dependencies

```toml
[dependencies]
veritas-core = "0.1.0-rc.1"
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

### Basic Setup

```rust
use veritas_core::VeritasClient;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create an in-memory client (for testing)
    let client = VeritasClient::in_memory().await?;

    // Unlock with password
    client.unlock(b"my_secure_password").await?;

    // Your code here...

    // Lock when done
    client.lock().await?;

    Ok(())
}
```

## Client Lifecycle

### Creating a Client

```rust
use veritas_core::{VeritasClient, ClientConfigBuilder};
use std::path::PathBuf;

// Option 1: In-memory client (for testing)
let client = VeritasClient::in_memory().await?;

// Option 2: Persistent client with custom path
let config = ClientConfigBuilder::new()
    .with_data_dir(PathBuf::from("./my-veritas-data"))
    .build();
let client = VeritasClient::new(config).await?;

// Option 3: Client with full configuration
let config = ClientConfigBuilder::new()
    .with_data_dir(PathBuf::from("/var/lib/veritas"))
    .enable_internet()
    .enable_local_discovery()
    .disable_bluetooth()
    .with_bootstrap_peer("peer1.veritas.network:9000".into())
    .with_connection_timeout(Duration::from_secs(60))
    .build();
let client = VeritasClient::new(config).await?;
```

### Unlock/Lock Operations

```rust
// Unlock the client
client.unlock(b"my_password").await?;

// Check if unlocked
if client.is_unlocked().await {
    println!("Client is unlocked");
}

// Get current state
match client.state().await {
    ClientState::Unlocked => println!("Ready to use"),
    ClientState::Locked => println!("Needs to be unlocked"),
    _ => println!("Other state"),
}

// Lock the client (zeroizes sensitive data)
client.lock().await?;

// Shutdown (clean termination)
client.shutdown().await?;
```

### Password Management

```rust
// First-time unlock creates the password
client.unlock(b"initial_password").await?;

// Subsequent unlocks must use the same password
client.unlock(b"initial_password").await?;

// Wrong password returns error
match client.unlock(b"wrong_password").await {
    Ok(_) => println!("Unlocked"),
    Err(e) => println!("Failed: {}", e),
}
```

## Identity Management

### Creating Identities

```rust
// Create identity with label
let hash = client.create_identity(Some("Alice")).await?;
println!("Created identity: {}", hash);

// Create identity without label
let hash2 = client.create_identity(None).await?;

// Maximum 3 identities per device
let hash3 = client.create_identity(Some("Third")).await?;

// Fourth identity will fail
match client.create_identity(Some("Fourth")).await {
    Ok(_) => unreachable!(),
    Err(e) => println!("Expected error: {}", e),
}
```

### Identity Information

```rust
// Get current identity hash
let hash = client.identity_hash().await?;
println!("My identity: {}", hash);

// Get public keys (shareable)
let public_keys = client.public_keys().await?;
println!("Public keys: {} bytes", public_keys.len());

// List all identities
let identities = client.list_identities().await?;
for identity in identities {
    println!(
        "Identity: {} (label: {:?}, primary: {})",
        identity.hash,
        identity.label,
        identity.is_primary
    );
}
```

### Identity Slots

```rust
// Check available slots
let slots = client.identity_slots().await?;
println!("Used: {}/{}", slots.used, slots.max);
println!("Available: {}", slots.available);

if slots.can_create() {
    println!("Can create more identities");
}
```

### Switching Primary Identity

```rust
// Create multiple identities
let id1 = client.create_identity(Some("Primary")).await?;
let id2 = client.create_identity(Some("Secondary")).await?;

// Check current primary
let current = client.identity_hash().await?;
println!("Current primary: {}", current);

// Switch primary
client.set_primary_identity(&id2).await?;
println!("Switched to: {}", id2);
```

## Messaging

### Sending Messages

```rust
use veritas_core::{SendOptions, MessageHash};

// Get recipient's identity hash (shared out-of-band)
let recipient = IdentityHash::from_hex("abc123...")?;

// Send a simple message
let hash = client.send_message(&recipient, "Hello!").await?;
println!("Message sent: {}", hash);

// Send with options
let options = SendOptions::default()
    .request_receipt()
    .with_timing_jitter();

let hash = client.send_message_with_options(&recipient, "Hi!", options).await?;
```

### Receiving Messages

```rust
// Receive all pending messages
let messages = client.receive_messages().await?;

for msg in messages {
    println!("From: {}", msg.sender);
    println!("Text: {}", msg.text().unwrap_or("(no text)"));
    println!("Time: {}", msg.timestamp);
    println!("Verified: {}", msg.signature_verified);
    println!("---");
}
```

### Message Status

```rust
use veritas_core::MessageStatus;

// Get status of a sent message
let status = client.message_status(&message_hash).await?;

match status {
    MessageStatus::Pending => println!("Waiting to send"),
    MessageStatus::Sending => println!("Currently sending"),
    MessageStatus::Sent => println!("Sent to network"),
    MessageStatus::Delivered => println!("Delivered to recipient"),
    MessageStatus::Read => println!("Read by recipient"),
    MessageStatus::Failed(reason) => println!("Failed: {}", reason),
}
```

### Delivery Receipts

```rust
// Check if message has receipt
if msg.is_receipt() {
    let receipt = msg.receipt().unwrap();
    println!("Receipt for: {}", receipt.message_hash);
    println!("Type: {:?}", receipt.receipt_type);
}

// Listen for receipts
client.on_receipt(|receipt| {
    println!("Received receipt for: {}", receipt.message_hash);
});
```

## Safety Numbers

Safety numbers allow users to verify they're communicating with the correct person.

### Computing Safety Numbers

```rust
use veritas_core::SafetyNumber;

// Get your public keys
let my_keys = client.public_keys().await?;

// Get contact's public keys (from their client)
let their_keys = contact_public_keys;

// Compute safety number
let safety = SafetyNumber::compute(&my_keys, &their_keys)?;

// Display formats
println!("Numeric (for voice): {}", safety.to_numeric_string());
// Output: 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890

println!("QR code (for scanning): {}", safety.to_qr_string());
// Output: 64-character hex string
```

### Verifying Safety Numbers

```rust
// Both parties compute the same safety number
let alice_safety = SafetyNumber::compute(&alice_keys, &bob_keys)?;
let bob_safety = SafetyNumber::compute(&bob_keys, &alice_keys)?;

// They should be identical (symmetric)
assert_eq!(alice_safety.to_numeric_string(), bob_safety.to_numeric_string());

// Users verify by:
// 1. Reading the numeric digits to each other (voice call)
// 2. Scanning each other's QR codes (in person)
// 3. Comparing displayed numbers on both devices
```

## Groups

### Creating Groups

```rust
use veritas_core::{GroupId, GroupRole};

// Create a group
let group_id = client.create_group("Family Chat").await?;
println!("Created group: {}", group_id);

// Get group info
let info = client.group_info(&group_id).await?;
println!("Group: {}", info.name);
println!("Members: {}", info.member_count);
```

### Managing Members

```rust
// Add member (requires Admin role)
client.add_group_member(&group_id, &new_member_hash, GroupRole::Member).await?;

// Remove member
client.remove_group_member(&group_id, &member_hash).await?;

// Change role
client.set_member_role(&group_id, &member_hash, GroupRole::Moderator).await?;

// List members
let members = client.group_members(&group_id).await?;
for member in members {
    println!("{}: {:?}", member.identity_hash, member.role);
}
```

### Group Messaging

```rust
// Send message to group
let hash = client.send_group_message(&group_id, "Hello everyone!").await?;

// Receive group messages
let messages = client.receive_group_messages(&group_id).await?;
for msg in messages {
    println!("[{}] {}: {}", msg.group_id, msg.sender, msg.text);
}
```

## Error Handling

### Basic Error Handling

```rust
use veritas_core::CoreError;

match client.unlock(b"password").await {
    Ok(_) => println!("Success"),
    Err(CoreError::InvalidPassword) => println!("Wrong password"),
    Err(CoreError::AlreadyUnlocked) => println!("Already unlocked"),
    Err(e) => println!("Other error: {}", e),
}
```

### Result Type Alias

```rust
use veritas_core::Result;

async fn my_function(client: &VeritasClient) -> Result<()> {
    let hash = client.create_identity(Some("Test")).await?;
    Ok(())
}
```

### Error Types

```rust
use veritas_core::CoreError;

// Common errors
match result {
    Err(CoreError::NotUnlocked) => {
        println!("Client must be unlocked first");
    }
    Err(CoreError::IdentityLimitReached { max, used }) => {
        println!("Identity limit reached: {}/{}", used, max);
    }
    Err(CoreError::IdentityNotFound { hash }) => {
        println!("Identity not found: {}", hash);
    }
    Err(CoreError::MessageTooLong { max, actual }) => {
        println!("Message too long: {} > {}", actual, max);
    }
    Err(e) => {
        println!("Error: {}", e);
    }
    Ok(v) => {
        // Success
    }
}
```

## Advanced Usage

### Custom Configuration

```rust
use veritas_core::{ClientConfigBuilder, StorageConfig, NetworkConfig};
use std::time::Duration;

let config = ClientConfigBuilder::new()
    // Storage configuration
    .with_data_dir(PathBuf::from("/var/lib/veritas"))
    .with_encrypted_database()

    // Network configuration
    .enable_internet()
    .enable_local_discovery()
    .disable_bluetooth()
    .with_connection_timeout(Duration::from_secs(60))
    .with_bootstrap_peers(vec![
        "/dns4/peer1.veritas.network/tcp/9000".into(),
        "/dns4/peer2.veritas.network/tcp/9000".into(),
    ])

    // Feature configuration
    .enable_timing_jitter()
    .enable_receipts()
    .with_max_queued_messages(5000)

    .build_validated()?;

let client = VeritasClient::new(config).await?;
```

### Concurrent Operations

```rust
use tokio::sync::Mutex;
use std::sync::Arc;

// Wrap client for concurrent access
let client = Arc::new(Mutex::new(client));

// Spawn multiple tasks
let client_clone = client.clone();
let handle1 = tokio::spawn(async move {
    let client = client_clone.lock().await;
    client.receive_messages().await
});

let client_clone = client.clone();
let handle2 = tokio::spawn(async move {
    let client = client_clone.lock().await;
    client.send_message(&recipient, "Hello").await
});

// Wait for both
let (messages, send_result) = tokio::join!(handle1, handle2);
```

### Using with async-std

```rust
// VERITAS uses tokio, but can integrate with async-std via compatibility layers
// See tokio documentation for details
```

### WASM Usage (JavaScript)

```javascript
import init, { WasmClient, WasmSafetyNumber } from './veritas_wasm.js';

async function main() {
    await init();

    // Create client
    const client = new WasmClient();

    // Unlock
    await client.unlock("my_password");

    // Create identity
    const hash = await client.create_identity("Alice");
    console.log("Identity:", hash);

    // Get public keys
    const keys = await client.get_public_keys();

    // Compute safety number
    const safety = WasmSafetyNumber.compute(keys, otherKeys);
    console.log("Safety number:", safety.to_numeric_string());

    // Lock when done
    await client.lock();
}

main();
```

### Python Usage

```python
from veritas import VeritasClient, SafetyNumber

# Create client
client = VeritasClient()

# Unlock
client.unlock("my_password")

# Create identity
hash = client.create_identity("Alice")
print(f"Identity: {hash}")

# Get public keys
keys = client.public_keys()

# Compute safety number
safety = SafetyNumber.compute(keys, other_keys)
print(f"Safety number: {safety.to_numeric_string()}")

# Lock when done
client.lock()
```

## See Also

- [API Reference](../docs/API.md) - Complete API documentation
- [Architecture](../docs/ARCHITECTURE.md) - System design
- [Security](../docs/SECURITY.md) - Security considerations
