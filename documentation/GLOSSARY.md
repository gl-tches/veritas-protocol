# VERITAS Glossary

Terms, concepts, and abbreviations used in VERITAS.

## A

### AEAD
**Authenticated Encryption with Associated Data**. Encryption that provides both confidentiality and integrity. VERITAS uses ChaCha20-Poly1305 AEAD.

### Argon2id
A password hashing algorithm used in VERITAS for key derivation. Combines Argon2i (side-channel resistant) and Argon2d (GPU resistant).

## B

### BLAKE3
A cryptographic hash function used in VERITAS for hashing, key derivation, and MACs. Fast and secure.

### Block
A unit of data in the VERITAS blockchain containing transactions and chain entries.

### Bootstrap Node
An initial peer used to discover other nodes in the network. New nodes connect to bootstrap nodes first.

### BLE (Bluetooth Low Energy)
A wireless technology used for local message relay when internet connectivity is unavailable.

## C

### ChaCha20-Poly1305
A symmetric encryption algorithm (ChaCha20) combined with a MAC (Poly1305). Used for message encryption.

### Chain Entry
A record stored on the VERITAS blockchain, such as identity registration, message proof, or reputation change.

### Constant-Time Comparison
Comparing values in a way that takes the same time regardless of the data, preventing timing attacks.

## D

### DHT (Distributed Hash Table)
A decentralized lookup system. VERITAS uses Kademlia DHT for peer discovery and message routing.

### Domain Separation
Adding unique prefixes to cryptographic operations to prevent cross-protocol attacks.

## E

### E2E (End-to-End) Encryption
Encryption where only the communicating users can read the messages. VERITAS provides E2E encryption by default.

### Envelope
The outer wrapper of a VERITAS message. Contains the mailbox key and encrypted payload but hides sender identity.

### Ephemeral Key
A temporary key generated for a single message. Provides forward secrecy.

### Epoch
A time period (typically 24 hours) used for mailbox key rotation and other time-based operations.

## F

### Forward Secrecy
A property where compromise of long-term keys doesn't compromise past session keys. Achieved using ephemeral keys.

### Fuzz Testing
Automated testing that provides random/unexpected inputs to find bugs and vulnerabilities.

## G

### Gossipsub
A pub/sub protocol used for message announcements. Part of libp2p.

### Group Key
A symmetric key shared among group members for encrypting group messages.

## H

### Hash256
VERITAS's 256-bit hash type based on BLAKE3.

### Health Check
An HTTP endpoint that returns the node's operational status.

## I

### Identity Hash
A 32-byte unique identifier derived from a user's public key using BLAKE3.

### Identity Limit
Maximum number of identities per device (3 in VERITAS).

## K

### Kademlia
A distributed hash table protocol used for peer discovery.

### Key Rotation
The process of replacing cryptographic keys. Identity keys rotate every 30 days.

### Keyring
Encrypted storage for identity keys and credentials.

## L

### libp2p
A modular network stack used by VERITAS for peer-to-peer communication.

## M

### Mailbox Key
A derived key used to route messages to recipients without revealing their identity.

### mDNS
Multicast DNS. Used for discovering peers on the local network.

### Merkle Proof
A cryptographic proof that a piece of data is part of a Merkle tree.

### Merkle Tree
A tree of hashes used to efficiently verify data integrity. Used in blockchain.

### ML-DSA (Module-Lattice Digital Signature Algorithm)
A post-quantum digital signature algorithm. VERITAS will use ML-DSA-65 once stable.

### ML-KEM (Module-Lattice Key Encapsulation Mechanism)
A post-quantum key encapsulation algorithm. VERITAS will use ML-KEM-768 once stable.

### Multiaddr
Multi-address format used by libp2p. Example: `/ip4/192.168.1.1/tcp/9000`

## N

### Noise Protocol
A cryptographic handshake protocol used for secure P2P connections.

### Nonce
A number used once. Used in encryption to ensure unique ciphertexts.

## O

### Origin Fingerprint
A privacy-preserving device identifier used for identity limiting.

## P

### Padding
Adding extra bytes to messages to hide their true size. VERITAS pads to fixed buckets (256, 512, 1024 bytes).

### Peer ID
A unique identifier for a node derived from its public key.

### Post-Quantum
Cryptography resistant to attacks from quantum computers. VERITAS is post-quantum ready.

### Primary Identity
The currently active identity when multiple identities exist.

### Property Test
A test that verifies properties hold for arbitrary inputs using random data generation.

## Q

### Quarantine
A reputation state where users can send but with restrictions. Triggered at reputation ≤ 200.

## R

### Relay Mode
Node mode where the node forwards messages for other peers.

### Reputation Score
A number (0-1000) representing a user's trustworthiness. Starts at 500.

### Receipt
Confirmation that a message was delivered or read.

## S

### Safety Number
A verification code computed from two users' public keys. Used to verify identities out-of-band.

### Slashing
Penalty for validator misbehavior. Can result in stake loss.

### SLA (Service Level Agreement)
Validator performance requirements. 99% uptime required.

### Store-and-Forward
Mechanism to store messages for offline recipients and forward when they connect.

### Sybil Attack
Creating multiple fake identities to gain unfair influence. Mitigated by identity limits.

## T

### Timing Jitter
Random delays (0-3 seconds) added to messages to prevent traffic analysis.

### TTL (Time To Live)
How long messages are stored. VERITAS uses 7 days.

## V

### Validator
A node that participates in blockchain consensus. Requires 700+ reputation.

### Validator Set
The group of active validators (max 21).

## W

### WASM (WebAssembly)
A binary format for running code in browsers. VERITAS provides WASM bindings.

## X

### X25519
An elliptic curve Diffie-Hellman key exchange algorithm. Used for classical key exchange.

### XChaCha20-Poly1305
Extended-nonce version of ChaCha20-Poly1305 with 192-bit nonces.

## Z

### Zeroization
Securely overwriting sensitive data in memory when no longer needed.

---

## Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_MESSAGE_CHARS` | 300 | Maximum message length |
| `MAX_CHUNKS` | 3 | Maximum chunks per message |
| `MESSAGE_TTL` | 7 days | Message expiry time |
| `KEY_EXPIRY` | 30 days | Identity key expiry |
| `KEY_WARNING` | 5 days | Days before expiry to warn |
| `MAX_IDENTITIES_PER_ORIGIN` | 3 | Identity limit per device |
| `REPUTATION_START` | 500 | Starting reputation score |
| `REPUTATION_MAX` | 1000 | Maximum reputation |
| `REPUTATION_QUARANTINE` | 200 | Quarantine threshold |
| `MIN_VALIDATOR_STAKE` | 700 | Minimum reputation to validate |
| `MAX_VALIDATORS` | 21 | Maximum active validators |
| `PADDING_BUCKETS` | 256, 512, 1024 | Message padding sizes |
| `MAX_JITTER_MS` | 3000 | Maximum timing jitter |

## See Also

- [Architecture](../docs/ARCHITECTURE.md) - System design
- [Security](../docs/SECURITY.md) - Security design
- [API Reference](../docs/API.md) - API documentation
