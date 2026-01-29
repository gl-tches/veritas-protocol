# VERITAS Architecture Guide

System architecture, design decisions, and data flow for the VERITAS Protocol.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Crate Dependency Graph](#crate-dependency-graph)
- [Component Details](#component-details)
- [Data Flow](#data-flow)
- [Network Topology](#network-topology)
- [Storage Architecture](#storage-architecture)
- [Blockchain Integration](#blockchain-integration)
- [Transport Selection](#transport-selection)

---

## Overview

VERITAS (Verified Encrypted Real-time Integrity Transmission And Signing) is a post-quantum secure, decentralized messaging protocol with blockchain verification and offline P2P capability.

### Design Principles

1. **Privacy First**: Minimize metadata exposure at all layers
2. **Post-Quantum Security**: Prepare for quantum computing threats
3. **Decentralization**: No central points of failure or control
4. **Offline Capability**: Function without continuous connectivity
5. **Verifiability**: Cryptographic proofs for all claims

### Key Features

- End-to-end encryption with forward secrecy
- Post-quantum cryptography (ML-KEM, ML-DSA)
- Metadata minimization (sender/timestamp hidden)
- Multi-transport networking (Internet, WiFi, Bluetooth)
- Blockchain-based message verification
- Reputation system with anti-gaming measures

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              APPLICATION LAYER                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        veritas-core                                  │    │
│  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐              │    │
│  │  │ VeritasClient │ │ ClientConfig  │ │ SafetyNumber  │              │    │
│  │  └───────┬───────┘ └───────────────┘ └───────────────┘              │    │
│  │          │                                                           │    │
│  │          ▼                                                           │    │
│  │  ┌───────────────────────────────────────────────────────┐          │    │
│  │  │              Internal Services                         │          │    │
│  │  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │          │    │
│  │  │  │   Identity   │ │   Message    │ │    Chain     │   │          │    │
│  │  │  │   Manager    │ │   Service    │ │   Service    │   │          │    │
│  │  │  └──────────────┘ └──────────────┘ └──────────────┘   │          │    │
│  │  │  ┌──────────────┐                                      │          │    │
│  │  │  │  Reputation  │                                      │          │    │
│  │  │  │   Service    │                                      │          │    │
│  │  │  └──────────────┘                                      │          │    │
│  │  └───────────────────────────────────────────────────────┘          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                              PROTOCOL LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐                 │
│  │veritas-protocol│  │veritas-identity│  │veritas-reputation│               │
│  │                │  │                │  │                │                 │
│  │ • Envelope     │  │ • IdentityHash │  │ • Score        │                 │
│  │ • Encryption   │  │ • KeyPair      │  │ • Rate Limiter │                 │
│  │ • Groups       │  │ • Lifecycle    │  │ • Collusion    │                 │
│  │ • Receipts     │  │ • Limits       │  │ • Reports      │                 │
│  │ • Chunking     │  │ • Username     │  │ • Decay        │                 │
│  └────────────────┘  └────────────────┘  └────────────────┘                 │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                            INFRASTRUCTURE LAYER                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐                 │
│  │  veritas-net   │  │ veritas-chain  │  │ veritas-store  │                 │
│  │                │  │                │  │                │                 │
│  │ • Transport    │  │ • Block        │  │ • EncryptedDb  │                 │
│  │ • DHT          │  │ • Merkle       │  │ • MessageQueue │                 │
│  │ • Gossip       │  │ • Validator    │  │ • Keyring      │                 │
│  │ • Discovery    │  │ • Slashing     │  │                │                 │
│  │ • Bluetooth    │  │ • Sync         │  │                │                 │
│  └────────────────┘  └────────────────┘  └────────────────┘                 │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                            CRYPTOGRAPHY LAYER                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        veritas-crypto                                │    │
│  │                                                                      │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │    │
│  │  │  Hash256 │ │Symmetric │ │  X25519  │ │  ML-KEM  │ │  ML-DSA  │  │    │
│  │  │ (BLAKE3) │ │(ChaCha20)│ │ (ECDH)   │ │  (KEM)   │ │ (Sigs)   │  │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                              BINDINGS LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐                 │
│  │  veritas-ffi   │  │  veritas-wasm  │  │  veritas-py    │                 │
│  │  (C Bindings)  │  │  (WebAssembly) │  │  (Python)      │                 │
│  └────────────────┘  └────────────────┘  └────────────────┘                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Crate Dependency Graph

```
                                 ┌─────────────┐
                                 │veritas-core │
                                 └──────┬──────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           │                            │                            │
           ▼                            ▼                            ▼
    ┌──────────────┐            ┌──────────────┐            ┌──────────────┐
    │veritas-net   │            │veritas-chain │            │veritas-store │
    └──────┬───────┘            └──────┬───────┘            └──────┬───────┘
           │                           │                           │
           │                           │                           │
           │      ┌────────────────────┼────────────────────┐      │
           │      │                    │                    │      │
           ▼      ▼                    ▼                    ▼      ▼
    ┌─────────────────┐         ┌─────────────────┐         │      │
    │veritas-protocol │         │veritas-reputation│        │      │
    └────────┬────────┘         └────────┬────────┘         │      │
             │                           │                   │      │
             └───────────┬───────────────┴───────────────────┘      │
                         │                                          │
                         ▼                                          │
                  ┌─────────────────┐                               │
                  │veritas-identity │                               │
                  └────────┬────────┘                               │
                           │                                        │
                           └──────────────┬─────────────────────────┘
                                          │
                                          ▼
                                   ┌─────────────┐
                                   │veritas-crypto│
                                   └─────────────┘


Bindings (independent):

    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │ veritas-ffi │     │veritas-wasm │     │ veritas-py  │
    └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
           │                   │                   │
           └───────────────────┴───────────────────┘
                               │
                               ▼
                        ┌─────────────┐
                        │veritas-core │
                        └─────────────┘
```

### Dependency Rules

1. **veritas-crypto**: Foundation - no internal dependencies
2. **veritas-identity**: Depends only on crypto
3. **veritas-protocol**: Depends on crypto and identity
4. **veritas-reputation**: Depends on crypto and identity
5. **veritas-store**: Depends on protocol and crypto
6. **veritas-chain**: Depends on protocol and crypto
7. **veritas-net**: Depends on protocol and reputation
8. **veritas-core**: Orchestrates all crates
9. **Bindings**: Depend only on core

---

## Component Details

### veritas-crypto

Low-level cryptographic primitives.

| Module | Purpose | Library |
|--------|---------|---------|
| `hash` | BLAKE3 hashing | blake3 |
| `symmetric` | ChaCha20-Poly1305 AEAD | chacha20poly1305 |
| `x25519` | Elliptic curve DH | x25519-dalek |
| `mlkem` | Post-quantum KEM | ml-kem (future) |
| `mldsa` | Post-quantum signatures | ml-dsa (future) |

### veritas-identity

Decentralized identity management.

| Module | Purpose |
|--------|---------|
| `identity_hash` | BLAKE3-based identity fingerprints |
| `keypair` | Exchange + signing key pairs |
| `lifecycle` | Key rotation and expiry |
| `limits` | Per-device identity limits |
| `username` | Optional username registration |

### veritas-protocol

Wire protocol and message formats.

| Module | Purpose |
|--------|---------|
| `envelope` | Minimal metadata envelope |
| `encryption` | E2E message encryption |
| `signing` | Message signatures |
| `chunking` | Large message splitting |
| `groups` | Group key management |
| `receipts` | Delivery confirmations |
| `limits` | Protocol constants |

### veritas-net

P2P networking layer.

| Module | Purpose |
|--------|---------|
| `transport` | Transport abstraction |
| `transport_manager` | Multi-transport orchestration |
| `node` | libp2p node implementation |
| `dht` | Kademlia DHT operations |
| `gossip` | GossipSub pub/sub |
| `discovery` | mDNS local discovery |
| `bluetooth` | BLE relay transport |
| `relay` | Store-and-forward |

### veritas-chain

Blockchain verification layer.

| Module | Purpose |
|--------|---------|
| `block` | Block structure |
| `chain` | Chain management |
| `merkle` | Merkle tree proofs |
| `validator` | PoS validator selection |
| `slashing` | Penalty enforcement |
| `sync` | Chain synchronization |

### veritas-store

Encrypted local storage.

| Module | Purpose |
|--------|---------|
| `encrypted_db` | Encrypted key-value store (sled) |
| `keyring` | Identity key storage |
| `message_queue` | Inbox/outbox management |

### veritas-reputation

Reputation and anti-gaming.

| Module | Purpose |
|--------|---------|
| `score` | Reputation scoring |
| `rate_limiter` | Message rate limits |
| `collusion` | Graph-based detection |
| `report` | User reporting |
| `decay` | Time-based decay |
| `effects` | Reputation consequences |

---

## Data Flow

### Sending a Message

```
┌─────────────┐
│  User App   │
└──────┬──────┘
       │ 1. send_message(recipient, "Hello")
       ▼
┌──────────────────┐
│  VeritasClient   │
│  ┌────────────┐  │
│  │  Message   │  │  2. Validate content (300 chars max)
│  │  Service   │  │
│  └─────┬──────┘  │
└────────┼─────────┘
         │
         ▼ 3. Encrypt payload
┌──────────────────┐
│ veritas-protocol │
│                  │
│  ┌────────────┐  │     ┌─────────────────────────────────────┐
│  │ InnerPayload│◄─────│ sender_id, timestamp, content, sig  │
│  └─────┬──────┘  │     └─────────────────────────────────────┘
│        │         │
│        ▼         │
│  ┌────────────┐  │     ┌─────────────────────────────────────┐
│  │MinimalEnv  │◄─────│ mailbox_key, ephemeral_pk, nonce,   │
│  │            │  │     │ ciphertext (padded)                 │
│  └─────┬──────┘  │     └─────────────────────────────────────┘
└────────┼─────────┘
         │
         ▼ 4. Select transport
┌──────────────────┐
│   veritas-net    │
│  ┌────────────┐  │
│  │ Transport  │  │  Priority: Internet > Local > BLE > Queue
│  │  Manager   │  │
│  └─────┬──────┘  │
│        │         │
│        ▼         │
│  ┌────────────┐  │
│  │  Gossip    │  │  5. Announce via GossipSub
│  │  Manager   │  │
│  └─────┬──────┘  │
└────────┼─────────┘
         │
         ▼ 6. Store for blockchain proof
┌──────────────────┐
│  veritas-chain   │
│  ┌────────────┐  │
│  │   Block    │  │  Entry: message_hash, sender, recipient
│  │   Entry    │  │
│  └────────────┘  │
└──────────────────┘
```

### Receiving a Message

```
┌──────────────────┐
│   veritas-net    │
│  ┌────────────┐  │
│  │  Gossip    │  │  1. Receive announcement
│  │  Manager   │  │
│  └─────┬──────┘  │
│        │         │
│        ▼         │
│  ┌────────────┐  │
│  │    DHT     │  │  2. Check if mailbox_key matches ours
│  │  Lookup    │  │
│  └─────┬──────┘  │
└────────┼─────────┘
         │
         ▼ 3. Retrieve encrypted envelope
┌──────────────────┐
│ veritas-protocol │
│  ┌────────────┐  │
│  │MinimalEnv  │  │  4. Derive shared secret from ephemeral_pk
│  └─────┬──────┘  │
│        │         │
│        ▼         │
│  ┌────────────┐  │
│  │ InnerPayload│  │  5. Decrypt and verify signature
│  └─────┬──────┘  │
└────────┼─────────┘
         │
         ▼
┌──────────────────┐
│  veritas-store   │
│  ┌────────────┐  │
│  │  Message   │  │  6. Store in inbox
│  │   Queue    │  │
│  └────────────┘  │
└──────────────────┘
         │
         ▼
┌──────────────────┐
│  VeritasClient   │  7. Return ReceivedMessage
└──────────────────┘
```

---

## Network Topology

```
                              ┌──────────────┐
                              │   Internet   │
                              └──────┬───────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         │                           │                           │
         ▼                           ▼                           ▼
    ┌─────────┐                 ┌─────────┐                 ┌─────────┐
    │Bootstrap│                 │Bootstrap│                 │Bootstrap│
    │  Node 1 │                 │  Node 2 │                 │  Node 3 │
    └────┬────┘                 └────┬────┘                 └────┬────┘
         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
         ┌─────────┐            ┌─────────┐            ┌─────────┐
         │Validator│            │Validator│            │Validator│
         │  Node   │◄──────────►│  Node   │◄──────────►│  Node   │
         └────┬────┘            └────┬────┘            └────┬────┘
              │                      │                      │
              │         Gossipsub + Kademlia DHT            │
              │                      │                      │
    ┌─────────┴─────────┬────────────┴────────────┬─────────┴─────────┐
    │                   │                         │                   │
    ▼                   ▼                         ▼                   ▼
┌───────┐          ┌───────┐                 ┌───────┐          ┌───────┐
│ User  │◄────────►│ User  │                 │ User  │◄────────►│ User  │
│ Node  │  mDNS    │ Node  │                 │ Node  │   BLE    │ Node  │
└───────┘  (LAN)   └───────┘                 └───────┘ (relay)  └───────┘
```

### Peer Types

| Type | Role | Requirements |
|------|------|--------------|
| Bootstrap | Initial network entry | High availability |
| Validator | Block production | 700+ reputation, 99% uptime |
| User | Send/receive messages | None |

### Discovery Methods

1. **Bootstrap Peers**: Hardcoded known-good nodes
2. **Kademlia DHT**: Distributed peer discovery
3. **mDNS**: Local network discovery
4. **Bluetooth**: Direct device discovery

---

## Storage Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        veritas-store                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                     EncryptedDb                            │  │
│  │                                                            │  │
│  │  Storage Key (Argon2id derived from password)              │  │
│  │           │                                                │  │
│  │           ▼                                                │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              sled (embedded database)                │  │  │
│  │  │                                                      │  │  │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │  │  │
│  │  │  │ keyring  │  │  inbox   │  │  outbox  │          │  │  │
│  │  │  │  (tree)  │  │  (tree)  │  │  (tree)  │          │  │  │
│  │  │  └──────────┘  └──────────┘  └──────────┘          │  │  │
│  │  │                                                      │  │  │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │  │  │
│  │  │  │  blocks  │  │ contacts │  │  groups  │          │  │  │
│  │  │  │  (tree)  │  │  (tree)  │  │  (tree)  │          │  │  │
│  │  │  └──────────┘  └──────────┘  └──────────┘          │  │  │
│  │  │                                                      │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                                                            │  │
│  │  All values encrypted with ChaCha20-Poly1305               │  │
│  │                                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │    Keyring    │  │ MessageQueue  │  │  BlockCache   │       │
│  │               │  │               │  │               │       │
│  │ • Identities  │  │ • Inbox       │  │ • Headers     │       │
│  │ • Private keys│  │ • Outbox      │  │ • Bodies      │       │
│  │ • Metadata    │  │ • Status      │  │ • Proofs      │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

Data Directory Structure:
~/.local/share/veritas/
├── db/                 # sled database files
│   ├── conf
│   ├── db
│   └── blobs/
├── cache/              # Temporary cache
└── logs/               # Application logs
```

### Encryption at Rest

All stored data is encrypted using:

1. **Key Derivation**: Argon2id (password -> storage key)
2. **Encryption**: ChaCha20-Poly1305 (per-value)
3. **Nonces**: Random per encryption operation

---

## Blockchain Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                        VERITAS Chain                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Block Structure:                                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      BlockHeader                           │  │
│  │  ┌──────────────┬──────────────┬──────────────┐           │  │
│  │  │  block_hash  │ parent_hash  │    height    │           │  │
│  │  ├──────────────┼──────────────┼──────────────┤           │  │
│  │  │  timestamp   │ merkle_root  │  validator   │           │  │
│  │  └──────────────┴──────────────┴──────────────┘           │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                       BlockBody                            │  │
│  │  ┌──────────────────────────────────────────────────────┐ │  │
│  │  │                   ChainEntry[]                        │ │  │
│  │  │  ┌────────────────┐  ┌────────────────┐              │ │  │
│  │  │  │IdentityReg    │  │ UsernameReg    │              │ │  │
│  │  │  │ • identity    │  │ • username     │              │ │  │
│  │  │  │ • public_keys │  │ • identity     │              │ │  │
│  │  │  │ • timestamp   │  │ • timestamp    │              │ │  │
│  │  │  └────────────────┘  └────────────────┘              │ │  │
│  │  │  ┌────────────────┐  ┌────────────────┐              │ │  │
│  │  │  │ MessageProof   │  │ ReputationChg  │              │ │  │
│  │  │  │ • msg_hash    │  │ • identity     │              │ │  │
│  │  │  │ • sender      │  │ • delta        │              │ │  │
│  │  │  │ • recipient   │  │ • reason       │              │ │  │
│  │  │  └────────────────┘  └────────────────┘              │ │  │
│  │  │  ┌────────────────┐  ┌────────────────┐              │ │  │
│  │  │  │ ValidatorReg   │  │ ValidatorSlash │              │ │  │
│  │  │  │ • identity    │  │ • identity     │              │ │  │
│  │  │  │ • stake       │  │ • reason       │              │ │  │
│  │  │  │ • region      │  │ • amount       │              │ │  │
│  │  │  └────────────────┘  └────────────────┘              │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Merkle Tree:                                                   │
│                        ┌────────┐                                │
│                        │  Root  │                                │
│                        └───┬────┘                                │
│                    ┌───────┴───────┐                             │
│                    ▼               ▼                             │
│               ┌────────┐     ┌────────┐                          │
│               │ H(A+B) │     │ H(C+D) │                          │
│               └───┬────┘     └───┬────┘                          │
│               ┌───┴───┐      ┌───┴───┐                           │
│               ▼       ▼      ▼       ▼                           │
│            ┌────┐  ┌────┐ ┌────┐  ┌────┐                         │
│            │ A  │  │ B  │ │ C  │  │ D  │  (Chain Entries)        │
│            └────┘  └────┘ └────┘  └────┘                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Validator Selection (PoS)

```
Selection Weight = stake * performance_multiplier * sla_bonus

Where:
  stake = reputation staked (min 700)
  performance_multiplier = 0.5 + (performance_score / 100)  [0.5-1.5]
  sla_bonus = compliant ? (1.0 + streak * 0.05).min(0.5) : 0.7
```

### Slashing Penalties

| Offense | Penalty |
|---------|---------|
| Missed block | 0.1% per block |
| SLA violation | 1% per violation |
| Invalid block | 5% |
| Double sign | 100% + permanent ban |

---

## Transport Selection

### Priority Order

```
┌─────────────────────────────────────────────────────────────────┐
│                     Transport Selection                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Check Internet ──────────────────► Available? ──► USE IT    │
│         │                                   │                    │
│         │ No                                │                    │
│         ▼                                   │                    │
│  2. Check Local WiFi ────────────────► Available? ──► USE IT    │
│         │                                   │                    │
│         │ No                                │                    │
│         ▼                                   │                    │
│  3. Check Bluetooth ─────────────────► Available? ──► USE IT    │
│         │                                   │                    │
│         │ No                                │                    │
│         ▼                                   │                    │
│  4. Queue Locally ───────────────────► Store for later          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Transport Characteristics

| Transport | Latency | Reliability | Privacy | Notes |
|-----------|---------|-------------|---------|-------|
| Internet | Low | High | Medium | Primary transport |
| Local WiFi | Low | Medium | High | mDNS discovery |
| Bluetooth | High | Low | Medium | Pure relay, no PIN |
| Queue | N/A | N/A | High | Offline storage |

### Bluetooth Relay Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     Bluetooth Relay                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Offline Device A                    Internet-Connected B        │
│  ┌─────────────┐                     ┌─────────────┐            │
│  │   VERITAS   │                     │   VERITAS   │            │
│  │   Client    │                     │   Client    │            │
│  └──────┬──────┘                     └──────┬──────┘            │
│         │                                   │                    │
│         │ BLE                               │ Internet           │
│         │ (encrypted message)               │                    │
│         ▼                                   │                    │
│  ┌─────────────┐                           │                    │
│  │   Relay     │ ─────────────────────────►│                    │
│  │   Node      │   Forward to network      │                    │
│  └─────────────┘                           ▼                    │
│                                      ┌─────────────┐            │
│  Key Points:                         │   Network   │            │
│  • NO PIN verification               └─────────────┘            │
│  • NO pairing required                                          │
│  • Security from E2E encryption                                 │
│  • Any VERITAS node can relay                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## See Also

- [API Documentation](API.md) - Complete API reference
- [Security Guide](SECURITY.md) - Threat model and cryptographic design
- [Setup Guide](SETUP.md) - Installation and configuration
