# VCL Protocol (Verified Commit Link)

Cryptographically chained packet transport protocol.

## What is VCL?

VCL is a transport protocol where each packet cryptographically links to the previous one, creating an immutable chain of data transmission.

## Features

- Packet-level integrity (SHA-256)
- Cryptographic signatures (Ed25519)
- Chain validation (each packet references previous hash)
- UDP-based (low latency)
- Tamper-evident

## Quick Start

cargo run

## Architecture

Packet N -> hash -> Packet N+1 -> hash -> Packet N+2

## Use Cases

- Secure financial transactions
- Anti-cheat game networking
- Audit-logged communications

## License

MIT
