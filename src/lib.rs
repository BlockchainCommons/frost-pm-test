/*!
# FROST PM Test Library

This library provides FROST (Flexible Round-Optimized Schnorr Threshold) signature functionality
with a focus on usability and abstraction. It includes:

- `FROSTGroupConfig` - Configuration for FROST groups with human-readable participant names
- `FROSTGroup` - A fully constituted FROST group with all key material for signing
- FROST-controlled Provenance Mark chain functionality for distributed attestation

The library abstracts away the complexity of key generation methods (trusted dealer vs DKG)
and provides a clean, high-level API for threshold signature operations and provenance mark chains.
*/

pub mod frost_group;
pub mod frost_group_config;

// FROST-controlled provenance mark modules
pub mod kdf;
pub mod message;
pub mod pm_chain;

pub use frost_group::FrostGroup;
pub use frost_group_config::FrostGroupConfig;
pub use pm_chain::{FrostPmChain, PrecommitReceipt};
