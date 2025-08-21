/*!
# FROST PM Test Library

This library provides FROST (Flexible Round-Optimized Schnorr Threshold) signature functionality
with a focus on usability and abstraction. It includes:

- `FROSTGroupConfig` - Configuration for FROST groups with human-readable participant names
- `FROSTGroup` - A fully constituted FROST group with all key material for signing

The library abstracts away the complexity of key generation methods (trusted dealer vs DKG)
and provides a clean, high-level API for threshold signature operations.
*/

pub mod frost_group;
pub mod frost_group_config;

pub use frost_group::FROSTGroup;
pub use frost_group_config::FROSTGroupConfig;
