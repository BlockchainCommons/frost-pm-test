/*!
# FROST PM Test Library

This library provides FROST (Flexible Round-Optimized Schnorr Threshold) signature functionality
with a focus on usability and abstraction. It includes:

- `GroupConfig` - Configuration for FROST groups with human-readable participant names
- `Group` - A fully constituted FROST group with all key material for signing

The library abstracts away the complexity of key generation methods (trusted dealer vs DKG)
and provides a clean, high-level API for threshold signature operations.
*/

pub mod group_config;
pub mod group;

pub use group_config::GroupConfig;
pub use group::Group;
