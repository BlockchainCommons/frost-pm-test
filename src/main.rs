/*!
# FROST PM Test - FROST-Controlled Provenance Mark Chain Demo

This is a demonstration binary that shows how to create FROST-controlled provenance mark chains
where a threshold group collectively controls a provenance mark chain without any single party
ever holding a master seed or key.

The demo creates a 2-of-3 FROST group and demonstrates:
1. Genesis mark creation using FROST signatures
2. Subsequent mark creation with different signer subsets
3. Chain validation using the provenance-mark crate
4. Indistinguishability from single-signer chains
*/

mod demo;

use anyhow::Result;

fn main() -> Result<()> { demo::run_demo() }
