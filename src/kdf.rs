use bc_crypto::sha256;
use frost_ed25519::{Identifier, round1::SigningCommitments};
use provenance_mark::ProvenanceMarkResolution;
use std::collections::BTreeMap;

/// Compute a deterministic root over Round-1 commitment map
/// This provides deterministic key derivation from commitment sets
pub fn commitments_root(
    commitments: &BTreeMap<Identifier, SigningCommitments>,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(commitments.len() * 100);

    for (id, sc) in commitments {
        // Get canonical bytes for identifier and commitments using serde+bincode
        let id_bytes = bincode::serialize(id).expect("serialize identifier");
        let sc_bytes =
            bincode::serialize(sc).expect("serialize signing commitments");

        // Add length prefixes for deterministic parsing
        buf.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(&(sc_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&sc_bytes);
    }

    sha256(&buf)
}

/// KDF for nextKey / key derivation from commitment root
/// Domain separation and binding to chain + seq
/// Returns the correct length for the given resolution
pub fn kdf_next(
    chain_id: &[u8],
    seq: u32,
    root: [u8; 32],
    res: ProvenanceMarkResolution,
) -> Vec<u8> {
    let mut msg = b"PM:v1/next".to_vec();
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(&root);
    let hash = sha256(&msg);
    // Truncate to the appropriate length for this resolution
    let len = res.link_length();
    hash[..len].to_vec()
}
