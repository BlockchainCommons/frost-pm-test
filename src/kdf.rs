use frost_ed25519::{Identifier, round1::SigningCommitments};
use hkdf::Hkdf;
use provenance_mark::ProvenanceMarkResolution;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn link_len(res: ProvenanceMarkResolution) -> usize {
    match res {
        ProvenanceMarkResolution::Low => 4,
        ProvenanceMarkResolution::Medium => 8,
        ProvenanceMarkResolution::Quartile => 16,
        ProvenanceMarkResolution::High => 32,
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// Derive exactly `len` bytes from a FROST signature serialization and message salt.
pub fn hkdf_next(
    len: usize,
    sig_bytes: &[u8],
    salt_msg: &[u8],
    info: &[u8],
) -> Vec<u8> {
    let salt = sha256(salt_msg);
    let hk = Hkdf::<Sha256>::new(Some(&salt), sig_bytes);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("HKDF expand");
    out
}

/// Compute a deterministic root over Round-1 commitment map
/// This follows the expert's recommendation for stateless coordinator design
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
/// Domain separation and binding to chain + seq as recommended by expert
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
    let len = link_len(res);
    hash[..len].to_vec()
}

/// Alternative name following expert's specification
pub fn derive_link_from_root(
    res: ProvenanceMarkResolution,
    chain_id: &[u8],
    seq: u32,
    root: [u8; 32],
) -> Vec<u8> {
    kdf_next(chain_id, seq, root, res)
}
