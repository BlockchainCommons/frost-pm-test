use dcbor::{CBOREncodable, Date};
use frost_ed25519::Identifier;
use provenance_mark::ProvenanceMarkResolution;

// Domain separation tags
pub const DS_GENESIS: &[u8] = b"DS_GENESIS\0";
pub const DS_HASH: &[u8] = b"DS_HASH\0";

pub fn res_code(res: ProvenanceMarkResolution) -> u8 {
    match res {
        ProvenanceMarkResolution::Low => 0,
        ProvenanceMarkResolution::Medium => 1,
        ProvenanceMarkResolution::Quartile => 2,
        ProvenanceMarkResolution::High => 3,
    }
}

pub fn genesis_message(
    res: ProvenanceMarkResolution,
    min_signers: usize,
    max_signers: usize,
    mut ids: Vec<Identifier>,
) -> Vec<u8> {
    // Canonical order by serialized bytes:
    ids.sort_by(|a, b| a.serialize().cmp(&b.serialize()));
    let mut m = Vec::new();
    m.extend_from_slice(DS_GENESIS);
    m.push(res_code(res));
    m.extend_from_slice(&min_signers.to_be_bytes());
    m.extend_from_slice(&max_signers.to_be_bytes());
    m.extend_from_slice(&(ids.len() as u16).to_be_bytes());
    for id in ids {
        let ser = id.serialize();
        m.extend_from_slice(&(ser.len() as u16).to_be_bytes());
        m.extend_from_slice(&ser);
    }
    m
}

pub fn hash_message(
    id: &[u8],
    seq: usize,
    date: Date,
    obj_hash: &[u8],
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DS_HASH);
    m.extend_from_slice(id); // linkLen bytes
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&(date.to_cbor_data()));
    m.extend_from_slice(&(obj_hash.len() as u16).to_be_bytes());
    m.extend_from_slice(obj_hash);
    m
}
