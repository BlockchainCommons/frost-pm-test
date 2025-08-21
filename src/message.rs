use chrono::{DateTime, Utc};
use frost_ed25519::Identifier;
use provenance_mark::ProvenanceMarkResolution;

pub const DS_GENESIS: &[u8] = b"BC:ProvMark:FROST:v1:GENESIS\0";
pub const DS_HASH:    &[u8] = b"BC:ProvMark:FROST:v1:HASH\0";
pub const DS_KDF_K0:  &[u8] = b"BC:ProvMark:FROST:v1:KDF:key0\0";
pub const DS_KDF_NXT: &[u8] = b"BC:ProvMark:FROST:v1:KDF:next\0";

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
    min_signers: u16,
    max_signers: u16,
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
    seq: u32,
    date: DateTime<Utc>,
    obj_hash: &[u8],
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DS_HASH);
    m.extend_from_slice(id); // linkLen bytes
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&(date.timestamp_millis() as u64).to_be_bytes());
    m.extend_from_slice(&(obj_hash.len() as u16).to_be_bytes());
    m.extend_from_slice(obj_hash);
    m
}
