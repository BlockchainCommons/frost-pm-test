use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use provenance_mark::ProvenanceMarkResolution;

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
pub fn hkdf_next(len: usize, sig_bytes: &[u8], salt_msg: &[u8], info: &[u8]) -> Vec<u8> {
    let salt = sha256(salt_msg);
    let hk = Hkdf::<Sha256>::new(Some(&salt), sig_bytes);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).expect("HKDF expand");
    out
}
