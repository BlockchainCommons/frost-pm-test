use crate::{
    FROSTGroup,
    kdf::{hkdf_next, link_len},
    message::{DS_KDF_K0, DS_KDF_NXT, genesis_message, hash_message},
};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use frost_ed25519::Identifier;
use provenance_mark::{ProvenanceMark, ProvenanceMarkResolution};
use rand::rngs::OsRng;

// Holds public chain metadata for the demo
#[derive(Clone, Debug)]
pub struct ChainMeta {
    pub res: ProvenanceMarkResolution,
    pub id: Vec<u8>,   // == key_0
    pub seq_next: u32, // next sequence to produce
    pub last_date: DateTime<Utc>,
}

// A convenience wrapper to build FROST-controlled PM chains
#[derive(Debug)]
pub struct FrostPmChain<'g> {
    pub group: &'g FROSTGroup,
    pub meta: ChainMeta,
}

impl<'g> FrostPmChain<'g> {
    // Create genesis: run one FROST session for key_0, one for nextKey_0, then build Mark 0.
    pub fn new_genesis(
        group: &'g FROSTGroup,
        res: ProvenanceMarkResolution,
        genesis_signers: &[&str],
        date0: DateTime<Utc>,
        obj_hash: &[u8], // e.g., SHA-256(image)
    ) -> Result<(Self, ProvenanceMark, Vec<u8>)> {
        if genesis_signers.len() < group.min_signers() as usize {
            bail!("insufficient signers");
        }
        let ll = link_len(res);

        // Build M0 from public group data
        let participant_names = group.participant_names();
        let ids: Vec<Identifier> = participant_names
            .iter()
            .map(|name| group.name_to_id(name).unwrap())
            .collect();
        let m0 =
            genesis_message(res, group.min_signers(), group.max_signers(), ids);

        // FROST: derive key_0 using the group's built-in signing method
        let sig0 =
            group.sign(&m0, genesis_signers, &mut OsRng).map_err(|e| {
                anyhow::anyhow!("Failed to sign genesis message: {}", e)
            })?;
        let key0 = hkdf_next(ll, &sig0.serialize()?, &m0, DS_KDF_K0);

        // id == key0 (genesis invariant)
        let id = key0.clone();

        // Per-mark signing for nextKey_0:
        let m_hash0 = hash_message(&id, 0, date0, obj_hash);
        let sig_hash0 = group
            .sign(&m_hash0, genesis_signers, &mut OsRng)
            .map_err(|e| {
                anyhow::anyhow!("Failed to sign hash message: {}", e)
            })?;
        let next_key0 =
            hkdf_next(ll, &sig_hash0.serialize()?, &m_hash0, DS_KDF_NXT);

        // Convert chrono::DateTime to dcbor::Date for ProvenanceMark
        let pm_date = dcbor::Date::from_timestamp(date0.timestamp() as f64);

        // Build mark 0 (no info)
        let mark0 = ProvenanceMark::new(
            res,
            key0,
            next_key0.clone(),
            id.clone(),
            0,
            pm_date,
            None::<String>,
        )?; // uses PM crate logic for hash/truncation

        let meta = ChainMeta { res, id, seq_next: 1, last_date: date0 };
        Ok((Self { group, meta }, mark0, next_key0))
    }

    // Append one mark: reveal previous nextKey as key_i, sign M_i to derive nextKey_i.
    pub fn append_mark_with_key(
        &mut self,
        signers: &[&str],
        date: DateTime<Utc>,
        obj_hash: &[u8],
        key_i: Vec<u8>, // == previous nextKey
        seq_i: u32,     // normally self.meta.seq_next
    ) -> Result<(ProvenanceMark, Vec<u8>)> {
        if signers.len() < self.group.min_signers() as usize {
            bail!("insufficient signers");
        }
        if date < self.meta.last_date {
            bail!("date monotonicity violated");
        }
        let ll = link_len(self.meta.res);

        // Derive nextKey_i from FROST over M_i
        let m_hash_i = hash_message(&self.meta.id, seq_i, date, obj_hash);
        let sig_i =
            self.group
                .sign(&m_hash_i, signers, &mut OsRng)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to sign hash message: {}", e)
                })?;
        let next_key_i =
            hkdf_next(ll, &sig_i.serialize()?, &m_hash_i, DS_KDF_NXT);

        // Convert chrono::DateTime to dcbor::Date for ProvenanceMark
        let pm_date = dcbor::Date::from_timestamp(date.timestamp() as f64);

        let mark_i = ProvenanceMark::new(
            self.meta.res,
            key_i.clone(),
            next_key_i.clone(),
            self.meta.id.clone(),
            seq_i,
            pm_date,
            None::<String>,
        )?;

        self.meta.seq_next = seq_i + 1;
        self.meta.last_date = date;
        Ok((mark_i, next_key_i))
    }
}
