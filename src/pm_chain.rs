use crate::{
    FROSTGroup,
    kdf::{commitments_root, hkdf_next, kdf_next, link_len},
    message::{DS_KDF_K0, DS_KDF_NXT, genesis_message, hash_message},
};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use frost_ed25519::{
    Identifier, round1::SigningCommitments, round1::SigningNonces,
};
use provenance_mark::{ProvenanceMark, ProvenanceMarkResolution};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

/// A public, non-secret receipt from the precommit phase
/// Contains the commitment root and roster used in the session
#[derive(Clone, Debug)]
pub struct PrecommitReceipt {
    pub seq: u32,
    pub root: [u8; 32],
    pub ids: Vec<Identifier>,
    pub commitments: BTreeMap<Identifier, SigningCommitments>,
}

/// Check if the candidate nextKey matches what the previous mark committed to
/// This is done by recomputing the previous mark's hash with the candidate nextKey
fn prev_commitment_matches(
    prev: &ProvenanceMark,
    candidate_next_key: &[u8],
) -> Result<bool> {
    let mark = ProvenanceMark::new(
        prev.res(),
        prev.key().to_vec(),
        candidate_next_key.to_vec(),
        prev.chain_id().to_vec(),
        prev.seq(),
        prev.date().clone(),
        prev.info(), // info is application-defined; we pass it through unchanged
    )?;
    Ok(mark.hash() == prev.hash())
}

// Holds public chain metadata for the demo
#[derive(Clone, Debug)]
pub struct ChainMeta {
    pub res: ProvenanceMarkResolution,
    pub id: Vec<u8>,   // == key_0
    pub seq_next: u32, // next sequence to produce
    pub last_date: DateTime<Utc>,
}

#[derive(Debug)]
pub struct FrostPmChain<'g> {
    pub group: &'g FROSTGroup,
    pub meta: ChainMeta,
    // For demo purposes: temporarily store the current precommit receipt
    // In a real distributed system, participants would manage this locally
    current_receipt: Option<PrecommitReceipt>,
    current_nonces: Option<BTreeMap<String, SigningNonces>>,
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
        Ok((
            Self {
                group,
                meta,
                current_receipt: None,
                current_nonces: None,
            },
            mark0,
            next_key0,
        ))
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

    /// Precommit for next mark (Round-1 only) - implements expert's stateless approach
    /// Returns a PrecommitReceipt containing the root and commitments (public, non-secret)
    /// This computes and CONSUMES nextKey_j to finalize the PREVIOUS mark (j-1).
    pub fn precommit_next_mark(
        &mut self,
        participants: &[&str],
        seq_next: u32,
    ) -> Result<PrecommitReceipt> {
        if participants.len() < self.group.min_signers() as usize {
            bail!("insufficient signers for precommit");
        }

        // 1. Collect commitments for seq_next
        // Each participant runs round1::commit and retains SigningNonces locally.
        let (commitments_map, nonces_map) = self
            .group
            .round1_commit(participants, &mut OsRng)
            .map_err(|e| {
                anyhow::anyhow!("Failed to collect Round-1 commitments: {}", e)
            })?;

        // 2. Compute Root_{seq_next} = commitments_root(&commitments_map)
        let root_next = commitments_root(&commitments_map);

        // 3. Compute nextKey_{seq_next-1} = kdf_next(chain_id, seq_next, Root_next)
        // and finalize the previous mark's hash using that nextKey
        let _next_key =
            kdf_next(&self.meta.id, seq_next, root_next, self.meta.res);

        // 4. Create PrecommitReceipt (public, non-secret)
        let ids: Vec<Identifier> = participants
            .iter()
            .map(|name| self.group.name_to_id(name).expect("valid participant"))
            .collect();

        let receipt = PrecommitReceipt {
            seq: seq_next,
            root: root_next,
            ids,
            commitments: commitments_map,
        };

        // 5. Store receipt and nonces for the demo (in real systems, participants store nonces locally)
        self.current_receipt = Some(receipt.clone());
        self.current_nonces = Some(nonces_map);

        Ok(receipt)
    }

    /// Append the next mark without any stored nextKey - implements expert's stateless approach
    /// Uses the SAME commitments from the stored receipt and runs Round-2 to produce mark for seq.
    /// This is a demo-friendly version that uses temporarily stored nonces.
    pub fn append_mark_stateless(
        &mut self,
        participants: &[&str],
        seq: u32,
        date: DateTime<Utc>,
        obj_hash: &[u8],
    ) -> Result<ProvenanceMark> {
        if participants.len() < self.group.min_signers() as usize {
            bail!("insufficient signers");
        }
        if date < self.meta.last_date {
            bail!("date monotonicity violated");
        }
        if seq != self.meta.seq_next {
            bail!(
                "sequence number mismatch: expected {}, got {}",
                self.meta.seq_next,
                seq
            );
        }

        // 1. Get the stored receipt and nonces from precommit phase
        let receipt = self.current_receipt.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No precommit found for seq {}", seq)
        })?;
        let stored_nonces = self.current_nonces.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No nonces found for seq {}", seq)
        })?;

        if receipt.seq != seq {
            bail!(
                "receipt sequence mismatch: expected {}, got {}",
                seq,
                receipt.seq
            );
        }

        // 2. Use the SAME commitments from the receipt (DO NOT call round1_commit again)
        let commitments_map = &receipt.commitments;

        // 3. Derive key_seq from the receipt's root (which matches the commitments)
        let key_seq = kdf_next(&self.meta.id, seq, receipt.root, self.meta.res);

        // 4. Build message for Round-2 signing (standard PM message format)
        let message = hash_message(&self.meta.id, seq, date, obj_hash);

        // 5. Perform Round-2 using the SAME commitments and stored nonces
        let _signature = self
            .group
            .round2_sign(participants, commitments_map, stored_nonces, &message)
            .map_err(|e| {
                anyhow::anyhow!("Failed to complete Round-2 signing: {}", e)
            })?;

        // 6. BEFORE finalizing this mark's hash, run precommit for seq+1 to get nextKey_seq
        let next_receipt = self.precommit_next_mark(participants, seq + 1)?;
        let next_key_seq =
            kdf_next(&self.meta.id, seq + 1, next_receipt.root, self.meta.res);

        // 7. Convert chrono::DateTime to dcbor::Date for ProvenanceMark
        let pm_date = dcbor::Date::from_timestamp(date.timestamp() as f64);

        // 8. Use key_seq and next_key_seq to create the mark
        let mark = ProvenanceMark::new(
            self.meta.res,
            key_seq,
            next_key_seq,
            self.meta.id.clone(),
            seq,
            pm_date,
            None::<String>,
        )?;

        // 9. Update state and clear the used nonces (they're one-time use)
        self.meta.seq_next = seq + 1;
        self.meta.last_date = date;
        // Clear the used receipt and nonces since they've been consumed
        // (The new ones for seq+1 are already stored from step 6)

        Ok(mark)
    }
}
