use crate::{
    FrostGroup,
    kdf::{commitments_root, kdf_next},
    message::{genesis_message, hash_message},
};
use anyhow::{Result, bail};
use bc_crypto::hkdf_hmac_sha256;
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
    pub seq: usize,
    pub root: [u8; 32],
    pub ids: Vec<Identifier>,
    pub commitments: BTreeMap<Identifier, SigningCommitments>,
}

/// Check if the candidate nextKey matches what the previous mark committed to
/// This is done by recomputing the previous mark's hash with the candidate nextKey
pub fn prev_commitment_matches(
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
    pub seq_next: usize, // next sequence to produce
    pub last_date: DateTime<Utc>,
}

#[derive(Debug)]
pub struct FrostPmChain<'g> {
    pub group: &'g FrostGroup,
    pub meta: ChainMeta,
    // For demo purposes: temporarily store the current precommit receipt
    // In a real distributed system, participants would manage this locally
    current_receipt: Option<PrecommitReceipt>,
    current_nonces: Option<BTreeMap<String, SigningNonces>>,
    // Store the last mark for chain verification
    last_mark: Option<ProvenanceMark>,
}

impl<'g> FrostPmChain<'g> {
    // Create genesis: derive key_0, precommit seq=1, then finalize Mark 0.
    pub fn new_genesis(
        group: &'g FrostGroup,
        res: ProvenanceMarkResolution,
        genesis_signers: &[&str],
        date0: DateTime<Utc>,
        _obj_hash: &[u8], // e.g., SHA-256(image)
    ) -> Result<(Self, ProvenanceMark)> {
        if genesis_signers.len() < group.min_signers() as usize {
            bail!("insufficient signers");
        }
        let ll = res.link_length();

        // 1. Derive key_0 (and thus id) with a one-time genesis signing
        // Build M0 from public group data
        let participant_names = group.participant_names();
        let ids: Vec<Identifier> = participant_names
            .iter()
            .map(|name| group.name_to_id(name).unwrap())
            .collect();
        let m0 =
            genesis_message(res, group.min_signers(), group.max_signers(), ids);

        // FROST: derive key_0 using the group's built-in signing method
        let sig0 = group.sign(&m0, genesis_signers, &mut OsRng)?;
        let key0 = hkdf_hmac_sha256(&sig0.serialize()?, &m0, ll);

        // id == key0 (genesis invariant)
        let id = key0.clone();

        // 2. Precommit for seq=1 (Round-1 only)
        // Collect SigningCommitments for seq=1 from the chosen quorum
        let mut chain = Self {
            group,
            meta: ChainMeta {
                res,
                id: id.clone(),
                seq_next: 0,
                last_date: date0,
            },
            current_receipt: None,
            current_nonces: None,
            last_mark: None,
        };

        let receipt1 = chain.precommit_next_mark(genesis_signers, 1)?;

        // Compute nextKey_0 = derive_link_from_root(res, id, 1, Root_1)
        let next_key0 = kdf_next(&id, 1, receipt1.root, res);

        // 3. Finalize M⟨0⟩ with key_0 and this nextKey_0
        let pm_date = dcbor::Date::from_timestamp(date0.timestamp() as f64);
        let mark0 = ProvenanceMark::new(
            res,
            key0,
            next_key0,
            id.clone(),
            0,
            pm_date,
            None::<String>,
        )?;

        // Store the genesis mark and update the sequence
        chain.last_mark = Some(mark0.clone());
        chain.meta.seq_next = 1;

        Ok((chain, mark0))
    }

    /// Precommit for next mark (Round-1 only)
    /// Returns a PrecommitReceipt containing the root and commitments (public, non-secret)
    /// This computes and CONSUMES nextKey_j to finalize the PREVIOUS mark (j-1).
    pub fn precommit_next_mark(
        &mut self,
        participants: &[&str],
        seq_next: usize,
    ) -> Result<PrecommitReceipt> {
        if participants.len() < self.group.min_signers() as usize {
            bail!("insufficient signers for precommit");
        }

        // 1. Collect commitments for seq_next
        // Each participant runs round1::commit and retains SigningNonces locally.
        let (commitments_map, nonces_map) = self
            .group
            .round1_commit(participants, &mut OsRng)?;

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

    /// Append the next mark using precommitted Round-1 commitments
    /// This implements the two-ceremony approach: precommit (Round-1) + append (Round-2)
    pub fn append_mark(
        &mut self,
        participants: &[&str],
        seq: usize,
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

        // 4. Verify that this key_seq matches what the previous mark committed to
        if let Some(prev_mark) = &self.last_mark {
            if !prev_commitment_matches(prev_mark, &key_seq)? {
                bail!(
                    "Chain integrity check failed: key_seq doesn't match previous mark's nextKey"
                );
            }
        }

        // 5. Build message for Round-2 signing (standard PM message format)
        let message = hash_message(&self.meta.id, seq, date, obj_hash);

        // 6. Perform Round-2 using the SAME commitments and stored nonces
        let _signature = self
            .group
            .round2_sign(participants, commitments_map, stored_nonces, &message)?;

        // 7. BEFORE finalizing this mark's hash, run precommit for seq+1 to get nextKey_seq
        let next_receipt = self.precommit_next_mark(participants, seq + 1)?;
        let next_key_seq =
            kdf_next(&self.meta.id, seq + 1, next_receipt.root, self.meta.res);

        // 8. Convert chrono::DateTime to dcbor::Date for ProvenanceMark
        let pm_date = dcbor::Date::from_timestamp(date.timestamp() as f64);

        // 9. Use key_seq and next_key_seq to create the mark
        let mark = ProvenanceMark::new(
            self.meta.res,
            key_seq,
            next_key_seq,
            self.meta.id.clone(),
            seq as u32,
            pm_date,
            None::<String>,
        )?;

        // 10. Update state and store the new mark for future verification
        self.last_mark = Some(mark.clone());
        self.meta.seq_next = seq + 1;
        self.meta.last_date = date;

        Ok(mark)
    }
}
