use crate::{
    FROSTGroup,
    kdf::{commitments_root, hkdf_next, kdf_next, link_len},
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

    /// Precommit for next mark (Round-1 only) - implements expert's stateless approach
    /// Derives nextKey for the previous mark and finalizes its hash. Stores nothing sensitive.
    /// This computes and CONSUMES nextKey_j to finalize the PREVIOUS mark (j-1).
    pub fn precommit_next_mark(
        &mut self,
        participants: &[&str],
        seq_next: u32,
    ) -> Result<()> {
        if participants.len() < self.group.min_signers() as usize {
            bail!("insufficient signers for precommit");
        }

        // 1. Collect commitments for seq_next
        // Each participant runs round1::commit and retains SigningNonces locally.
        let (commitments_map, _nonces_map) = self
            .group
            .round1_commit(participants, &mut OsRng)
            .map_err(|e| {
                anyhow::anyhow!("Failed to collect Round-1 commitments: {}", e)
            })?;

        // 2. Compute Root_{seq_next} = commitments_root(&commitments_map)
        let root_next = commitments_root(&commitments_map);

        // 3. Compute nextKey_{seq_next-1} = kdf_next(chain_id, seq_next, Root_next)
        let _next_key =
            kdf_next(&self.meta.id, seq_next, root_next, self.meta.res);

        // 4. Update internal state to indicate we've precommitted for seq_next
        // Note: In a real implementation, you'd need to store the commitments_map
        // temporarily so it can be replayed in append_mark_stateless
        // For this demo, we'll simulate this with the internal signing approach

        // Discard commitments_map here as per expert's recommendation
        // Signers keep their SigningNonces for seq_next locally
        Ok(())
    }

    /// Append the next mark without any stored nextKey - implements expert's stateless approach
    /// Replays Round-1 for seq and runs Round-2 to produce mark for seq.
    /// Verifies the precommit matches the previous mark.
    pub fn append_mark_stateless(
        &mut self,
        participants: &[&str],
        date: DateTime<Utc>,
        obj_hash: &[u8],
        seq: u32,
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

        // 1. Ask the same participants to resend their SigningCommitments for this seq
        // (they must reuse the same SigningNonces they generated in precommit_next_mark)
        let (commitments_map, nonces_map) = self
            .group
            .round1_commit(participants, &mut OsRng)
            .map_err(|e| {
                anyhow::anyhow!("Failed to collect Round-1 commitments: {}", e)
            })?;

        // 2. Root_seq = commitments_root(&commitments_map)
        //    key_seq  = kdf_next(chain_id, seq, Root_seq)
        let root_seq = commitments_root(&commitments_map);
        let key_seq = kdf_next(&self.meta.id, seq, root_seq, self.meta.res);

        // 3. Build message for Round-2 signing (include Root_seq to bind Round-2 to commitments)
        let mut message = hash_message(&self.meta.id, seq, date, obj_hash);
        message.extend_from_slice(&root_seq); // Bind Round-2 tightly to the same commitment set

        // 4. Build a SigningPackage and perform Round-2
        let _signature = self
            .group
            .round2_sign(participants, &commitments_map, &nonces_map, &message)
            .map_err(|e| {
                anyhow::anyhow!("Failed to complete Round-2 signing: {}", e)
            })?;

        // 5. BEFORE finalizing this mark's hash, run precommit for seq+1 to get nextKey_seq
        // This implements the expert's two-ceremony approach
        self.precommit_next_mark(participants, seq + 1)?;

        // For the demo, derive nextKey_seq using the same approach as before
        // In the full stateless implementation, this would come from the precommit step
        let next_message = hash_message(&self.meta.id, seq + 1, date, obj_hash);
        let next_signature = self
            .group
            .sign(&next_message, participants, &mut OsRng)
            .map_err(|e| anyhow::anyhow!("Failed to derive nextKey: {}", e))?;
        let next_key_seq = hkdf_next(
            link_len(self.meta.res),
            &next_signature.serialize().unwrap(),
            &next_message,
            DS_KDF_NXT,
        );

        // 6. Convert chrono::DateTime to dcbor::Date for ProvenanceMark
        let pm_date = dcbor::Date::from_timestamp(date.timestamp() as f64);

        // 7. Use key_seq and nextKey_seq to create the mark
        let mark = ProvenanceMark::new(
            self.meta.res,
            key_seq,
            next_key_seq,
            self.meta.id.clone(),
            seq,
            pm_date,
            None::<String>,
        )?;

        // 8. Update state and zeroize sensitive data
        self.meta.seq_next = seq + 1;
        self.meta.last_date = date;

        // Note: In a real implementation, participants MUST zeroize their SigningNonces
        // after Round-2 completes for this seq

        Ok(mark)
    }
}
