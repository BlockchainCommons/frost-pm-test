use crate::{
    FrostGroup,
    kdf::{commitments_root, kdf_next},
    message::{genesis_message, hash_message},
};
use anyhow::{Result, bail};
use bc_crypto::{hkdf_hmac_sha256, sha256};
use dcbor::{CBOREncodable, Date};
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

#[derive(Debug)]
pub struct FrostPmChain {
    group: FrostGroup,
    last_mark: ProvenanceMark,
}

impl FrostPmChain {
    /// Get the resolution from the last mark
    fn res(&self) -> ProvenanceMarkResolution {
        self.last_mark.res()
    }

    /// Get the chain ID from the last mark
    fn chain_id(&self) -> &[u8] {
        self.last_mark.chain_id()
    }

    /// Get the next sequence number for the chain
    fn next_seq(&self) -> usize {
        self.last_mark.seq() as usize + 1
    }

    // Create genesis: derive key_0, precommit seq=1, then finalize Mark 0.
    // Returns the chain, genesis mark, and initial precommit data for seq=1
    pub fn new_genesis(
        group: FrostGroup,
        res: ProvenanceMarkResolution,
        signers: &[&str],
        date: Date,
        info: Option<impl CBOREncodable>,
    ) -> Result<(
        Self,
        ProvenanceMark,
        PrecommitReceipt,
        BTreeMap<String, SigningNonces>,
    )> {
        if signers.len() < group.min_signers() as usize {
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
        let sig_0 = group.sign(&m0, signers, &mut OsRng)?;

        // Verify signature
        assert!(group.verify(&m0, &sig_0).is_ok());

        let key_0 = hkdf_hmac_sha256(&sig_0.serialize()?, &m0, ll);

        // id == key_0 (genesis invariant)
        let id = key_0.clone();

        // 2. Precommit for seq=1 (Round-1 only)
        // Collect SigningCommitments for seq=1 from the chosen quorum
        // We need to create a temporary chain-like structure for this operation
        let (commitments_map, nonces_map) =
            group.round1_commit(signers, &mut OsRng)?;

        // Compute Root_1 = commitments_root(&commitments_map)
        let root_next = commitments_root(&commitments_map);

        let receipt1 = PrecommitReceipt {
            seq: 1,
            root: root_next,
            ids: signers
                .iter()
                .map(|name| group.name_to_id(name).expect("valid participant"))
                .collect(),
            commitments: commitments_map.clone(),
        };

        // Compute nextKey_0 = derive_link_from_root(res, id, 1, Root_1)
        let next_key0 = kdf_next(&id, 1, receipt1.root, res);

        // 3. Finalize M⟨0⟩ with key_0 and this nextKey_0
        let mark0 = ProvenanceMark::new(
            res,
            key_0,
            next_key0,
            id.clone(),
            0,
            date.clone(),
            info,
        )?;

        // 4. Create the chain with the genesis mark
        let chain = Self { group, last_mark: mark0.clone() };

        Ok((chain, mark0, receipt1, nonces_map))
    }

    /// Precommit for next mark (Round-1 only)
    /// Returns a PrecommitReceipt and nonces for later use in Round-2
    /// In a real distributed system, participants would manage nonces locally
    pub fn precommit_next_mark(
        &mut self,
        signers: &[&str],
        next_seq: usize,
        chain_id: &[u8],
        res: ProvenanceMarkResolution,
    ) -> Result<(PrecommitReceipt, BTreeMap<String, SigningNonces>)> {
        if signers.len() < self.group.min_signers() as usize {
            bail!("insufficient signers for precommit");
        }

        // 1. Collect commitments for next_seq
        // Each participant runs round1::commit and retains SigningNonces locally.
        let (commitments_map, nonces_map) =
            self.group.round1_commit(signers, &mut OsRng)?;

        // 2. Compute Root_{next_seq} = commitments_root(&commitments_map)
        let root_next = commitments_root(&commitments_map);

        // 3. Compute nextKey_{next_seq-1} = kdf_next(chain_id, next_seq, Root_next)
        // and finalize the previous mark's hash using that nextKey
        let _next_key = kdf_next(chain_id, next_seq, root_next, res);

        // 4. Create PrecommitReceipt (public, non-secret)
        let ids: Vec<Identifier> = signers
            .iter()
            .map(|name| self.group.name_to_id(name).expect("valid participant"))
            .collect();

        let receipt = PrecommitReceipt {
            seq: next_seq,
            root: root_next,
            ids,
            commitments: commitments_map,
        };

        // 5. Return both receipt and nonces for the application to manage
        Ok((receipt, nonces_map))
    }

    /// Append the next mark using precommitted Round-1 commitments
    /// This implements the two-ceremony approach: precommit (Round-1) + append (Round-2)
    /// Takes the receipt and nonces returned from precommit_next_mark
    /// Returns the new mark and the precommit data for the next round
    pub fn append_mark(
        &mut self,
        signers: &[&str],
        date: Date,
        info: Option<impl CBOREncodable>,
        receipt: &PrecommitReceipt,
        nonces: &BTreeMap<String, SigningNonces>,
    ) -> Result<(
        ProvenanceMark,
        PrecommitReceipt,
        BTreeMap<String, SigningNonces>,
    )> {
        if signers.len() < self.group.min_signers() as usize {
            bail!("insufficient signers");
        }

        // Check date monotonicity against the last mark's date
        if date < *self.last_mark.date() {
            bail!("date monotonicity violated");
        }

        let seq = self.next_seq();

        // 1. Validate the provided receipt and nonces
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
        let key_seq = kdf_next(self.chain_id(), seq, receipt.root, self.res());

        // 4. Verify that this key_seq matches what the previous mark committed to
        if !prev_commitment_matches(&self.last_mark, &key_seq)? {
            bail!(
                "Chain integrity check failed: key_seq doesn't match previous mark's nextKey"
            );
        }

        // 5. Build message for Round-2 signing (standard PM message format)
        // Hash the info to create obj_hash for the signing message
        // If info is provided, serialize it to CBOR and hash it; otherwise use empty bytes
        let info_bytes = if let Some(ref info_val) = info {
            info_val.to_cbor_data()
        } else {
            Vec::new()
        };
        let obj_hash = sha256(&info_bytes);
        let message =
            hash_message(self.chain_id(), seq, date.clone(), &obj_hash);

        // 6. Perform Round-2 using the SAME commitments and provided nonces
        let signature = self.group.round2_sign(
            signers,
            commitments_map,
            nonces,
            &message,
        )?;

        // 7. VERIFY the aggregate signature under the group verifying key
        self.group.verify(&message, &signature)?;

        // 8. BEFORE finalizing this mark's hash, run precommit for seq+1 to get nextKey_seq
        let chain_id = self.chain_id().to_vec();
        let res = self.res();
        let (next_receipt, next_nonces) =
            self.precommit_next_mark(signers, seq + 1, &chain_id, res)?;
        let next_key_seq = kdf_next(&chain_id, seq + 1, next_receipt.root, res);

        // 9. Convert chrono::DateTime to dcbor::Date for ProvenanceMark
        let pm_date = dcbor::Date::from_timestamp(date.timestamp() as f64);

        // 10. Use key_seq and next_key_seq to create the mark
        let mark = ProvenanceMark::new(
            res,
            key_seq,
            next_key_seq,
            chain_id,
            seq as u32,
            pm_date,
            info,
        )?;

        // 11. Update state and store the new mark for future verification
        self.last_mark = mark.clone();

        Ok((mark, next_receipt, next_nonces))
    }
}
