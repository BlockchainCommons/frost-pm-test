use crate::{
    FrostGroup, FrostGroupConfig,
    kdf::{commitments_root, kdf_next},
};
use anyhow::{Result, bail};
use bc_crypto::hkdf_hmac_sha256;
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
    pub seq: u32,
    pub root: [u8; 32],
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
    fn next_seq(&self) -> u32 {
        self.last_mark.seq() + 1
    }

    /// Get a reference to the underlying FROST group (for client use)
    pub fn group(&self) -> &FrostGroup {
        &self.group
    }

    /// Create a genesis message for a group (static version for new_genesis)
    pub fn genesis_message(
        config: &FrostGroupConfig,
        res: ProvenanceMarkResolution,
    ) -> String {
        let participant_names: Vec<String> =
            config.participants().keys().cloned().collect();
        format!(
            "FROST Provenance Mark Chain\nResolution: {}, Threshold: {} of {}\nParticipants: {}\nCharter: {}",
            res,
            config.min_signers(),
            participant_names.len(),
            participant_names.join(", "),
            config.charter()
        )
    }

    pub fn next_mark_message(
        self: &Self,
        date: Date,
        info: Option<impl CBOREncodable>,
    ) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"DS_HASH\0"); // domain separation
        m.extend_from_slice(self.chain_id());
        m.extend_from_slice(&self.next_seq().to_be_bytes());
        m.extend_from_slice(&(date.to_cbor_data()));
        let info_bytes = if let Some(ref info_val) = info {
            info_val.to_cbor_data()
        } else {
            Vec::new()
        };
        m.extend_from_slice(&(info_bytes.len() as u32).to_be_bytes());
        m.extend_from_slice(&info_bytes);
        m
    }

    /// Generate Round-1 commitments for a group (for client use)
    pub fn generate_round1_commitments(
        group: &FrostGroup,
        signers: &[&str],
        rng: &mut (impl rand::RngCore + rand::CryptoRng),
    ) -> Result<(
        BTreeMap<Identifier, SigningCommitments>,
        BTreeMap<String, SigningNonces>,
    )> {
        group.round1_commit(signers, rng)
    }

    /// Generate Round-2 signature for a group (for client use)
    pub fn generate_round2_signature(
        group: &FrostGroup,
        signers: &[&str],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        nonces: &BTreeMap<String, SigningNonces>,
        message: &[u8],
    ) -> Result<frost_ed25519::Signature> {
        group.round2_sign(signers, commitments, nonces, message)
    }

    // Create genesis: derive key_0, precommit seq=1, then finalize Mark 0.
    // Returns the chain, genesis mark, and initial precommit data for seq=1
    pub fn new_genesis(
        group: FrostGroup,
        genesis_message_signature: frost_ed25519::Signature,
        commitments_1: BTreeMap<Identifier, SigningCommitments>,
        res: ProvenanceMarkResolution,
        signers: &[&str],
        date: Date,
        info: Option<impl CBOREncodable>,
    ) -> Result<(Self, ProvenanceMark, PrecommitReceipt)> {
        if signers.len() < group.min_signers() as usize {
            bail!("insufficient signers");
        }
        let link_len = res.link_length();

        // 1. Derive key_0 (and thus id) using the provided genesis message signature
        // Build M0 from group configuration including charter and participant names
        let genesis_msg = Self::genesis_message(group.config(), res);
        let m0 = genesis_msg.as_bytes();

        // Verify the provided signature against the genesis message
        group.verify(&m0, &genesis_message_signature)?;

        let key_0 = hkdf_hmac_sha256(
            &genesis_message_signature.serialize()?,
            &m0,
            link_len,
        );

        // id == key_0 (genesis invariant)
        let id = key_0.clone();

        // 2. Use provided precommit data for seq=1
        // The client has already performed Round-1 commit for the next sequence

        // Compute Root_1 = commitments_root(&commitments_map)
        let next_root = commitments_root(&commitments_1);

        let receipt1 = PrecommitReceipt {
            seq: 1,
            root: next_root,
            commitments: commitments_1.clone(),
        };

        // Compute next_key_0 = derive_link_from_root(res, id, 1, Root_1)
        let next_key_0 = kdf_next(&id, 1, receipt1.root, res);

        // 3. Finalize M⟨0⟩ with key_0 and this next_key_0
        let mark_0 = ProvenanceMark::new(
            res,
            key_0,
            next_key_0,
            id.clone(),
            0,
            date.clone(),
            info,
        )?;

        // 4. Create the chain with the genesis mark
        let chain = Self { group, last_mark: mark_0.clone() };

        Ok((chain, mark_0, receipt1))
    }

    /// Append the next mark using precommitted Round-1 commitments
    /// This implements the two-ceremony approach: precommit (Round-1) + append (Round-2)
    /// Takes the receipt returned from precommit_next_mark and the client-generated signature
    /// Returns the new mark and the precommit data for the next round
    pub fn append_mark(
        &mut self,
        signers: &[&str],
        date: Date,
        info: Option<impl CBOREncodable>,
        receipt: &PrecommitReceipt,
        signature: frost_ed25519::Signature,
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

        // 2. Derive key from the receipt's root (which matches the commitments)
        let key = kdf_next(self.chain_id(), seq, receipt.root, self.res());

        // 3. Verify that this key matches what the previous mark committed to
        if !prev_commitment_matches(&self.last_mark, &key)? {
            bail!(
                "Chain integrity check failed: key doesn't match previous mark's next_key"
            );
        }

        // 4. Build message for Round-2 signing (standard PM message format)
        let message =
            Self::next_mark_message(&self, date.clone(), info.clone());

        // 5. VERIFY the provided signature under the group verifying key
        self.group.verify(&message, &signature)?;

        // 6. BEFORE finalizing this mark's hash, precommit for seq+1 to get next_key
        let chain_id = self.chain_id().to_vec();
        let res = self.res();
        let next_seq = seq + 1;

        // Precommit: collect commitments for next_seq
        let (next_commitments, next_nonces) =
            self.group.round1_commit(signers, &mut OsRng)?;
        let next_root = commitments_root(&next_commitments);

        let next_receipt = PrecommitReceipt {
            seq: next_seq,
            root: next_root,
            commitments: next_commitments,
        };

        let next_key = kdf_next(&chain_id, next_seq, next_receipt.root, res);

        // 7. Use key and next_key to create the mark
        let mark =
            ProvenanceMark::new(res, key, next_key, chain_id, seq, date, info)?;

        // 8. Store the new mark
        self.last_mark = mark.clone();

        Ok((mark, next_receipt, next_nonces))
    }
}
