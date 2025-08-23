use crate::{FrostGroup, FrostGroupConfig};
use anyhow::{Result, bail};
use bc_crypto::{hkdf_hmac_sha256, sha256};
use dcbor::{CBOREncodable, Date};
use frost_ed25519::{Identifier, round1::SigningCommitments};
use provenance_mark::{ProvenanceMark, ProvenanceMarkResolution};
use std::collections::BTreeMap;

/// A public, non-secret receipt from the precommit phase
/// Contains the commitment root and roster used in the session
#[derive(Clone, Debug)]
pub struct PrecommitReceipt {
    pub seq: u32,
    pub root: [u8; 32],
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

    // Create a new chain with its genesis mark: derive key_0, precommit seq=1,
    // then finalize Mark 0. Returns the chain, genesis mark, and initial
    // precommit data for seq=1
    pub fn new_chain(
        group: FrostGroup,
        signature_0: frost_ed25519::Signature,
        commitments_1: &BTreeMap<Identifier, SigningCommitments>,
        res: ProvenanceMarkResolution,
        date: Date,
        info: Option<impl CBOREncodable>,
    ) -> Result<(Self, ProvenanceMark, PrecommitReceipt, [u8; 32])> {
        let link_len = res.link_length();

        // 1. Derive key_0 (and thus id) using the provided genesis message signature
        // Build M0 from group configuration including charter and participant names
        let genesis_msg = Self::genesis_message(group.config(), res);
        let m0 = genesis_msg.as_bytes();

        // Verify the provided signature against the genesis message
        group.verify(&m0, &signature_0)?;

        let key_0 = hkdf_hmac_sha256(
            &signature_0.serialize()?,
            &m0,
            link_len,
        );

        // id == key_0 (genesis invariant)
        let id = key_0.clone();

        // 2. Use provided precommit data for seq=1
        // The client has already performed Round-1 commit for the next sequence

        // Compute Root_1 = commitments_root(&commitments_map)
        let root_1 = Self::commitments_root(&commitments_1);

        // Compute next_key_0 = derive_link_from_root(res, id, 1, Root_1)
        let next_key_0 = Self::kdf_next(&id, 1, root_1, res);

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

        let receipt_1 = PrecommitReceipt {
            seq: 1,
            root: root_1,
        };

        Ok((chain, mark_0, receipt_1, root_1))
    }

    /// Append the next mark using precommitted Round-1 commitments
    /// This implements the two-ceremony approach: precommit (Round-1) + append (Round-2)
    /// Takes the receipt and the client-generated signature
    /// Returns the new mark and the precommit receipt for the next round
    pub fn append_mark(
        &mut self,
        date: Date,
        info: Option<impl CBOREncodable>,
        receipt: &PrecommitReceipt,
        receipt_root: Option<[u8; 32]>,
        signature: frost_ed25519::Signature,
        next_commitments: BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<(ProvenanceMark, PrecommitReceipt, [u8; 32], BTreeMap<Identifier, SigningCommitments>)> {
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

        let root = if let Some(r) = receipt_root {
            r
        } else {
            receipt.root
        };

        // 2. Derive key from the receipt's root (which matches the commitments)
        let key =
            Self::kdf_next(self.chain_id(), seq, root, self.res());

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

        // 6. BEFORE finalizing this mark's hash, use provided commitments for seq+1
        let chain_id = self.chain_id().to_vec();
        let res = self.res();
        let next_seq = seq + 1;

        // Use client-provided commitments for next sequence
        let next_root = Self::commitments_root(&next_commitments);

        let next_key =
            Self::kdf_next(&chain_id, next_seq, next_root, res);

        // 7. Use key and next_key to create the mark
        let mark =
            ProvenanceMark::new(res, key, next_key, chain_id, seq, date, info)?;

        // 8. Store the new mark
        self.last_mark = mark.clone();

        let next_receipt = PrecommitReceipt {
            seq: next_seq,
            root: next_root,
        };

        Ok((mark, next_receipt, next_root, next_commitments))
    }

    /// Compute a deterministic root over Round-1 commitment map
    /// This provides deterministic key derivation from commitment sets
    fn commitments_root(
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(commitments.len() * 100);

        for (id, sc) in commitments {
            // Get canonical bytes for identifier and commitments using serde+bincode
            let id_bytes =
                bincode::serialize(id).expect("serialize identifier");
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
    /// Domain separation and binding to chain + seq
    /// Returns the correct length for the given resolution
    fn kdf_next(
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
        let len = res.link_length();
        hash[..len].to_vec()
    }
}
