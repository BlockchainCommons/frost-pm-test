use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use frost_ed25519 as frost;
use frost_ed25519::{
    Identifier, Signature, SigningPackage,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use rand::{CryptoRng, RngCore};

use crate::frost_group_config::FrostGroupConfig;

/// A fully constituted FROST group with all key material needed for signing
/// This type abstracts away whether keys were generated via trusted dealer or
/// DKG
#[derive(Debug, Clone)]
pub struct FrostGroup {
    /// Configuration for the FROST group parameters
    config: FrostGroupConfig,
    /// Key packages for each participant (contains signing shares)
    key_packages: BTreeMap<Identifier, KeyPackage>,
    /// The group's public key package (for verification and coordination)
    public_key_package: PublicKeyPackage,
}

impl FrostGroup {
    /// Create a new FROSTGroup using trusted dealer key generation
    pub fn new_with_trusted_dealer(
        config: FrostGroupConfig,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        // Generate secret shares using trusted dealer
        let (secret_shares, public_key_package) =
            frost::keys::generate_with_dealer(
                config.max_signers() as u16,
                config.min_signers() as u16,
                frost::keys::IdentifierList::Custom(&config.participant_ids()),
                rng,
            )?;

        // Convert secret shares to key packages
        let mut key_packages: BTreeMap<Identifier, KeyPackage> =
            BTreeMap::new();
        for (identifier, secret_share) in &secret_shares {
            let key_package = KeyPackage::try_from(secret_share.clone())?;
            key_packages.insert(*identifier, key_package);
        }

        // Use the more primitive constructor
        Self::new_from_key_material(config, key_packages, public_key_package)
    }

    /// Create a new FROSTGroup from existing key material (e.g., from DKG)
    pub fn new_from_key_material(
        config: FrostGroupConfig,
        key_packages: BTreeMap<Identifier, KeyPackage>,
        public_key_package: PublicKeyPackage,
    ) -> Result<Self> {
        // Validate that we have key packages for all participants
        if key_packages.len() != config.max_signers() as usize {
            bail!(
                "Expected {} key packages, got {}",
                config.max_signers(),
                key_packages.len()
            );
        }

        // Validate that all participant identifiers have corresponding key
        // packages
        for participant_id in config.participants().values() {
            if !key_packages.contains_key(participant_id) {
                bail!(
                    "Missing key package for participant {}",
                    config.participant_name(participant_id)
                );
            }
        }

        Ok(Self { config, key_packages, public_key_package })
    }

    /// Get the minimum number of signers required (threshold)
    pub fn min_signers(&self) -> usize { self.config.min_signers() }

    /// Get the maximum number of participants
    pub fn max_signers(&self) -> usize { self.config.max_signers() }

    /// Check if a participant name exists in this group
    pub fn has_participant(&self, name: &str) -> bool {
        self.config.participants().contains_key(name)
    }

    /// Get the list of all participant names
    pub fn participant_names(&self) -> Vec<String> {
        self.config.participants().keys().cloned().collect()
    }

    /// Get a reference to the group configuration
    pub fn config(&self) -> &FrostGroupConfig { &self.config }

    /// Get a reference to a participant's key package by name
    pub fn key_package(&self, name: &str) -> Result<&KeyPackage> {
        let id = self.name_to_id(name)?;
        self.key_packages
            .get(&id)
            .ok_or_else(|| anyhow!("No key package for participant {}", name))
    }

    /// Get the public key package for this group
    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    /// Get the group's verifying key (public key)
    pub fn verifying_key(&self) -> &frost::VerifyingKey {
        self.public_key_package.verifying_key()
    }

    /// Perform a complete signing ceremony with the specified signers and
    /// message Takes participant names instead of identifiers
    pub fn sign(
        &self,
        message: &[u8],
        signers: &[&str],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Signature> {
        if signers.len() < self.config.min_signers() {
            bail!(
                "Need at least {} signers, got {}",
                self.config.min_signers(),
                signers.len()
            );
        }

        // Validate all signer names exist upfront
        for &signer_name in signers {
            self.key_package(signer_name)?; // This validates the name exists
        }

        // Round 1: Generate nonces and commitments
        let mut nonces_map: BTreeMap<String, SigningNonces> = BTreeMap::new();
        let mut commitments_map: BTreeMap<String, SigningCommitments> =
            BTreeMap::new();

        for &signer_name in signers {
            let (nonces, commitments) =
                self.commit_for_participant(signer_name, rng)?;
            nonces_map.insert(signer_name.to_string(), nonces);
            commitments_map.insert(signer_name.to_string(), commitments);
        }

        let signing_package =
            self.create_signing_package(signers, &commitments_map, message)?;

        // Round 2: Generate signature shares
        let mut signature_shares: BTreeMap<String, SignatureShare> =
            BTreeMap::new();
        for &signer_name in signers {
            let nonces = &nonces_map[signer_name];
            let signature_share = self.sign_for_participant(
                signer_name,
                &signing_package,
                nonces,
            )?;
            signature_shares.insert(signer_name.to_string(), signature_share);
        }

        // Aggregate signature
        let group_signature = self.aggregate_signature(
            &signing_package,
            signers,
            &signature_shares,
        )?;

        Ok(group_signature)
    }

    /// Verify a signature against a message using the group's public key
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        Ok(self.verifying_key().verify(message, signature)?)
    }

    /// Round-1 only: collect commitments for two-ceremony approach
    /// Returns a map of Identifier -> SigningCommitments, and stores nonces
    /// locally Participants must keep their SigningNonces until Round-2
    /// completes
    pub fn round_1_commit(
        &self,
        signers: &[&str],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(
        BTreeMap<Identifier, SigningCommitments>,
        BTreeMap<String, SigningNonces>,
    )> {
        if signers.len() < self.config.min_signers() {
            bail!(
                "Need at least {} signers, got {}",
                self.config.min_signers(),
                signers.len()
            );
        }

        // Validate all signer names exist upfront
        for &signer_name in signers {
            self.key_package(signer_name)?; // This validates the name exists
        }

        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> =
            BTreeMap::new();
        let mut nonces_map: BTreeMap<String, SigningNonces> = BTreeMap::new();

        for &signer_name in signers {
            let (nonces, commitments) =
                self.commit_for_participant(signer_name, rng)?;
            let signer_id = self.name_to_id(signer_name)?;
            commitments_map.insert(signer_id, commitments);
            nonces_map.insert(signer_name.to_string(), nonces);
        }

        Ok((commitments_map, nonces_map))
    }

    /// Round-2: replay commitments and perform signing
    /// Requires the same commitments from Round-1 and the nonces kept by
    /// participants
    pub fn round_2_sign(
        &self,
        signers: &[&str],
        commitments_map: &BTreeMap<Identifier, SigningCommitments>,
        nonces_map: &BTreeMap<String, SigningNonces>,
        message: &[u8],
    ) -> Result<Signature> {
        if signers.len() < self.config.min_signers() {
            bail!(
                "Need at least {} signers, got {}",
                self.config.min_signers(),
                signers.len()
            );
        }

        // Create signing package from the commitments
        let signing_package =
            SigningPackage::new(commitments_map.clone(), message);

        // Round 2: Generate signature shares
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> =
            BTreeMap::new();
        for &signer_name in signers {
            let signer_id = self.name_to_id(signer_name)?;
            let nonces = &nonces_map[signer_name];
            let signature_share = self.sign_for_participant(
                signer_name,
                &signing_package,
                nonces,
            )?;
            signature_shares.insert(signer_id, signature_share);
        }

        // Aggregate signature
        let group_signature = frost::aggregate(
            &signing_package,
            &signature_shares,
            &self.public_key_package,
        )?;

        Ok(group_signature)
    }
}

impl FrostGroup {
    /// Convert participant name to identifier
    pub fn name_to_id(&self, name: &str) -> Result<Identifier> {
        self.config
            .participants()
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("Unknown participant: {}", name))
    }

    /// Helper method to perform round1 commit for a participant by name
    fn commit_for_participant(
        &self,
        participant_name: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(SigningNonces, SigningCommitments)> {
        let key_package = self.key_package(participant_name)?;
        Ok(frost::round1::commit(key_package.signing_share(), rng))
    }

    /// Helper method to perform round2 signing for a participant by name
    fn sign_for_participant(
        &self,
        participant_name: &str,
        signing_package: &SigningPackage,
        nonces: &SigningNonces,
    ) -> Result<SignatureShare> {
        let key_package = self.key_package(participant_name)?;
        Ok(frost::round2::sign(signing_package, nonces, key_package)?)
    }

    /// Helper method to create a signing package from signer names and their
    /// commitments
    fn create_signing_package(
        &self,
        signers: &[&str],
        commitments_by_name: &BTreeMap<String, SigningCommitments>,
        message: &[u8],
    ) -> Result<SigningPackage> {
        let mut frost_commitments_map: BTreeMap<
            Identifier,
            SigningCommitments,
        > = BTreeMap::new();
        for &signer_name in signers {
            let signer_id = self.name_to_id(signer_name)?;
            let commitments = &commitments_by_name[signer_name];
            frost_commitments_map.insert(signer_id, commitments.clone());
        }
        Ok(SigningPackage::new(frost_commitments_map, message))
    }

    /// Helper method to aggregate signature shares and create the final
    /// signature
    fn aggregate_signature(
        &self,
        signing_package: &SigningPackage,
        signers: &[&str],
        signature_shares_by_name: &BTreeMap<String, SignatureShare>,
    ) -> Result<Signature> {
        let mut frost_signature_shares: BTreeMap<Identifier, SignatureShare> =
            BTreeMap::new();
        for &signer_name in signers {
            let signer_id = self.name_to_id(signer_name)?;
            let signature_share = &signature_shares_by_name[signer_name];
            frost_signature_shares.insert(signer_id, signature_share.clone());
        }
        Ok(frost::aggregate(
            signing_package,
            &frost_signature_shares,
            &self.public_key_package,
        )?)
    }
}
