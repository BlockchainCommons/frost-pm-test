use frost_ed25519 as frost;
use frost_ed25519::{
    Identifier, Signature, SigningPackage,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

use crate::group_config::GroupConfig;

/// A fully constituted FROST group with all key material needed for signing
/// This type abstracts away whether keys were generated via trusted dealer or DKG
pub struct Group {
    /// Minimum number of signers required (threshold)
    min_signers: u16,
    /// Maximum number of participants
    max_signers: u16,
    /// Mapping of human-readable names to FROST identifiers
    participants: BTreeMap<&'static str, Identifier>,
    /// Reverse mapping from FROST identifiers to human-readable names
    id_to_name: BTreeMap<Identifier, &'static str>,
    /// Key packages for each participant (contains signing shares)
    key_packages: BTreeMap<Identifier, KeyPackage>,
    /// The group's public key package (for verification and coordination)
    public_key_package: PublicKeyPackage,
}

impl Group {
    /// Convert participant name to identifier (private helper)
    fn name_to_id(
        &self,
        name: &str,
    ) -> Result<Identifier, Box<dyn std::error::Error>> {
        self.participants
            .get(name)
            .cloned()
            .ok_or_else(|| format!("Unknown participant: {}", name).into())
    }

    /// Get participant name by identifier (private helper)
    fn id_to_name(&self, id: &Identifier) -> &'static str {
        self.id_to_name.get(id).unwrap_or(&"Unknown")
    }

    /// Create a new Group using trusted dealer key generation
    pub fn new_with_trusted_dealer(
        config: GroupConfig,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate secret shares using trusted dealer
        let (secret_shares, public_key_package) =
            frost::keys::generate_with_dealer(
                config.max_signers(),
                config.min_signers(),
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

    /// Create a new Group from existing key material (e.g., from DKG)
    pub fn new_from_key_material(
        config: GroupConfig,
        key_packages: BTreeMap<Identifier, KeyPackage>,
        public_key_package: PublicKeyPackage,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate that we have key packages for all participants
        if key_packages.len() != config.max_signers() as usize {
            return Err(format!(
                "Expected {} key packages, got {}",
                config.max_signers(),
                key_packages.len()
            )
            .into());
        }

        // Validate that all participant identifiers have corresponding key packages
        for participant_id in config.participants().values() {
            if !key_packages.contains_key(participant_id) {
                return Err(format!(
                    "Missing key package for participant {}",
                    config.participant_name(participant_id)
                )
                .into());
            }
        }

        Ok(Self {
            min_signers: config.min_signers(),
            max_signers: config.max_signers(),
            participants: config.participants().clone(),
            id_to_name: config.id_to_name().clone(),
            key_packages,
            public_key_package,
        })
    }

    /// Get the minimum number of signers required (threshold)
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Get the maximum number of participants
    pub fn max_signers(&self) -> u16 {
        self.max_signers
    }

    /// Check if a participant name exists in this group
    pub fn has_participant(&self, name: &str) -> bool {
        self.participants.contains_key(name)
    }

    /// Get participant names as a comma-separated string
    pub fn participant_names_string(&self) -> String {
        self.participants
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Get the list of all participant names
    pub fn participant_names(&self) -> Vec<&'static str> {
        self.participants.keys().cloned().collect()
    }

    /// Get a reference to a participant's key package by name
    pub fn key_package(
        &self,
        name: &str,
    ) -> Result<&KeyPackage, Box<dyn std::error::Error>> {
        let id = self.name_to_id(name)?;
        self.key_packages.get(&id).ok_or_else(|| {
            format!("No key package for participant {}", name).into()
        })
    }

    /// Get the public key package for this group
    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    /// Get the group's verifying key (public key)
    pub fn verifying_key(&self) -> &frost::VerifyingKey {
        self.public_key_package.verifying_key()
    }

    /// Select a subset of participants for signing (up to min_signers)
    /// Returns participant names instead of identifiers
    pub fn select_signers(&self, count: Option<usize>) -> Vec<&'static str> {
        let signer_count = count.unwrap_or(self.min_signers as usize);
        self.key_packages
            .keys()
            .take(signer_count.min(self.max_signers as usize))
            .map(|id| self.id_to_name(id))
            .collect()
    }

    /// Perform a complete signing ceremony with the specified signers and message
    /// Takes participant names instead of identifiers
    pub fn sign(
        &self,
        message: &[u8],
        signer_names: &[&str],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        if signer_names.len() < self.min_signers as usize {
            return Err(format!(
                "Need at least {} signers, got {}",
                self.min_signers,
                signer_names.len()
            )
            .into());
        }

        // Validate all signer names exist and get their key packages
        let mut key_packages_by_name = BTreeMap::new();
        for &signer_name in signer_names {
            let key_package = self.key_package(signer_name)?;
            key_packages_by_name.insert(signer_name, key_package);
        }

        // Round 1: Generate nonces and commitments
        let mut nonces_map: BTreeMap<Identifier, SigningNonces> =
            BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> =
            BTreeMap::new();

        for (signer_name, key_package) in &key_packages_by_name {
            let signer_id = self.name_to_id(signer_name)?;
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), rng);
            nonces_map.insert(signer_id, nonces);
            commitments_map.insert(signer_id, commitments);
        }

        // Create signing package
        let signing_package = SigningPackage::new(commitments_map, message);

        // Round 2: Generate signature shares
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> =
            BTreeMap::new();
        for (signer_name, key_package) in &key_packages_by_name {
            let signer_id = self.name_to_id(signer_name)?;
            let nonces = &nonces_map[&signer_id];

            let signature_share =
                frost::round2::sign(&signing_package, nonces, key_package)?;
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

    /// Verify a signature against a message using the group's public key
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.verifying_key()
            .verify(message, signature)
            .map_err(|e| e.into())
    }
}
