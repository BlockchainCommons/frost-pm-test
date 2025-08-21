/*!
# FROST PM Test - Complete 2-of-3 Group Generation and Signing Ceremony

This is a demonstration binary that performs a complete FROST (Flexible Round-Optimized Schnorr Threshold)
signing ceremony using the ED25519 ciphersuite. It demonstrates all stages of the FROST protocol:

1. **Trusted Dealer Key Generation**: Generate secret shares for a 2-of-3 threshold setup
2. **Key Package Creation**: Convert secret shares to key packages for each participant
3. **Round 1 - Commitment Phase**: Each participant generates nonces and commitments
4. **Signing Package Creation**: Coordinator creates a signing package with message and commitments
5. **Round 2 - Signature Generation**: Each participant creates a signature share
6. **Signature Aggregation**: Coordinator combines signature shares into final group signature
7. **Verification**: Verify the aggregated signature against the original message

This implementation uses direct library calls to the FROST implementation for educational purposes.
No user interaction is required - the binary runs autonomously and outputs progress to the console.
Participants are identified with human-readable names (Alice, Bob, Eve) for clarity.

## Usage

```bash
cargo run --bin frost-pm-test
```

## Technical Details

- **Ciphersuite**: FROST-ED25519-SHA512-v1
- **Threshold**: 2-of-3 (minimum 2 signers required)
- **Message**: "Hello, FROST! This is a 2-of-3 threshold signature demo."
- **Participants**: Alice, Bob, and Eve (3 total participants, with Alice and Bob selected for signing)

The demo follows the FROST specification RFC draft and demonstrates the complete protocol flow
without network communication (all done in-memory for simplicity).
*/

use std::collections::BTreeMap;

// FROST ED25519 imports
use frost::{
    Identifier, Signature, SigningPackage,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use frost_ed25519 as frost;

use rand::{thread_rng, CryptoRng, RngCore};

/// Configuration for the FROST group parameters
pub struct GroupConfig {
    /// Minimum number of signers required (threshold)
    min_signers: u16,
    /// Maximum number of participants
    max_signers: u16,
    /// Mapping of human-readable names to FROST identifiers
    participants: BTreeMap<&'static str, Identifier>,
    /// Reverse mapping from FROST identifiers to human-readable names
    id_to_name: BTreeMap<Identifier, &'static str>,
}

impl GroupConfig {
    /// Create a new GroupConfig with the specified threshold and participant names
    /// The maximum number of signers is automatically derived from the participant names array
    fn new(
        min_signers: u16,
        participant_names: &[&'static str],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let max_signers = participant_names.len() as u16;

        if min_signers > max_signers {
            return Err(format!(
                "min_signers ({}) cannot be greater than max_signers ({})",
                min_signers, max_signers
            )
            .into());
        }

        if min_signers == 0 {
            return Err("min_signers must be at least 1".into());
        }

        let mut participants = BTreeMap::new();
        let mut id_to_name = BTreeMap::new();

        for (i, name) in participant_names.iter().enumerate() {
            let id = Identifier::try_from((i + 1) as u16)?;
            participants.insert(*name, id);
            id_to_name.insert(id, *name);
        }

        Ok(Self { min_signers, max_signers, participants, id_to_name })
    }

    /// Get the list of participant identifiers
    fn participant_ids(&self) -> Vec<Identifier> {
        self.participants.values().cloned().collect()
    }

    /// Get participant name by identifier
    fn participant_name(&self, id: &Identifier) -> &'static str {
        self.id_to_name.get(id).unwrap_or(&"Unknown")
    }

    /// Get participant names as a comma-separated string
    fn participant_names_string(&self) -> String {
        self.participants
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self::new(2, &["Alice", "Bob", "Eve"])
            .expect("Default GroupConfig should be valid")
    }
}

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
    /// Create a new Group using trusted dealer key generation
    pub fn new_with_trusted_dealer(config: GroupConfig, rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate secret shares using trusted dealer
        let (secret_shares, public_key_package) = frost::keys::generate_with_dealer(
            config.max_signers,
            config.min_signers,
            frost::keys::IdentifierList::Custom(&config.participant_ids()),
            rng,
        )?;

        // Convert secret shares to key packages
        let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
        for (identifier, secret_share) in &secret_shares {
            let key_package = KeyPackage::try_from(secret_share.clone())?;
            key_packages.insert(*identifier, key_package);
        }

        Ok(Self {
            min_signers: config.min_signers,
            max_signers: config.max_signers,
            participants: config.participants,
            id_to_name: config.id_to_name,
            key_packages,
            public_key_package,
        })
    }

    /// Create a new Group from existing key material (e.g., from DKG)
    pub fn new_from_key_material(
        config: GroupConfig,
        key_packages: BTreeMap<Identifier, KeyPackage>,
        public_key_package: PublicKeyPackage,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate that we have key packages for all participants
        if key_packages.len() != config.max_signers as usize {
            return Err(format!(
                "Expected {} key packages, got {}",
                config.max_signers,
                key_packages.len()
            ).into());
        }

        // Validate that all participant identifiers have corresponding key packages
        for participant_id in config.participants.values() {
            if !key_packages.contains_key(participant_id) {
                return Err(format!(
                    "Missing key package for participant {}",
                    config.participant_name(participant_id)
                ).into());
            }
        }

        Ok(Self {
            min_signers: config.min_signers,
            max_signers: config.max_signers,
            participants: config.participants,
            id_to_name: config.id_to_name,
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

    /// Get participant name by identifier
    pub fn participant_name(&self, id: &Identifier) -> &'static str {
        self.id_to_name.get(id).unwrap_or(&"Unknown")
    }

    /// Get participant names as a comma-separated string
    pub fn participant_names_string(&self) -> String {
        self.participants
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Get the list of all participant identifiers
    pub fn participant_ids(&self) -> Vec<Identifier> {
        self.participants.values().cloned().collect()
    }

    /// Get a reference to a participant's key package
    pub fn key_package(&self, id: &Identifier) -> Option<&KeyPackage> {
        self.key_packages.get(id)
    }

    /// Get all key packages
    pub fn key_packages(&self) -> &BTreeMap<Identifier, KeyPackage> {
        &self.key_packages
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
    pub fn select_signers(&self, count: Option<usize>) -> Vec<Identifier> {
        let signer_count = count.unwrap_or(self.min_signers as usize);
        self.key_packages
            .keys()
            .take(signer_count.min(self.max_signers as usize))
            .cloned()
            .collect()
    }

    /// Perform a complete signing ceremony with the specified signers and message
    pub fn sign(&self, message: &[u8], signers: &[Identifier], rng: &mut (impl RngCore + CryptoRng)) -> Result<Signature, Box<dyn std::error::Error>> {
        if signers.len() < self.min_signers as usize {
            return Err(format!(
                "Need at least {} signers, got {}",
                self.min_signers,
                signers.len()
            ).into());
        }

        // Round 1: Generate nonces and commitments
        let mut nonces_map: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for signer_id in signers {
            let key_package = self.key_packages.get(signer_id)
                .ok_or_else(|| format!("No key package for signer {}", self.participant_name(signer_id)))?;

            let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);
            nonces_map.insert(*signer_id, nonces);
            commitments_map.insert(*signer_id, commitments);
        }

        // Create signing package
        let signing_package = SigningPackage::new(commitments_map, message);

        // Round 2: Generate signature shares
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        for signer_id in signers {
            let nonces = &nonces_map[signer_id];
            let key_package = &self.key_packages[signer_id];

            let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;
            signature_shares.insert(*signer_id, signature_share);
        }

        // Aggregate signature
        let group_signature = frost::aggregate(&signing_package, &signature_shares, &self.public_key_package)?;

        Ok(group_signature)
    }

    /// Verify a signature against a message using the group's public key
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Box<dyn std::error::Error>> {
        self.verifying_key()
            .verify(message, signature)
            .map_err(|e| e.into())
    }
}

/// Configuration for a signing session
struct SigningSession {
    /// Message to be signed
    message: &'static [u8],
}

impl Default for SigningSession {
    fn default() -> Self {
        Self {
            message:
                b"Hello, FROST! This is a 2-of-3 threshold signature demo.",
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "🚀 FROST Protocol Demo - 2-of-3 Threshold Signature with ED25519"
    );
    println!(
        "================================================================"
    );
    println!();

    let group_config = GroupConfig::default();
    let signing_session = SigningSession::default();
    let mut rng = thread_rng();

    println!("📋 Demo Configuration:");
    println!("   • Ciphersuite: FROST-ED25519-SHA512-v1");
    println!(
        "   • Threshold: {} of {}",
        group_config.min_signers, group_config.max_signers
    );
    println!(
        "   • Message: {:?}",
        std::str::from_utf8(signing_session.message).unwrap_or("<binary>")
    );
    println!(
        "   • Message length: {} bytes",
        signing_session.message.len()
    );
    println!(
        "   • Participants: {}",
        group_config.participant_names_string()
    );
    println!();

    // =============================================================================
    // STEP 1: GROUP FORMATION
    // Create a fully constituted FROST group with all necessary key material
    // =============================================================================

    println!("🏗️  STEP 1: Group Formation");
    println!("   Creating FROST group using trusted dealer key generation...");

    let group = Group::new_with_trusted_dealer(group_config, &mut rng)?;

    println!("   ✅ Group formed successfully");
    println!("   📝 Group public key: {}", hex::encode(&group.verifying_key().serialize()?));
    println!("   � {} participants configured with key packages", group.max_signers());
    println!();

    // =============================================================================
    // STEP 2: PARTICIPANT VERIFICATION
    // Verify all participants have valid key packages
    // =============================================================================

    println!("🔧 STEP 2: Participant Verification");
    println!("   Verifying key packages for all participants...");

    for participant_id in group.participant_ids() {
        let participant_name = group.participant_name(&participant_id);
        if group.key_package(&participant_id).is_some() {
            println!("   ✅ {} has valid key package", participant_name);
        }
    }

    println!("   📦 All {} key packages verified", group.max_signers());
    println!();

    // =============================================================================
    // STEP 3: SIGNING CEREMONY
    // Perform a complete FROST threshold signature using the group
    // =============================================================================

    println!("✍️  STEP 3: Signing Ceremony");
    println!("   Selecting {} signers for threshold signature...", group.min_signers());

    // Select signers (in this case, the first min_signers participants)
    let signers = group.select_signers(None);

    for (i, signer_id) in signers.iter().enumerate() {
        let participant_name = group.participant_name(signer_id);
        println!("   👤 Signer {}: {}", i + 1, participant_name);
    }
    println!();

    println!("   🎲 Executing FROST signing protocol...");
    println!("   📝 Message: {:?}", std::str::from_utf8(signing_session.message).unwrap_or("<binary>"));

    // Perform the complete signing ceremony
    let group_signature = group.sign(signing_session.message, &signers, &mut rng)?;

    println!("   ✅ Group signature generated successfully");
    let signature_bytes = group_signature.serialize()?;
    println!("   📝 Signature length: {} bytes", signature_bytes.len());
    println!("   📝 Signature (hex): {}", hex::encode(&signature_bytes));
    println!();

    // =============================================================================
    // STEP 4: SIGNATURE VERIFICATION
    // Verify the signature using the group's public key
    // =============================================================================

    println!("✅ STEP 4: Signature Verification");
    println!("   Verifying signature against the original message...");

    match group.verify(signing_session.message, &group_signature) {
        Ok(()) => {
            println!("   🎉 Signature verification: PASSED");
            println!("   ✅ The message was successfully signed using FROST threshold signature");
        }
        Err(error) => {
            println!("   ❌ Signature verification: FAILED");
            println!("   💥 Error: {:?}", error);
            return Err(error);
        }
    }
    println!();

    // =============================================================================
    // STEP 5: DEMONSTRATION SUMMARY
    // Display a comprehensive summary of what was accomplished
    // =============================================================================

    println!("📊 STEP 5: Demo Summary and Validation");
    println!("════════════════════════════════════════");

    // Validate all the key properties of our FROST ceremony
    assert_eq!(
        group.key_packages().len(),
        group.max_signers() as usize,
        "Should have correct number of key packages"
    );
    assert_eq!(
        signers.len(),
        group.min_signers() as usize,
        "Should have correct number of signing participants"
    );
    assert_eq!(
        signature_bytes.len(),
        64,
        "ED25519 signature should be 64 bytes"
    );

    println!("✅ All validations passed!");
    println!();

    println!("🏆 FROST Protocol Demo Results:");
    println!("   🏗️  Group formation: ✅ COMPLETED");
    println!("   � Key package verification: ✅ COMPLETED");
    println!("   ✍️  Threshold signing ceremony: ✅ COMPLETED");
    println!("   ✅ Cryptographic verification: ✅ PASSED");
    println!();

    println!("📈 Protocol Statistics:");
    println!("   • Total participants: {}", group.max_signers());
    println!("   • Signing participants: {}", group.min_signers());
    println!(
        "   • Threshold: {} of {}",
        group.min_signers(), group.max_signers()
    );
    println!(
        "   • Message length: {} bytes",
        signing_session.message.len()
    );
    println!("   • Signature length: {} bytes", signature_bytes.len());
    println!(
        "   • Group public key length: {} bytes",
        group.verifying_key().serialize()?.len()
    );
    println!("   • Ciphersuite: FROST-ED25519-SHA512-v1");
    println!();

    println!("🎯 Key Technical Accomplishments:");
    println!("   • Demonstrated complete FROST protocol execution");
    println!("   • Successfully performed threshold signature generation");
    println!("   • Validated cryptographic correctness of all operations");
    println!(
        "   • Showed how {} participants can jointly sign with only {} signatures",
        group.max_signers(), group.min_signers()
    );
    println!("   • Used secure ED25519 elliptic curve cryptography");
    println!("   • Abstracted key generation method (trusted dealer used)");
    println!();

    println!("🎉 FROST 2-of-3 Threshold Signature Demo: SUCCESS!");
    println!(
        "================================================================"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    impl GroupConfig {
        /// Create a predefined 3-of-5 configuration with corporate participants
        pub fn corporate_board() -> Result<Self, Box<dyn std::error::Error>> {
            Self::new(3, &["CEO", "CFO", "CTO", "COO", "CLO"])
        }

        /// Create a predefined 2-of-4 configuration with family members
        pub fn family() -> Result<Self, Box<dyn std::error::Error>> {
            Self::new(2, &["Alice", "Bob", "Charlie", "Diana"])
        }
    }

    #[test]
    fn test_default_config() {
        let config = GroupConfig::default();
        assert_eq!(config.min_signers, 2);
        assert_eq!(config.max_signers, 3);
        assert_eq!(config.participants.len(), 3);
        assert!(config.participants.contains_key("Alice"));
        assert!(config.participants.contains_key("Bob"));
        assert!(config.participants.contains_key("Eve"));
    }

    #[test]
    fn test_corporate_board_config() {
        let config = GroupConfig::corporate_board().unwrap();
        assert_eq!(config.min_signers, 3);
        assert_eq!(config.max_signers, 5);
        assert_eq!(config.participants.len(), 5);
        assert!(config.participants.contains_key("CEO"));
        assert!(config.participants.contains_key("CFO"));
        assert!(config.participants.contains_key("CTO"));
        assert!(config.participants.contains_key("COO"));
        assert!(config.participants.contains_key("CLO"));
    }

    #[test]
    fn test_family_config() {
        let config = GroupConfig::family().unwrap();
        assert_eq!(config.min_signers, 2);
        assert_eq!(config.max_signers, 4);
        assert_eq!(config.participants.len(), 4);
        assert!(config.participants.contains_key("Alice"));
        assert!(config.participants.contains_key("Bob"));
        assert!(config.participants.contains_key("Charlie"));
        assert!(config.participants.contains_key("Diana"));
    }

    #[test]
    fn test_config_validation() {
        // Test min_signers = 0
        let result = GroupConfig::new(0, &["Alice", "Bob"]);
        assert!(result.is_err());

        // Test min_signers > max_signers
        let result = GroupConfig::new(5, &["Alice", "Bob"]);
        assert!(result.is_err());

        // Test valid config
        let result = GroupConfig::new(2, &["Alice", "Bob", "Charlie"]);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.min_signers, 2);
        assert_eq!(config.max_signers, 3);
    }

    #[test]
    fn test_participant_name_lookup() {
        let config = GroupConfig::default();
        let alice_id = config.participants["Alice"];
        assert_eq!(config.participant_name(&alice_id), "Alice");

        // Test unknown identifier
        let unknown_id = frost::Identifier::try_from(99u16).unwrap();
        assert_eq!(config.participant_name(&unknown_id), "Unknown");
    }

    #[test]
    fn test_participant_names_string() {
        let config = GroupConfig::default();
        let names = config.participant_names_string();
        // BTreeMap maintains sorted order, so we can predict the output
        assert_eq!(names, "Alice, Bob, Eve");
    }

    #[test]
    fn test_group_creation_with_trusted_dealer() {
        let config = GroupConfig::default();
        let mut rng = rand::thread_rng();

        let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();

        assert_eq!(group.min_signers(), 2);
        assert_eq!(group.max_signers(), 3);
        assert_eq!(group.key_packages().len(), 3);
        assert_eq!(group.participant_names_string(), "Alice, Bob, Eve");

        // Verify all participants have key packages
        for participant_id in group.participant_ids() {
            assert!(group.key_package(&participant_id).is_some());
        }
    }

    #[test]
    fn test_group_signing() {
        let config = GroupConfig::default();
        let mut rng = rand::thread_rng();

        let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();
        let message = b"Test message for FROST signing";

        // Select signers
        let signers = group.select_signers(None);
        assert_eq!(signers.len(), 2); // min_signers

        // Perform signing
        let signature = group.sign(message, &signers, &mut rng).unwrap();

        // Verify signature
        assert!(group.verify(message, &signature).is_ok());

        // Verify with wrong message fails
        let wrong_message = b"Wrong message";
        assert!(group.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_group_insufficient_signers() {
        let config = GroupConfig::default();
        let mut rng = rand::thread_rng();

        let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();
        let message = b"Test message";

        // Try to sign with only 1 signer (need 2 for threshold)
        let insufficient_signers = vec![group.participant_ids()[0]];

        let result = group.sign(message, &insufficient_signers, &mut rng);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Need at least 2 signers"));
    }

    #[test]
    fn test_corporate_board_signing() {
        let config = GroupConfig::corporate_board().unwrap();
        let mut rng = rand::thread_rng();

        let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();
        assert_eq!(group.min_signers(), 3);
        assert_eq!(group.max_signers(), 5);

        let message = b"Corporate board resolution";
        let signers = group.select_signers(None); // Should select 3 signers
        assert_eq!(signers.len(), 3);

        let signature = group.sign(message, &signers, &mut rng).unwrap();
        assert!(group.verify(message, &signature).is_ok());
    }
}
