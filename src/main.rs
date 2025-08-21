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
    keys::KeyPackage,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use frost_ed25519 as frost;

use rand::thread_rng;

/// Configuration for the FROST group parameters
struct GroupConfig {
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
    // STEP 1: TRUSTED DEALER KEY GENERATION
    // Generate secret shares for all participants using a trusted dealer approach
    // =============================================================================

    println!("🔑 STEP 1: Trusted Dealer Key Generation");
    println!(
        "   Generating secret shares for {} participants with threshold {}...",
        group_config.max_signers, group_config.min_signers
    );

    let (secret_shares, public_key_package) =
        frost::keys::generate_with_dealer(
            group_config.max_signers,
            group_config.min_signers,
            frost::keys::IdentifierList::Custom(
                &group_config.participant_ids(),
            ),
            &mut rng,
        )?;

    println!("   ✅ Generated {} secret shares", secret_shares.len());
    println!("   ✅ Created public key package");

    // Display some key information
    let group_public_key = public_key_package.verifying_key();
    let group_key_bytes = group_public_key.serialize()?;
    println!("   📝 Group public key: {}", hex::encode(&group_key_bytes));
    println!();

    // =============================================================================
    // STEP 2: KEY PACKAGE CREATION
    // Convert secret shares to key packages that participants will use for signing
    // =============================================================================

    println!("🔧 STEP 2: Key Package Creation");
    println!(
        "   Converting secret shares to key packages for each participant..."
    );

    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();

    for (identifier, secret_share) in &secret_shares {
        let key_package = KeyPackage::try_from(secret_share.clone())?;
        key_packages.insert(*identifier, key_package);
        let participant_name = group_config.participant_name(identifier);
        println!(
            "   ✅ Created key package for participant {}",
            participant_name
        );
    }

    println!("   📦 Total key packages created: {}", key_packages.len());
    println!();

    // =============================================================================
    // STEP 3: PARTICIPANT SELECTION
    // Select which participants will participate in this signing ceremony
    // For this demo, we'll use the first 2 participants (satisfying the 2-of-3 threshold)
    // =============================================================================

    println!("👥 STEP 3: Participant Selection");
    println!(
        "   Selecting {} participants for this signing ceremony...",
        group_config.min_signers
    );

    let signing_participants: Vec<Identifier> = key_packages
        .keys()
        .take(group_config.min_signers as usize)
        .cloned()
        .collect();

    for (i, participant_id) in signing_participants.iter().enumerate() {
        let participant_name = group_config.participant_name(participant_id);
        println!("   👤 Participant {}: {}", i + 1, participant_name);
    }
    println!();

    // =============================================================================
    // STEP 4: ROUND 1 - COMMITMENT PHASE
    // Each participating signer generates nonces and creates commitments
    // =============================================================================

    println!("🎲 STEP 4: Round 1 - Commitment Phase");
    println!("   Each participant generates nonces and commitments...");

    let mut nonces_map: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, SigningCommitments> =
        BTreeMap::new();

    for participant_id in &signing_participants {
        let key_package = &key_packages[participant_id];

        // Generate nonces and commitments for this participant
        let (nonces, commitments) =
            frost::round1::commit(key_package.signing_share(), &mut rng);

        nonces_map.insert(*participant_id, nonces);
        commitments_map.insert(*participant_id, commitments);

        println!(
            "   ✅ Participant {} generated nonces and commitments",
            group_config.participant_name(participant_id)
        );
    }

    println!(
        "   🎯 Round 1 complete: {} participants ready",
        nonces_map.len()
    );
    println!();

    // =============================================================================
    // STEP 5: SIGNING PACKAGE CREATION
    // The coordinator creates a signing package containing the message and all commitments
    // =============================================================================

    println!("📦 STEP 5: Signing Package Creation");
    println!("   Creating signing package with message and commitments...");

    let signing_package =
        SigningPackage::new(commitments_map.clone(), signing_session.message);

    println!("   ✅ Signing package created");
    println!(
        "   📝 Package contains {} commitments",
        commitments_map.len()
    );
    println!("   📝 Message hash included in package");
    println!();

    // =============================================================================
    // STEP 6: ROUND 2 - SIGNATURE SHARE GENERATION
    // Each participant creates a signature share using their nonces and the signing package
    // =============================================================================

    println!("✍️  STEP 6: Round 2 - Signature Share Generation");
    println!("   Each participant creates a signature share...");

    let mut signature_shares: BTreeMap<Identifier, SignatureShare> =
        BTreeMap::new();

    for participant_id in &signing_participants {
        let nonces = &nonces_map[participant_id];
        let key_package = &key_packages[participant_id];

        // Generate signature share for this participant
        let signature_share =
            frost::round2::sign(&signing_package, nonces, key_package)?;

        signature_shares.insert(*participant_id, signature_share);

        println!(
            "   ✅ Participant {} created signature share",
            group_config.participant_name(participant_id)
        );
    }

    println!(
        "   🎯 Round 2 complete: {} signature shares collected",
        signature_shares.len()
    );
    println!();

    // =============================================================================
    // STEP 7: SIGNATURE AGGREGATION
    // The coordinator combines all signature shares into the final group signature
    // =============================================================================

    println!("🔗 STEP 7: Signature Aggregation");
    println!("   Combining signature shares into final group signature...");

    let group_signature: Signature = frost::aggregate(
        &signing_package,
        &signature_shares,
        &public_key_package,
    )?;

    println!("   ✅ Group signature successfully aggregated");

    // Display signature information
    let signature_bytes = group_signature.serialize()?;
    println!("   📝 Signature length: {} bytes", signature_bytes.len());
    println!("   📝 Signature (hex): {}", hex::encode(&signature_bytes));
    println!();

    // =============================================================================
    // STEP 8: SIGNATURE VERIFICATION
    // Verify that the aggregated signature is valid for the original message
    // =============================================================================

    println!("✅ STEP 8: Signature Verification");
    println!(
        "   Verifying the aggregated signature against the original message..."
    );

    // Perform cryptographic verification
    let verification_result = public_key_package
        .verifying_key()
        .verify(signing_session.message, &group_signature);

    match verification_result {
        Ok(()) => {
            println!("   🎉 Signature verification: PASSED");
            println!(
                "   ✅ The message was successfully signed using FROST threshold signature"
            );
        }
        Err(error) => {
            println!("   ❌ Signature verification: FAILED");
            println!("   💥 Error: {:?}", error);
            return Err(Box::new(error));
        }
    }
    println!();

    // =============================================================================
    // STEP 9: DEMONSTRATION SUMMARY
    // Display a comprehensive summary of what was accomplished
    // =============================================================================

    println!("📊 STEP 9: Demo Summary and Validation");
    println!("════════════════════════════════════════");

    // Validate all the key properties of our FROST ceremony
    assert_eq!(
        secret_shares.len(),
        group_config.max_signers as usize,
        "Should have correct number of secret shares"
    );
    assert_eq!(
        key_packages.len(),
        group_config.max_signers as usize,
        "Should have correct number of key packages"
    );
    assert_eq!(
        signing_participants.len(),
        group_config.min_signers as usize,
        "Should have correct number of signing participants"
    );
    assert_eq!(
        nonces_map.len(),
        group_config.min_signers as usize,
        "Should have correct number of nonce sets"
    );
    assert_eq!(
        commitments_map.len(),
        group_config.min_signers as usize,
        "Should have correct number of commitments"
    );
    assert_eq!(
        signature_shares.len(),
        group_config.min_signers as usize,
        "Should have correct number of signature shares"
    );
    assert_eq!(
        signature_bytes.len(),
        64,
        "ED25519 signature should be 64 bytes"
    );

    println!("✅ All validations passed!");
    println!();

    println!("🏆 FROST Protocol Demo Results:");
    println!("   🔑 Key generation: ✅ COMPLETED");
    println!("   👥 Participant setup: ✅ COMPLETED");
    println!("   🎲 Round 1 (commitments): ✅ COMPLETED");
    println!("   📦 Signing package: ✅ COMPLETED");
    println!("   ✍️  Round 2 (signature shares): ✅ COMPLETED");
    println!("   🔗 Signature aggregation: ✅ COMPLETED");
    println!("   ✅ Cryptographic verification: ✅ PASSED");
    println!();

    println!("📈 Protocol Statistics:");
    println!("   • Total participants: {}", group_config.max_signers);
    println!("   • Signing participants: {}", group_config.min_signers);
    println!(
        "   • Threshold: {} of {}",
        group_config.min_signers, group_config.max_signers
    );
    println!(
        "   • Message length: {} bytes",
        signing_session.message.len()
    );
    println!("   • Signature length: {} bytes", signature_bytes.len());
    println!(
        "   • Group public key length: {} bytes",
        group_key_bytes.len()
    );
    println!("   • Ciphersuite: FROST-ED25519-SHA512-v1");
    println!();

    println!("🎯 Key Technical Accomplishments:");
    println!("   • Demonstrated complete FROST protocol execution");
    println!("   • Successfully performed threshold signature generation");
    println!("   • Validated cryptographic correctness of all operations");
    println!(
        "   • Showed how {} participants can jointly sign with only {} signatures",
        group_config.max_signers, group_config.min_signers
    );
    println!("   • Used secure ED25519 elliptic curve cryptography");
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
}
