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

/// Create a mapping of human-readable names to FROST identifiers
fn create_participant_mapping()
-> Result<BTreeMap<&'static str, Identifier>, Box<dyn std::error::Error>> {
    let mut participants = BTreeMap::new();
    participants.insert("Alice", Identifier::try_from(1)?);
    participants.insert("Bob", Identifier::try_from(2)?);
    participants.insert("Eve", Identifier::try_from(3)?);
    Ok(participants)
}

/// Create a reverse mapping from FROST identifiers to human-readable names
fn create_identifier_name_mapping()
-> Result<BTreeMap<Identifier, &'static str>, Box<dyn std::error::Error>> {
    let mut mapping = BTreeMap::new();
    mapping.insert(Identifier::try_from(1)?, "Alice");
    mapping.insert(Identifier::try_from(2)?, "Bob");
    mapping.insert(Identifier::try_from(3)?, "Eve");
    Ok(mapping)
}

/// Configuration for the FROST group parameters
struct GroupConfig {
    /// Minimum number of signers required (threshold)
    min_signers: u16,
    /// Maximum number of participants
    max_signers: u16,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self { min_signers: 2, max_signers: 3 }
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

    // Create human-readable participant mappings
    let participants = create_participant_mapping()?;
    let id_to_name = create_identifier_name_mapping()?;
    let participant_ids: Vec<Identifier> =
        participants.values().cloned().collect();

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
        participants
            .keys()
            .map(|s| *s)
            .collect::<Vec<_>>()
            .join(", ")
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
            frost::keys::IdentifierList::Custom(&participant_ids),
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
        let participant_name = id_to_name.get(identifier).unwrap_or(&"Unknown");
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
        let participant_name =
            id_to_name.get(participant_id).unwrap_or(&"Unknown");
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
            id_to_name.get(participant_id).unwrap_or(&"Unknown")
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
            id_to_name.get(participant_id).unwrap_or(&"Unknown")
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
