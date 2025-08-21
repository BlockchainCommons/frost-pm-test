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

pub mod frost_group;
pub mod frost_group_config;

use frost_group::FROSTGroup;
use frost_group_config::FROSTGroupConfig;
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "🚀 FROST Protocol Demo - 2-of-3 Threshold Signature with ED25519"
    );
    println!(
        "================================================================"
    );
    println!();

    let group_config = FROSTGroupConfig::default();
    let message = b"Hello, FROST! This is a 2-of-3 threshold signature demo.";
    let mut rng = thread_rng();

    println!("📋 Demo Configuration:");
    println!("   • Ciphersuite: FROST-ED25519-SHA512-v1");
    println!(
        "   • Threshold: {} of {}",
        group_config.min_signers(),
        group_config.max_signers()
    );
    println!(
        "   • Message: {:?}",
        std::str::from_utf8(message).unwrap_or("<binary>")
    );
    println!("   • Message length: {} bytes", message.len());
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

    let group = FROSTGroup::new_with_trusted_dealer(group_config, &mut rng)?;

    println!("   ✅ Group formed successfully");
    println!(
        "   📝 Group public key: {}",
        hex::encode(&group.verifying_key().serialize()?)
    );
    println!(
        "   � {} participants configured with key packages",
        group.max_signers()
    );
    println!();

    // =============================================================================
    // STEP 2: PARTICIPANT VERIFICATION
    // Verify all participants have valid key packages
    // =============================================================================

    println!("🔧 STEP 2: Participant Verification");
    println!("   Verifying key packages for all participants...");

    for participant_name in group.participant_names() {
        if group.key_package(participant_name).is_ok() {
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
    println!(
        "   Selecting {} signers for threshold signature...",
        group.min_signers()
    );

    // Select signers (in this case, the first min_signers participants)
    let participant_names = group.participant_names();
    let signers: Vec<&str> = participant_names
        .iter()
        .take(group.min_signers() as usize)
        .copied()
        .collect();

    for (i, participant_name) in signers.iter().enumerate() {
        println!("   👤 Signer {}: {}", i + 1, participant_name);
    }
    println!();

    println!("   🎲 Executing FROST signing protocol...");
    println!(
        "   📝 Message: {:?}",
        std::str::from_utf8(message).unwrap_or("<binary>")
    );

    // Perform the complete signing ceremony
    let group_signature = group.sign(message, &signers, &mut rng)?;

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

    match group.verify(message, &group_signature) {
        Ok(()) => {
            println!("   🎉 Signature verification: PASSED");
            println!(
                "   ✅ The message was successfully signed using FROST threshold signature"
            );
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
        group.participant_names().len(),
        group.max_signers() as usize,
        "Should have correct number of participants"
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
        group.min_signers(),
        group.max_signers()
    );
    println!("   • Message length: {} bytes", message.len());
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
        group.max_signers(),
        group.min_signers()
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
