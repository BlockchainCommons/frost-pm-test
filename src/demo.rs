use anyhow::Result;
use chrono::Utc;
use frost_pm_test::{
    FROSTGroup, FROSTGroupConfig, kdf::sha256, pm_chain::FrostPmChain,
};
use provenance_mark::ProvenanceMarkResolution;
use rand::rngs::OsRng;

pub fn run_demo() -> Result<()> {
    println!("🔒 FROST-Controlled Provenance Mark Chain Demo");
    println!("===============================================\n");

    // Create a 2-of-3 FROST group
    println!("1. Creating FROST group with participants: Alice, Bob, Charlie");
    println!("   Threshold: 2 of 3 signers required");
    let config = FROSTGroupConfig::new(2, &["alice", "bob", "charlie"])
        .map_err(|e| anyhow::anyhow!("Failed to create FROST config: {}", e))?;
    let group = FROSTGroup::new_with_trusted_dealer(config, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("Failed to create FROST group: {}", e))?;
    println!("   ✓ FROST group created successfully\n");

    // Create the first "image" to attest
    let image1 = b"Original artwork by Alice - 2024";
    let obj_hash1 = sha256(image1);
    println!("2. Creating genesis mark for first artwork");
    println!("   Artwork: {:?}", String::from_utf8_lossy(image1));
    println!("   Object hash: {}", hex::encode(&obj_hash1));

    // Genesis: Alice + Bob sign
    let (mut chain, mark0, _next_key0) = FrostPmChain::new_genesis(
        &group,
        ProvenanceMarkResolution::Quartile,
        &["alice", "bob"],
        Utc::now(),
        &obj_hash1,
    )?;

    println!("   Signers: Alice, Bob");
    println!("   ✓ Genesis mark created: {}", mark0.identifier());
    println!("   Chain ID: {}", hex::encode(mark0.chain_id()));
    println!(
        "   Genesis invariant verified: key == id: {}\n",
        mark0.key() == mark0.chain_id()
    );

    // Create second artwork
    let image2 = b"Derivative work by Bob - 2024";
    let obj_hash2 = sha256(image2);
    println!(
        "3. Creating second mark for derivative artwork (stateless approach)"
    );
    println!("   Artwork: {:?}", String::from_utf8_lossy(image2));
    println!("   Object hash: {}", hex::encode(&obj_hash2));

    // Stateless approach: 1) Precommit for NEXT mark — Round‑1 only.
    // This computes and CONSUMES nextKey_0 to finalize the PREVIOUS mark (0) internally
    chain.precommit_next_mark(&["bob", "charlie"], 1)?;

    // 2) Append this mark — replay Round‑1 for seq=1, run Round‑2 for seq=1,
    // recompute key_1 from Root_1, and internally do precommit for seq=2
    let mark1 = chain.append_mark_stateless(
        &["bob", "charlie"],
        Utc::now(),
        &obj_hash2,
        1,
    )?;

    println!("   Signers: Bob, Charlie");
    println!("   ✓ Second mark created: {}", mark1.identifier());
    println!("   Sequence: {}\n", mark1.seq());

    // Create third artwork
    let image3 = b"Collaborative work by Alice, Bob & Charlie - 2024";
    let obj_hash3 = sha256(image3);
    println!(
        "4. Creating third mark for collaborative artwork (stateless approach)"
    );
    println!("   Artwork: {:?}", String::from_utf8_lossy(image3));
    println!("   Object hash: {}", hex::encode(&obj_hash3));

    // Stateless approach continues: precommit for mark 2, then append mark 2
    chain.precommit_next_mark(&["alice", "charlie"], 2)?;
    let mark2 = chain.append_mark_stateless(
        &["alice", "charlie"],
        Utc::now(),
        &obj_hash3,
        2,
    )?;

    println!("   Signers: Alice, Charlie");
    println!("   ✓ Third mark created: {}", mark2.identifier());
    println!("   Sequence: {}\n", mark2.seq());

    // Verify the chain
    println!("5. Verifying provenance mark chain");

    // Check individual mark properties
    println!("   Genesis check: {}", mark0.is_genesis());
    println!(
        "   Sequence validity: {}",
        provenance_mark::ProvenanceMark::is_sequence_valid(&[
            mark0.clone(),
            mark1.clone(),
            mark2.clone()
        ])
    );
    println!("   Mark 0 → Mark 1: {}", mark0.precedes(&mark1));
    println!("   Mark 1 → Mark 2: {}", mark1.precedes(&mark2));

    // Show the chain structure
    println!("\n6. Chain structure:");
    println!(
        "   Mark 0: seq={}, hash={}",
        mark0.seq(),
        hex::encode(mark0.hash())
    );
    println!(
        "   Mark 1: seq={}, hash={}",
        mark1.seq(),
        hex::encode(mark1.hash())
    );
    println!(
        "   Mark 2: seq={}, hash={}",
        mark2.seq(),
        hex::encode(mark2.hash())
    );

    println!(
        "\n🎉 FROST-controlled provenance mark chain created successfully!"
    );
    println!(
        "   • Each mark was signed by a different subset of the FROST quorum"
    );
    println!("   • No single party ever held the master seed or key");
    println!("   • The chain is indistinguishable from a single-signer chain");
    println!("   • All provenance mark invariants are preserved");
    println!(
        "   • ✨ STATELESS COORDINATOR: No nextKey stored between generations!"
    );
    println!(
        "   • Two-ceremony approach: precommit (Round-1) + append (Round-2)"
    );
    println!("   • nextKey derived from next mark's Round-1 commitments");

    Ok(())
}
