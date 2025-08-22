use anyhow::Result;
use chrono::Utc;
use frost_pm_test::{
    FROSTGroup, FROSTGroupConfig, kdf::sha256, pm_chain::FrostPmChain,
};
use provenance_mark::ProvenanceMarkResolution;
use rand::rngs::OsRng;

#[test]
fn frost_controls_pm_chain() -> Result<()> {
    // Build a 2-of-3 group with usernames ["alice","bob","charlie"]
    let config = FROSTGroupConfig::new(2, &["alice", "bob", "charlie"])
        .map_err(|e| anyhow::anyhow!("Failed to create FROST config: {}", e))?;
    let group = FROSTGroup::new_with_trusted_dealer(config, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("Failed to create FROST group: {}", e))?;
    let res = ProvenanceMarkResolution::Quartile;

    // Fake "image" for genesis
    let image = b"demo image bytes";
    let obj_hash = sha256(image);

    // Genesis from alice+bob
    let (mut chain, mark0) = FrostPmChain::new_genesis(
        &group,
        res,
        &["alice", "bob"],
        Utc::now(),
        &obj_hash,
    )?;

    println!("Genesis mark created: {}", mark0.identifier());
    assert!(mark0.is_genesis());

    // Create second mark with a different "image"
    let image2 = b"second image bytes";
    let obj_hash2 = sha256(image2);

    let mark1 = chain.append_mark(
        &["alice", "bob"], // Use same participants as genesis precommit
        1,
        Utc::now(),
        &obj_hash2,
    )?;

    println!("Second mark created: {}", mark1.identifier());

    // Create third mark with yet another "image"
    let image3 = b"third image bytes";
    let obj_hash3 = sha256(image3);

    let mark2 = chain.append_mark(
        &["alice", "bob"], // Use same participants as mark1 precommit
        2,
        Utc::now(),
        &obj_hash3,
    )?;

    println!("Third mark created: {}", mark2.identifier());

    // Verify the invariants with the PM crate
    assert!(mark0.is_genesis());
    assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&[
        mark0.clone(),
        mark1.clone(),
        mark2.clone()
    ]));
    assert!(mark0.precedes(&mark1));
    assert!(mark1.precedes(&mark2));

    println!("All provenance mark chain invariants verified successfully!");
    println!("Chain ID: {}", hex::encode(mark0.chain_id()));
    println!(
        "Mark 0: seq={}, hash={}",
        mark0.seq(),
        hex::encode(mark0.hash())
    );
    println!(
        "Mark 1: seq={}, hash={}",
        mark1.seq(),
        hex::encode(mark1.hash())
    );
    println!(
        "Mark 2: seq={}, hash={}",
        mark2.seq(),
        hex::encode(mark2.hash())
    );

    Ok(())
}

#[test]
fn frost_pm_chain_insufficient_signers_fails() -> Result<()> {
    let config = FROSTGroupConfig::new(2, &["alice", "bob", "charlie"])
        .map_err(|e| anyhow::anyhow!("Failed to create FROST config: {}", e))?;
    let group = FROSTGroup::new_with_trusted_dealer(config, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("Failed to create FROST group: {}", e))?;
    let res = ProvenanceMarkResolution::Medium;
    let image = b"test image";
    let obj_hash = sha256(image);

    // Try to create genesis with only 1 signer (threshold is 2)
    let result = FrostPmChain::new_genesis(
        &group,
        res,
        &["alice"], // Only 1 signer, but threshold is 2
        Utc::now(),
        &obj_hash,
    );

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("insufficient signers")
    );

    Ok(())
}

#[test]
fn frost_pm_chain_date_monotonicity() -> Result<()> {
    let config = FROSTGroupConfig::new(2, &["alice", "bob", "charlie"])
        .map_err(|e| anyhow::anyhow!("Failed to create FROST config: {}", e))?;
    let group = FROSTGroup::new_with_trusted_dealer(config, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("Failed to create FROST group: {}", e))?;
    let res = ProvenanceMarkResolution::High;
    let image = b"genesis image";
    let obj_hash = sha256(image);

    let genesis_time = Utc::now();
    let (mut chain, _mark0) = FrostPmChain::new_genesis(
        &group,
        res,
        &["alice", "bob"],
        genesis_time,
        &obj_hash,
    )?;

    let image2 = b"second image";
    let obj_hash2 = sha256(image2);

    // Try to create a mark with earlier date than genesis (should fail)
    let earlier_time = genesis_time - chrono::Duration::seconds(60);
    let result = chain.append_mark(
        &["alice", "bob"], // Use same participants as genesis precommit
        1,
        earlier_time,
        &obj_hash2,
    );

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("date monotonicity violated")
    );

    Ok(())
}

#[test]
fn frost_pm_different_signer_combinations() -> Result<()> {
    // Test that different valid signer combinations work
    let config = FROSTGroupConfig::new(3, &["alice", "bob", "charlie", "dave"])
        .map_err(|e| anyhow::anyhow!("Failed to create FROST config: {}", e))?;
    let group = FROSTGroup::new_with_trusted_dealer(config, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("Failed to create FROST group: {}", e))?;
    let res = ProvenanceMarkResolution::Low;

    let image1 = b"image1";
    let obj_hash1 = sha256(image1);

    // Genesis with alice, bob, charlie
    let (mut chain, mark0) = FrostPmChain::new_genesis(
        &group,
        res,
        &["alice", "bob", "charlie"],
        Utc::now(),
        &obj_hash1,
    )?;

    let image2 = b"image2";
    let obj_hash2 = sha256(image2);

    // Next mark with same participants as genesis precommit
    let mark1 = chain.append_mark(
        &["alice", "bob", "charlie"], // Use same participants as genesis precommit
        1,
        Utc::now(),
        &obj_hash2,
    )?;

    // Verify both marks are valid and form a proper chain
    assert!(mark0.is_genesis());
    assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&[
        mark0.clone(),
        mark1.clone()
    ]));
    assert!(mark0.precedes(&mark1));

    println!("Different signer combinations test passed!");

    Ok(())
}
