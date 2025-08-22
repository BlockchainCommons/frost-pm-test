use anyhow::Result;
use chrono::Utc;
use frost_pm_test::{FrostGroup, FrostGroupConfig, pm_chain::FrostPmChain};
use provenance_mark::ProvenanceMarkResolution;
use rand::rngs::OsRng;

#[test]
fn frost_controls_pm_chain() -> Result<()> {
    // Build a 2-of-3 group with usernames ["alice","bob","charlie"]
    let config = FrostGroupConfig::new(2, &["alice", "bob", "charlie"])?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let res = ProvenanceMarkResolution::Quartile;

    // Fake "image" for genesis
    let image_content = "demo image bytes";

    // Genesis from alice+bob
    let (mut chain, mark0) = FrostPmChain::new_genesis(
        &group,
        res,
        &["alice", "bob"],
        Utc::now(),
        Some(image_content),
    )?;

    println!("Genesis mark created: {}", mark0.identifier());
    assert!(mark0.is_genesis());

    // Create second mark with a different "image"
    let image2_content = "second image bytes";

    let mark1 = chain.append_mark(
        &["alice", "bob"], // Use same participants as genesis precommit
        1,
        Utc::now(),
        Some(image2_content),
    )?;

    println!("Second mark created: {}", mark1.identifier());

    // Create third mark with yet another "image"
    let image3_content = "third image bytes";

    let mark2 = chain.append_mark(
        &["alice", "bob"], // Use same participants as mark1 precommit
        2,
        Utc::now(),
        Some(image3_content),
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
    let config = FrostGroupConfig::new(2, &["alice", "bob", "charlie"])?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let res = ProvenanceMarkResolution::Medium;

    // Try to create genesis with only 1 signer (threshold is 2)
    let result = FrostPmChain::new_genesis(
        &group,
        res,
        &["alice"], // Only 1 signer, but threshold is 2
        Utc::now(),
        Some("test content"),
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
    let config = FrostGroupConfig::new(2, &["alice", "bob", "charlie"])?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let res = ProvenanceMarkResolution::High;

    let genesis_time = Utc::now();
    let (mut chain, _mark0) = FrostPmChain::new_genesis(
        &group,
        res,
        &["alice", "bob"],
        genesis_time,
        Some("test content"),
    )?;

    // Try to create a mark with earlier date than genesis (should fail)
    let earlier_time = genesis_time - chrono::Duration::seconds(60);
    let result = chain.append_mark(
        &["alice", "bob"], // Use same participants as genesis precommit
        1,
        earlier_time,
        Some("test content 2"),
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
    let config = FrostGroupConfig::new(2, &["alice", "bob", "charlie"])?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let res = ProvenanceMarkResolution::Low;

    // Genesis with alice, bob, charlie
    let (mut chain, mark0) = FrostPmChain::new_genesis(
        &group,
        res,
        &["alice", "bob", "charlie"],
        Utc::now(),
        Some("test content 1"),
    )?;

    // Next mark with same participants as genesis precommit
    let mark1 = chain.append_mark(
        &["alice", "bob", "charlie"], // Use same participants as genesis precommit
        1,
        Utc::now(),
        Some("test content 2"),
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

#[test]
fn frost_pm_all_resolutions() -> Result<()> {
    let config = FrostGroupConfig::new(2, &["alice", "bob", "charlie"])?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

    let resolutions = [
        (ProvenanceMarkResolution::Low, "Low", 4),
        (ProvenanceMarkResolution::Medium, "Medium", 8),
        (ProvenanceMarkResolution::Quartile, "Quartile", 16),
        (ProvenanceMarkResolution::High, "High", 32),
    ];

    for (res, name, expected_link_len) in resolutions {
        println!(
            "Testing {} resolution ({}-byte links)",
            name, expected_link_len
        );

        // Test data for this resolution

        // Genesis
        let (mut chain, mark0) = FrostPmChain::new_genesis(
            &group,
            res,
            &["alice", "bob"],
            Utc::now(),
            Some("test content 1"),
        )?;

        // Verify genesis properties
        assert!(mark0.is_genesis());
        assert_eq!(mark0.res(), res);
        assert_eq!(mark0.key().len(), expected_link_len);
        assert_eq!(mark0.chain_id(), mark0.key()); // Genesis invariant
        println!(
            "  ✓ Genesis mark: {} ({})",
            mark0.identifier(),
            mark0.key().len()
        );

        // Second mark
        let mark1 = chain.append_mark(
            &["alice", "bob"], // Same participants as genesis precommit
            1,
            Utc::now(),
            Some("test content 2"),
        )?;

        // Verify chain properties
        assert_eq!(mark1.seq(), 1);
        assert_eq!(mark1.res(), res);
        assert_eq!(mark1.key().len(), expected_link_len);
        assert_eq!(mark1.chain_id(), mark0.chain_id());
        println!(
            "  ✓ Second mark: {} ({})",
            mark1.identifier(),
            mark1.key().len()
        );

        // Third mark
        let mark2 = chain.append_mark(
            &["alice", "bob"], // Same participants as mark1 precommit
            2,
            Utc::now(),
            Some("test content 3"),
        )?;

        // Verify chain properties
        assert_eq!(mark2.seq(), 2);
        assert_eq!(mark2.res(), res);
        assert_eq!(mark2.key().len(), expected_link_len);
        assert_eq!(mark2.chain_id(), mark0.chain_id());
        println!(
            "  ✓ Third mark: {} ({})",
            mark2.identifier(),
            mark2.key().len()
        );

        // Verify complete chain integrity
        let marks = vec![mark0.clone(), mark1.clone(), mark2.clone()];
        assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&marks));
        assert!(mark0.precedes(&mark1));
        assert!(mark1.precedes(&mark2));

        println!("  ✓ Chain integrity verified for {} resolution\n", name);
    }

    Ok(())
}
