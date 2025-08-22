use anyhow::Result;
use dcbor::Date;
use frost_pm_test::{FrostGroup, FrostGroupConfig, pm_chain::FrostPmChain};
use provenance_mark::ProvenanceMarkResolution;
use rand::rngs::OsRng;

#[test]
fn frost_controls_pm_chain() -> Result<()> {
    // Build a 2-of-3 group with usernames ["alice","bob","charlie"]
    let config = FrostGroupConfig::new(
        2,
        &["alice", "bob", "charlie"],
        "Provenance mark chain demonstration".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let res = ProvenanceMarkResolution::Quartile;

    // Fake "image" for genesis
    let image_content = "demo image bytes";

    // Client generates genesis message and signs it
    let genesis_msg = FrostPmChain::genesis_message(&group);
    let genesis_signature =
        group.sign(genesis_msg.as_bytes(), &["alice", "bob"], &mut OsRng)?;

    // Client generates Round-1 commitments for seq=1
    let (seq1_commitments, seq1_nonces) =
        FrostPmChain::generate_round1_commitments(
            &group,
            &["alice", "bob"],
            &mut OsRng,
        )?;

    // Genesis from alice+bob
    let (mut chain, mark0, receipt, nonces) = FrostPmChain::new_genesis(
        group.clone(),
        genesis_signature,
        seq1_commitments,
        seq1_nonces,
        res,
        &["alice", "bob"],
        Date::now(),
        Some(image_content),
    )?;

    println!("Genesis mark created: {}", mark0.identifier());
    assert!(mark0.is_genesis());

    // Create second mark with a different "image"
    let image2_content = "second image bytes";
    let mark2_date = Date::now();

    // Client generates message and Round-2 signature
    let message = FrostPmChain::next_mark_message(
        &chain,
        mark2_date.clone(),
        Some(image2_content),
    );
    let signature = FrostPmChain::generate_round2_signature(
        chain.group(),
        &["alice", "bob"],
        &receipt.commitments,
        &nonces,
        &message,
    )?;

    let (mark1, receipt, nonces) = chain.append_mark(
        &["alice", "bob"], // Use same participants as genesis precommit
        mark2_date,
        Some(image2_content),
        &receipt,
        signature,
    )?;

    println!("Second mark created: {}", mark1.identifier());

    // Create third mark with yet another "image"
    let image3_content = "third image bytes";
    let mark3_date = Date::now();

    // Client generates message and Round-2 signature
    let message3 = FrostPmChain::next_mark_message(
        &chain,
        mark3_date.clone(),
        Some(image3_content),
    );
    let signature3 = FrostPmChain::generate_round2_signature(
        chain.group(),
        &["alice", "bob"],
        &receipt.commitments,
        &nonces,
        &message3,
    )?;

    let (mark2, _receipt, _nonces) = chain.append_mark(
        &["alice", "bob"], // Use same participants as mark1 precommit
        mark3_date,
        Some(image3_content),
        &receipt,
        signature3,
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
    let config = FrostGroupConfig::new(
        2,
        &["alice", "bob", "charlie"],
        "Insufficient signers test chain".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let res = ProvenanceMarkResolution::Medium;

    // Generate genesis message and try to sign with insufficient signers - this should fail at signing stage
    let genesis_msg = FrostPmChain::genesis_message(&group);
    let sign_result =
        group.sign(genesis_msg.as_bytes(), &["alice"], &mut OsRng); // Only 1 signer, but threshold is 2

    // The signing should fail due to insufficient signers
    assert!(sign_result.is_err());

    // But let's also test that new_genesis would fail if somehow we got a signature
    // We'll create a valid signature first
    let valid_signature =
        group.sign(genesis_msg.as_bytes(), &["alice", "bob"], &mut OsRng)?;

    // We also need valid commitments for the test
    let (seq1_commitments, seq1_nonces) =
        FrostPmChain::generate_round1_commitments(
            &group,
            &["alice", "bob"],
            &mut OsRng,
        )?;

    // Try to create genesis with only 1 signer in the signers list (threshold validation)
    let result = FrostPmChain::new_genesis(
        group,
        valid_signature,
        seq1_commitments,
        seq1_nonces,
        res,
        &["alice"], // Only 1 signer, but threshold is 2
        Date::now(),
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
    let config = FrostGroupConfig::new(
        2,
        &["alice", "bob", "charlie"],
        "Date monotonicity test chain".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let res = ProvenanceMarkResolution::High;

    // Client generates genesis message and signs it
    let genesis_msg = FrostPmChain::genesis_message(&group);
    let genesis_signature =
        group.sign(genesis_msg.as_bytes(), &["alice", "bob"], &mut OsRng)?;

    // Client generates Round-1 commitments for seq=1
    let (seq1_commitments, seq1_nonces) =
        FrostPmChain::generate_round1_commitments(
            &group,
            &["alice", "bob"],
            &mut OsRng,
        )?;

    let genesis_time = Date::now();
    let (mut chain, _mark0, receipt, nonces) = FrostPmChain::new_genesis(
        group,
        genesis_signature,
        seq1_commitments,
        seq1_nonces,
        res,
        &["alice", "bob"],
        genesis_time.clone(),
        Some("test content"),
    )?;

    // Try to create a mark with earlier date than genesis (should fail)
    let earlier_time = Date::from_datetime(
        genesis_time.datetime() - chrono::Duration::seconds(60),
    );

    // Even though this will fail, we need to provide a signature
    let message_fail = FrostPmChain::next_mark_message(
        &chain,
        earlier_time.clone(),
        Some("test content 2"),
    );
    let signature_fail = FrostPmChain::generate_round2_signature(
        chain.group(),
        &["alice", "bob"],
        &receipt.commitments,
        &nonces,
        &message_fail,
    )?;

    let result = chain.append_mark(
        &["alice", "bob"], // Use same participants as genesis precommit
        earlier_time,
        Some("test content 2"),
        &receipt,
        signature_fail,
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
    let config = FrostGroupConfig::new(
        2,
        &["alice", "bob", "charlie"],
        "Different signer combinations test chain".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let res = ProvenanceMarkResolution::Low;

    // Client generates genesis message and signs it
    let genesis_msg = FrostPmChain::genesis_message(&group);
    let genesis_signature = group.sign(
        genesis_msg.as_bytes(),
        &["alice", "bob", "charlie"],
        &mut OsRng,
    )?;

    // Client generates Round-1 commitments for seq=1
    let (seq1_commitments, seq1_nonces) =
        FrostPmChain::generate_round1_commitments(
            &group,
            &["alice", "bob", "charlie"],
            &mut OsRng,
        )?;

    // Genesis with alice, bob, charlie
    let (mut chain, mark0, receipt, nonces) = FrostPmChain::new_genesis(
        group.clone(),
        genesis_signature,
        seq1_commitments,
        seq1_nonces,
        res,
        &["alice", "bob", "charlie"],
        Date::now(),
        Some("test content 1"),
    )?;

    // Next mark with same participants as genesis precommit
    let mark_date = Date::now();
    let message_next = FrostPmChain::next_mark_message(
        &chain,
        mark_date.clone(),
        Some("test content 2"),
    );
    let signature_next = FrostPmChain::generate_round2_signature(
        chain.group(),
        &["alice", "bob", "charlie"],
        &receipt.commitments,
        &nonces,
        &message_next,
    )?;

    let (mark1, _receipt, _nonces) = chain.append_mark(
        &["alice", "bob", "charlie"], // Use same participants as genesis precommit
        mark_date,
        Some("test content 2"),
        &receipt,
        signature_next,
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
    let config = FrostGroupConfig::new(
        2,
        &["alice", "bob", "charlie"],
        "All resolutions test chain".to_string(),
    )?;
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

        // Client generates genesis message and signs it
        let genesis_msg = FrostPmChain::genesis_message(&group);
        let genesis_signature = group.sign(
            genesis_msg.as_bytes(),
            &["alice", "bob"],
            &mut OsRng,
        )?;

        // Client generates Round-1 commitments for seq=1
        let (seq1_commitments, seq1_nonces) =
            FrostPmChain::generate_round1_commitments(
                &group,
                &["alice", "bob"],
                &mut OsRng,
            )?;

        // Genesis
        let (mut chain, mark0, receipt, nonces) = FrostPmChain::new_genesis(
            group.clone(),
            genesis_signature,
            seq1_commitments,
            seq1_nonces,
            res,
            &["alice", "bob"],
            Date::now(),
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
        let mark2_date = Date::now();
        let message2 = FrostPmChain::next_mark_message(
            &chain,
            mark2_date.clone(),
            Some("test content 2"),
        );
        let signature2 = FrostPmChain::generate_round2_signature(
            chain.group(),
            &["alice", "bob"],
            &receipt.commitments,
            &nonces,
            &message2,
        )?;

        let (mark1, receipt, nonces) = chain.append_mark(
            &["alice", "bob"], // Same participants as genesis precommit
            mark2_date,
            Some("test content 2"),
            &receipt,
            signature2,
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
        let mark3_date = Date::now();
        let message3 = FrostPmChain::next_mark_message(
            &chain,
            mark3_date.clone(),
            Some("test content 3"),
        );
        let signature3 = FrostPmChain::generate_round2_signature(
            chain.group(),
            &["alice", "bob"],
            &receipt.commitments,
            &nonces,
            &message3,
        )?;

        let (mark2, _receipt, _nonces) = chain.append_mark(
            &["alice", "bob"], // Same participants as mark1 precommit
            mark3_date,
            Some("test content 3"),
            &receipt,
            signature3,
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
