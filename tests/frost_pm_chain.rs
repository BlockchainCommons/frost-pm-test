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
    let res = ProvenanceMarkResolution::Quartile;
    let genesis_msg = FrostPmChain::genesis_message(&config, res);
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

    // Fake "image" for genesis
    let image_content = "demo image bytes";

    // Client generates genesis message and signs it
    let genesis_signature =
        group.sign(genesis_msg.as_bytes(), &["alice", "bob"], &mut OsRng)?;

    // Client generates Round-1 commitments for seq=1
    let (seq1_commitments, seq1_nonces) =
        group.round_1_commit(&["alice", "bob"], &mut OsRng)?;

    // Genesis from alice+bob
    let (mut chain, mark_0, receipt, root_1) = FrostPmChain::new_chain(
        group.clone(),
        genesis_signature,
        &seq1_commitments,
        res,
        Date::now(),
        Some(image_content),
    )?;

    println!("Genesis mark created: {}", mark_0.identifier());
    assert!(mark_0.is_genesis());

    // Create second mark with a different "image"
    let image2_content = "second image bytes";
    let mark2_date = Date::now();

    // Client generates message and Round-2 signature
    let message = FrostPmChain::next_mark_message(
        &chain,
        mark2_date.clone(),
        Some(image2_content),
    );
    let signature = chain.group().round_2_sign(
        &["alice", "bob"],
        &seq1_commitments,
        &seq1_nonces,
        &message,
    )?;

    // Client generates commitments for seq=2 before calling append_mark
    let (seq2_commitments, seq2_nonces) = chain
        .group()
        .round_1_commit(&["alice", "bob"], &mut OsRng)?;

    let (mark1, receipt, receipt_commitments) = chain.append_mark(
        mark2_date,
        Some(image2_content),
        &receipt,
        Some(root_1),
        signature,
        seq2_commitments,
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
    let signature3 = chain.group().round_2_sign(
        &["alice", "bob"],
        &receipt_commitments,
        &seq2_nonces,
        &message3,
    )?;

    // Client generates commitments for seq=3 before calling append_mark
    let (seq3_commitments, _seq3_nonces) = chain
        .group()
        .round_1_commit(&["alice", "bob"], &mut OsRng)?;

    let (mark2, _receipt, _receipt_commitments) = chain.append_mark(
        mark3_date,
        Some(image3_content),
        &receipt,
        Some(receipt.root),
        signature3,
        seq3_commitments,
    )?;

    println!("Third mark created: {}", mark2.identifier());

    // Verify the invariants with the PM crate
    assert!(mark_0.is_genesis());
    assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&[
        mark_0.clone(),
        mark1.clone(),
        mark2.clone()
    ]));
    assert!(mark_0.precedes(&mark1));
    assert!(mark1.precedes(&mark2));

    println!("All provenance mark chain invariants verified successfully!");
    println!("Chain ID: {}", hex::encode(mark_0.chain_id()));
    println!(
        "Mark 0: seq={}, hash={}",
        mark_0.seq(),
        hex::encode(mark_0.hash())
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
fn frost_pm_chain_date_monotonicity() -> Result<()> {
    let config = FrostGroupConfig::new(
        2,
        &["alice", "bob", "charlie"],
        "Date monotonicity test chain".to_string(),
    )?;

    // Client generates genesis message and signs it
    let res = ProvenanceMarkResolution::High;
    let genesis_msg = FrostPmChain::genesis_message(&config, res);
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let genesis_signature =
        group.sign(genesis_msg.as_bytes(), &["alice", "bob"], &mut OsRng)?;

    // Client generates Round-1 commitments for seq=1
    let (seq1_commitments, seq1_nonces) =
        group.round_1_commit(&["alice", "bob"], &mut OsRng)?;

    let genesis_time = Date::now();
    let (mut chain, _mark_0, receipt, _root_1) = FrostPmChain::new_chain(
        group,
        genesis_signature,
        &seq1_commitments,
        res,
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
    let signature_fail = chain.group().round_2_sign(
        &["alice", "bob"],
        &seq1_commitments,
        &seq1_nonces,
        &message_fail,
    )?;

    // Generate commitments for the test (even though it will fail)
    let (dummy_commitments, _dummy_nonces) = chain
        .group()
        .round_1_commit(&["alice", "bob"], &mut OsRng)?;

    let result = chain.append_mark(
        earlier_time,
        Some("test content 2"),
        &receipt,
        None,
        signature_fail,
        dummy_commitments,
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
    let res = ProvenanceMarkResolution::Low;
    let genesis_msg = FrostPmChain::genesis_message(&config, res);
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

    // Client generates genesis message and signs it
    let genesis_signature = group.sign(
        genesis_msg.as_bytes(),
        &["alice", "bob", "charlie"],
        &mut OsRng,
    )?;

    // Client generates Round-1 commitments for seq=1
    let (seq1_commitments, seq1_nonces) =
        group.round_1_commit(&["alice", "bob", "charlie"], &mut OsRng)?;

    // Genesis with alice, bob, charlie
    let (mut chain, mark_0, receipt, _root_1) = FrostPmChain::new_chain(
        group.clone(),
        genesis_signature,
        &seq1_commitments,
        res,
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
    let signature_next = chain.group().round_2_sign(
        &["alice", "bob", "charlie"],
        &seq1_commitments,
        &seq1_nonces,
        &message_next,
    )?;

    // Generate commitments for next sequence
    let (next_commitments, _next_nonces) = chain
        .group()
        .round_1_commit(&["alice", "bob", "charlie"], &mut OsRng)?;

    let (mark1, _receipt, _receipt_commitments) = chain.append_mark(
        mark_date,
        Some("test content 2"),
        &receipt,
        None,
        signature_next,
        next_commitments,
    )?;

    // Verify both marks are valid and form a proper chain
    assert!(mark_0.is_genesis());
    assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&[
        mark_0.clone(),
        mark1.clone()
    ]));
    assert!(mark_0.precedes(&mark1));

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
        let genesis_msg = FrostPmChain::genesis_message(group.config(), res);
        let genesis_signature = group.sign(
            genesis_msg.as_bytes(),
            &["alice", "bob"],
            &mut OsRng,
        )?;

        // Client generates Round-1 commitments for seq=1
        let (seq1_commitments, seq1_nonces) =
            group.round_1_commit(&["alice", "bob"], &mut OsRng)?;

        // Genesis
        let (mut chain, mark_0, receipt, _root_1) = FrostPmChain::new_chain(
            group.clone(),
            genesis_signature,
            &seq1_commitments,
            res,
            Date::now(),
            Some("test content 1"),
        )?;

        // Verify genesis properties
        assert!(mark_0.is_genesis());
        assert_eq!(mark_0.res(), res);
        assert_eq!(mark_0.key().len(), expected_link_len);
        assert_eq!(mark_0.chain_id(), mark_0.key()); // Genesis invariant
        println!(
            "  ✓ Genesis mark: {} ({})",
            mark_0.identifier(),
            mark_0.key().len()
        );

        // Second mark
        let mark2_date = Date::now();
        let message2 = FrostPmChain::next_mark_message(
            &chain,
            mark2_date.clone(),
            Some("test content 2"),
        );
        let signature2 = chain.group().round_2_sign(
            &["alice", "bob"],
            &seq1_commitments,
            &seq1_nonces,
            &message2,
        )?;

        // Generate commitments for seq=2
        let (seq2_commitments, seq2_nonces) = chain
            .group()
            .round_1_commit(&["alice", "bob"], &mut OsRng)?;

        let (mark1, receipt, receipt_commitments) = chain.append_mark(
            mark2_date,
            Some("test content 2"),
            &receipt,
            None,
            signature2,
            seq2_commitments,
        )?;

        // Verify chain properties
        assert_eq!(mark1.seq(), 1);
        assert_eq!(mark1.res(), res);
        assert_eq!(mark1.key().len(), expected_link_len);
        assert_eq!(mark1.chain_id(), mark_0.chain_id());
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
        let signature3 = chain.group().round_2_sign(
            &["alice", "bob"],
            &receipt_commitments,
            &seq2_nonces,
            &message3,
        )?;

        // Generate commitments for seq=3
        let (seq3_commitments, _seq3_nonces) = chain
            .group()
            .round_1_commit(&["alice", "bob"], &mut OsRng)?;

        let (mark2, _receipt, _receipt_commitments) = chain.append_mark(
            mark3_date,
            Some("test content 3"),
            &receipt,
            None,
            signature3,
            seq3_commitments,
        )?;

        // Verify chain properties
        assert_eq!(mark2.seq(), 2);
        assert_eq!(mark2.res(), res);
        assert_eq!(mark2.key().len(), expected_link_len);
        assert_eq!(mark2.chain_id(), mark_0.chain_id());
        println!(
            "  ✓ Third mark: {} ({})",
            mark2.identifier(),
            mark2.key().len()
        );

        // Verify complete chain integrity
        let marks = vec![mark_0.clone(), mark1.clone(), mark2.clone()];
        assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&marks));
        assert!(mark_0.precedes(&mark1));
        assert!(mark1.precedes(&mark2));

        println!("  ✓ Chain integrity verified for {} resolution\n", name);
    }

    Ok(())
}
