use anyhow::Result;
use dcbor::Date;
use frost_pm_test::{FrostGroup, FrostGroupConfig, pm_chain::FrostPmChain};
use provenance_mark::ProvenanceMarkResolution;
use rand::rngs::OsRng;

#[test]
fn frost_controls_pm_chain() -> Result<()> {
    // Build a 2-of-3 group with usernames ["Alice","Bob","Charlie"]
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Charlie"],
        "Provenance mark chain demonstration".to_string(),
    )?;
    let res = ProvenanceMarkResolution::Quartile;
    let message_0 = FrostPmChain::genesis_message(&config, res);
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

    // Fake "image" for genesis
    let image_content = "demo image bytes";

    // Client generates genesis message and signs it
    let signers = &["Alice", "Bob"];
    let (commitments_0, nonces_0) =
        group.round_1_commit(signers, &mut OsRng)?;
    let signature_0 = group.round_2_sign(
        signers,
        &commitments_0,
        &nonces_0,
        message_0.as_bytes(),
    )?;

    // Client generates Round-1 commitments for seq=1
    let (commitments_1, nonces_1) =
        group.round_1_commit(signers, &mut OsRng)?;

    // Genesis from Alice+Bob
    let (mut chain, mark_0, root_1) = FrostPmChain::new_chain(
        group.clone(),
        signature_0,
        &commitments_1,
        res,
        Date::now(),
        Some(image_content),
    )?;

    println!("Genesis mark created: {}", mark_0.identifier());
    assert!(mark_0.is_genesis());

    // Create second mark with a different "image"
    let content_2 = "second image bytes";
    let date_2 = Date::now();

    // Client generates message and Round-2 signature
    let message = FrostPmChain::next_mark_message(
        &chain,
        date_2.clone(),
        Some(content_2),
    );
    let signature = chain.group().round_2_sign(
        signers,
        &commitments_1,
        &nonces_1,
        &message,
    )?;

    // Client generates commitments for seq=2 before calling append_mark
    let (commitments_2, nonces_2) =
        chain.group().round_1_commit(signers, &mut OsRng)?;

    let (mark_1, receipt_root, receipt_commitments) = chain
        .append_mark(
            date_2,
            Some(content_2),
            Some(root_1),
            signature,
            commitments_2,
        )?;

    println!("Mark 1 created: {}", mark_1.identifier());

    // Create mark 2 with yet another "image"
    let content_3 = "mark 2 image bytes";
    let date_3 = Date::now();

    // Client generates message and Round-2 signature
    let message_3 = FrostPmChain::next_mark_message(
        &chain,
        date_3.clone(),
        Some(content_3),
    );
    let signature_3 = chain.group().round_2_sign(
        signers,
        &receipt_commitments,
        &nonces_2,
        &message_3,
    )?;

    // Client generates commitments for seq=3 before calling append_mark
    let (commitments_3, _nonces_3) =
        chain.group().round_1_commit(signers, &mut OsRng)?;

    let (mark_2, _receipt_root, _receipt_commitments) = chain
        .append_mark(
            date_3,
            Some(content_3),
            Some(receipt_root),
            signature_3,
            commitments_3,
        )?;

    println!("Third mark created: {}", mark_2.identifier());

    // Verify the invariants with the PM crate
    assert!(mark_0.is_genesis());
    assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&[
        mark_0.clone(),
        mark_1.clone(),
        mark_2.clone()
    ]));
    assert!(mark_0.precedes(&mark_1));
    assert!(mark_1.precedes(&mark_2));

    println!("All provenance mark chain invariants verified successfully!");
    println!("Chain ID: {}", hex::encode(mark_0.chain_id()));
    println!(
        "Mark 0: seq={}, hash={}",
        mark_0.seq(),
        hex::encode(mark_0.hash())
    );
    println!(
        "Mark 1: seq={}, hash={}",
        mark_1.seq(),
        hex::encode(mark_1.hash())
    );
    println!(
        "Mark 2: seq={}, hash={}",
        mark_2.seq(),
        hex::encode(mark_2.hash())
    );

    Ok(())
}

#[test]
fn frost_pm_chain_date_monotonicity() -> Result<()> {
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Charlie"],
        "Date monotonicity test chain".to_string(),
    )?;

    // Client generates genesis message and signs it
    let res = ProvenanceMarkResolution::High;
    let message_0 = FrostPmChain::genesis_message(&config, res);
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let signers = &["Alice", "Bob"];
    let (commitments_0, nonces_0) =
        group.round_1_commit(signers, &mut OsRng)?;
    let signature_0 = group.round_2_sign(
        signers,
        &commitments_0,
        &nonces_0,
        message_0.as_bytes(),
    )?;

    // Client generates Round-1 commitments for seq=1
    let (commitments_1, nonces_1) =
        group.round_1_commit(signers, &mut OsRng)?;

    let date_0 = Date::now();
    let (mut chain, _mark_0, root_1) = FrostPmChain::new_chain(
        group,
        signature_0,
        &commitments_1,
        res,
        date_0.clone(),
        Some("test content"),
    )?;

    // Try to create a mark with earlier date than genesis (should fail)
    let earlier_time =
        Date::from_datetime(date_0.datetime() - chrono::Duration::seconds(60));

    // Even though this will fail, we need to provide a signature
    let message_fail = FrostPmChain::next_mark_message(
        &chain,
        earlier_time.clone(),
        Some("test content 2"),
    );
    let signature_fail = chain.group().round_2_sign(
        signers,
        &commitments_1,
        &nonces_1,
        &message_fail,
    )?;

    // Generate commitments for the test (even though it will fail)
    let (dummy_commitments, _dummy_nonces) =
        chain.group().round_1_commit(signers, &mut OsRng)?;

    let result = chain.append_mark(
        earlier_time,
        Some("test content 2"),
        Some(root_1),
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
        &["Alice", "Bob", "Charlie"],
        "Different signer combinations test chain".to_string(),
    )?;
    let res = ProvenanceMarkResolution::Low;
    let message_0 = FrostPmChain::genesis_message(&config, res);
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

    // Client generates genesis message and signs it
    let signers = &["Alice", "Bob", "Charlie"];
    let (commitments_0, nonces_0) =
        group.round_1_commit(signers, &mut OsRng)?;
    let signature_0 = group.round_2_sign(
        signers,
        &commitments_0,
        &nonces_0,
        message_0.as_bytes(),
    )?;

    // Client generates Round-1 commitments for seq=1
    let (commitments_1, nonces_1) =
        group.round_1_commit(signers, &mut OsRng)?;

    // Genesis with Alice, Bob, Charlie
    let date_0 = Date::now();
    let (mut chain, mark_0, root_1) = FrostPmChain::new_chain(
        group.clone(),
        signature_0,
        &commitments_1,
        res,
        date_0,
        Some("test content 1"),
    )?;

    // Next mark with same participants as genesis precommit
    let date_1 = Date::now();
    let message_1 = FrostPmChain::next_mark_message(
        &chain,
        date_1.clone(),
        Some("test content 2"),
    );
    let signature_1 = chain.group().round_2_sign(
        signers,
        &commitments_1,
        &nonces_1,
        &message_1,
    )?;

    // Generate commitments for next sequence
    let (commitments_2, _nonces_2) =
        chain.group().round_1_commit(signers, &mut OsRng)?;

    let (mark_1, _receipt_root, _receipt_commitments) = chain
        .append_mark(
            date_1,
            Some("test content 2"),
            Some(root_1),
            signature_1,
            commitments_2,
        )?;

    // Verify both marks are valid and form a proper chain
    assert!(mark_0.is_genesis());
    assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&[
        mark_0.clone(),
        mark_1.clone()
    ]));
    assert!(mark_0.precedes(&mark_1));

    println!("Different signer combinations test passed!");

    Ok(())
}

#[test]
fn frost_pm_all_resolutions() -> Result<()> {
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Charlie"],
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
        let message_0 = FrostPmChain::genesis_message(group.config(), res);
        let signers = &["Alice", "Bob"];
        let (commitments_0, nonces_0) =
            group.round_1_commit(signers, &mut OsRng)?;
        let signature_0 = group.round_2_sign(
            signers,
            &commitments_0,
            &nonces_0,
            message_0.as_bytes(),
        )?;

        // Client generates Round-1 commitments for seq=1
        let (commitments_1, nonces_1) =
            group.round_1_commit(signers, &mut OsRng)?;

        // Genesis
        let date_0 = Date::now();
        let (mut chain, mark_0, root_1) = FrostPmChain::new_chain(
            group.clone(),
            signature_0,
            &commitments_1,
            res,
            date_0,
            Some("test content 1"),
        )?;

        // Verify genesis properties
        assert!(mark_0.is_genesis());
        assert_eq!(mark_0.res(), res);
        assert_eq!(mark_0.seq(), 0);
        assert_eq!(mark_0.key().len(), expected_link_len);
        assert_eq!(mark_0.chain_id(), mark_0.key()); // Genesis invariant
        println!(
            "  ✓ Genesis mark: {} ({})",
            mark_0.identifier(),
            mark_0.key().len()
        );

        // Mark 1
        let date_1 = Date::now();
        let message_1 = FrostPmChain::next_mark_message(
            &chain,
            date_1.clone(),
            Some("test content 2"),
        );
        let signature_1 = chain.group().round_2_sign(
            signers,
            &commitments_1,
            &nonces_1,
            &message_1,
        )?;

        // Generate commitments for seq=2
        let (seq2_commitments, seq2_nonces) =
            chain.group().round_1_commit(signers, &mut OsRng)?;

        let (mark_1, receipt_root, receipt_commitments) = chain
            .append_mark(
                date_1,
                Some("test content 2"),
                Some(root_1),
                signature_1,
                seq2_commitments,
            )?;

        // Verify chain properties
        assert_eq!(mark_1.seq(), 1);
        assert_eq!(mark_1.res(), res);
        assert_eq!(mark_1.key().len(), expected_link_len);
        assert_eq!(mark_1.chain_id(), mark_0.chain_id());
        println!(
            "  ✓ Mark 1: {} ({})",
            mark_1.identifier(),
            mark_1.key().len()
        );

        // Mark 2
        let date_2 = Date::now();
        let message_2 = FrostPmChain::next_mark_message(
            &chain,
            date_2.clone(),
            Some("test content 3"),
        );
        let signature_2 = chain.group().round_2_sign(
            signers,
            &receipt_commitments,
            &seq2_nonces,
            &message_2,
        )?;

        // Generate commitments for seq=3
        let (seq3_commitments, _seq3_nonces) =
            chain.group().round_1_commit(signers, &mut OsRng)?;

        let (mark_2, _receipt_root, _receipt_commitments) = chain
            .append_mark(
                date_2,
                Some("test content 3"),
                Some(receipt_root),
                signature_2,
                seq3_commitments,
            )?;

        // Verify chain properties
        assert_eq!(mark_2.seq(), 2);
        assert_eq!(mark_2.res(), res);
        assert_eq!(mark_2.key().len(), expected_link_len);
        assert_eq!(mark_2.chain_id(), mark_0.chain_id());
        println!(
            "  ✓ Third mark: {} ({})",
            mark_2.identifier(),
            mark_2.key().len()
        );

        // Verify complete chain integrity
        let marks = vec![mark_0.clone(), mark_1.clone(), mark_2.clone()];
        assert!(provenance_mark::ProvenanceMark::is_sequence_valid(&marks));
        assert!(mark_0.precedes(&mark_1));
        assert!(mark_1.precedes(&mark_2));

        println!("  ✓ Chain integrity verified for {} resolution\n", name);
    }

    Ok(())
}
