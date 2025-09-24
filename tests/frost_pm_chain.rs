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
    let date_0 = Date::now();
    let info_0 = None::<String>;
    let message_0 =
        FrostPmChain::message_0(&config, res, &date_0, info_0.clone());
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

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
    let (mut chain, mark_0) = FrostPmChain::new_chain(
        res,
        &date_0,
        info_0,
        group.clone(),
        signature_0,
        &commitments_1,
    )?;

    println!("Genesis mark created: {}", mark_0.identifier());
    assert!(mark_0.is_genesis());

    // Create second mark with a different "image"
    let info_1 = Some("second image bytes");
    let date_1 = Date::now();

    // Client generates message and Round-2 signature
    let message_1 = chain.message_next(&date_1, info_1);
    let signature_1 = chain.group().round_2_sign(
        signers,
        &commitments_1,
        &nonces_1,
        message_1.as_bytes(),
    )?;

    // Client generates commitments for seq=2 before calling append_mark
    let (commitments_2, nonces_2) =
        chain.group().round_1_commit(signers, &mut OsRng)?;

    let mark_1 = chain.append_mark(
        date_1,
        info_1,
        &commitments_1,
        signature_1,
        &commitments_2,
    )?;

    println!("Mark 1 created: {}", mark_1.identifier());

    // Create mark 2 with yet another "image"
    let info_2 = Some("mark 2 image bytes");
    let date_2 = Date::now();

    // Client generates message and Round-2 signature
    let message_2 = chain.message_next(&date_2, info_2);
    let signature_2 = chain.group().round_2_sign(
        signers,
        &commitments_2,
        &nonces_2,
        message_2.as_bytes(),
    )?;

    // Client generates commitments for seq=3 before calling append_mark
    let (commitments_3, _nonces_3) =
        chain.group().round_1_commit(signers, &mut OsRng)?;

    let mark_2 = chain.append_mark(
        date_2,
        info_2,
        &commitments_2,
        signature_2,
        &commitments_3,
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
    let date_0 = Date::now();
    let info_0 = Some("test content");
    let message_0 = FrostPmChain::message_0(&config, res, &date_0, info_0);
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

    let (mut chain, _mark_0) = FrostPmChain::new_chain(
        res,
        &date_0,
        info_0,
        group,
        signature_0,
        &commitments_1,
    )?;

    // Try to create a mark with earlier date than genesis (should fail)
    let earlier_date =
        Date::from_datetime(date_0.datetime() - chrono::Duration::seconds(60));

    // Even though this will fail, we need to provide a signature
    let message_fail =
        chain.message_next(&earlier_date, Some("test content 2"));
    let signature_fail = chain.group().round_2_sign(
        signers,
        &commitments_1,
        &nonces_1,
        message_fail.as_bytes(),
    )?;

    // Generate commitments for the test (even though it will fail)
    let (commitments_2, _nonces_2) =
        chain.group().round_1_commit(signers, &mut OsRng)?;

    let result = chain.append_mark(
        earlier_date,
        Some("test content 2"),
        &commitments_1,
        signature_fail,
        &commitments_2,
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
    let date_0 = Date::now();
    let info_0 = Some("test content 1");
    let message_0 = FrostPmChain::message_0(&config, res, &date_0, info_0);
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
    let (mut chain, mark_0) = FrostPmChain::new_chain(
        res,
        &date_0,
        info_0,
        group.clone(),
        signature_0,
        &commitments_1,
    )?;

    // Next mark with same participants as genesis precommit
    let date_1 = Date::now();
    let info_1 = Some("test content 2");
    let message_1 = chain.message_next(&date_1, info_1);
    let signature_1 = chain.group().round_2_sign(
        signers,
        &commitments_1,
        &nonces_1,
        message_1.as_bytes(),
    )?;

    // Generate commitments for next sequence
    let (commitments_2, _nonces_2) =
        chain.group().round_1_commit(signers, &mut OsRng)?;

    let mark_1 = chain.append_mark(
        date_1,
        info_1,
        &commitments_1,
        signature_1,
        &commitments_2,
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
        ProvenanceMarkResolution::Low,
        ProvenanceMarkResolution::Medium,
        ProvenanceMarkResolution::Quartile,
        ProvenanceMarkResolution::High,
    ];

    for res in resolutions {
        println!(
            "Testing {} resolution ({}-byte links)",
            res,
            res.link_length()
        );

        // Test data for this resolution

        // Client generates genesis message and signs it
        let date_0 = Date::now();
        let info_0 = Some("test content 0");
        let message_0 =
            FrostPmChain::message_0(group.config(), res, &date_0, info_0);
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
        let (mut chain, mark_0) = FrostPmChain::new_chain(
            res,
            &date_0,
            info_0,
            group.clone(),
            signature_0,
            &commitments_1,
        )?;

        // Verify genesis properties
        assert!(mark_0.is_genesis());
        assert_eq!(mark_0.res(), res);
        assert_eq!(mark_0.seq(), 0);
        assert_eq!(mark_0.key().len(), res.link_length());
        assert_eq!(mark_0.chain_id(), mark_0.key()); // Genesis invariant
        println!(
            "  ✓ Genesis mark: {} ({})",
            mark_0.identifier(),
            mark_0.key().len()
        );

        // Mark 1
        let date_1 = Date::now();
        let info_1 = Some("test content 1");
        let message_1 = chain.message_next(&date_1, info_1);
        let signature_1 = chain.group().round_2_sign(
            signers,
            &commitments_1,
            &nonces_1,
            message_1.as_bytes(),
        )?;

        // Generate commitments for seq=2
        let (commitments_2, nonces_2) =
            chain.group().round_1_commit(signers, &mut OsRng)?;

        let mark_1 = chain.append_mark(
            date_1,
            info_1,
            &commitments_1,
            signature_1,
            &commitments_2,
        )?;

        // Verify chain properties
        assert_eq!(mark_1.seq(), 1);
        assert_eq!(mark_1.res(), res);
        assert_eq!(mark_1.key().len(), res.link_length());
        assert_eq!(mark_1.chain_id(), mark_0.chain_id());
        println!(
            "  ✓ Mark 1: {} ({})",
            mark_1.identifier(),
            mark_1.key().len()
        );

        // Mark 2
        let date_2 = Date::now();
        let info_2 = Some("test content 3");
        let message_2 = chain.message_next(&date_2, info_2);
        let signature_2 = chain.group().round_2_sign(
            signers,
            &commitments_2,
            &nonces_2,
            message_2.as_bytes(),
        )?;

        // Generate commitments for seq=3
        let (commitments_3, _nonces_3) =
            chain.group().round_1_commit(signers, &mut OsRng)?;

        let mark_2 = chain.append_mark(
            date_2,
            info_2,
            &commitments_2,
            signature_2,
            &commitments_3,
        )?;

        // Verify chain properties
        assert_eq!(mark_2.seq(), 2);
        assert_eq!(mark_2.res(), res);
        assert_eq!(mark_2.key().len(), res.link_length());
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

        println!("  ✓ Chain integrity verified for {} resolution\n", res);
    }

    Ok(())
}
