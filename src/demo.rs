use anyhow::{Result, bail};
use dcbor::Date;
use frost_pm_test::{
    FrostGroup, FrostGroupConfig, pm_chain::FrostPmChain, rand_core::OsRng,
};
use provenance_mark::ProvenanceMarkResolution;

const MARK_COUNT: usize = 100;

pub fn run_demo() -> Result<()> {
    println!("🔒 FROST-Controlled Provenance Mark Chain Demo");
    println!("===============================================");
    println!(
        "Demonstrating {}-mark chains across all supported resolutions\n",
        MARK_COUNT
    );

    // Create a 2-of-3 FROST group
    println!("1. Creating FROST group with participants: Alice, Bob, Charlie");
    println!("   Threshold: 2 of 3 signers required");
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Charlie"],
        "Demo provenance mark chain".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    println!("   ✓ FROST group created successfully\n");

    let resolutions = [
        (ProvenanceMarkResolution::Low, "🔵"),
        (ProvenanceMarkResolution::Medium, "🟡"),
        (ProvenanceMarkResolution::Quartile, "🟠"),
        (ProvenanceMarkResolution::High, "🔴"),
    ];

    for (i, (res, icon)) in resolutions.iter().enumerate() {
        println!(
            "{} ═══ {} Resolution Demo - {} Mark Chain ({} bytes) ═══",
            icon,
            res,
            MARK_COUNT,
            res.link_length()
        );

        // Genesis data
        let artwork_name =
            format!("Digital artwork collection #{} - 2024", i + 1);

        println!("   Collection: \"{}\"", artwork_name);

        // Client generates genesis message and signs it
        let date_0 = Date::now();
        let info_0 = Some(artwork_name);
        let message_0 = FrostPmChain::message_0(
            group.config(),
            *res,
            date_0,
            info_0.clone(),
        );
        let (commitments_0, nonces_0) =
            group.round_1_commit(&["Alice", "Bob"], &mut OsRng)?;
        let signature_0 = group.round_2_sign(
            &["Alice", "Bob"],
            &commitments_0,
            &nonces_0,
            message_0.as_bytes(),
        )?;

        // Client generates Round-1 commitments for seq=1
        let (commitments_1, nonces_1) =
            group.round_1_commit(&["Alice", "Bob"], &mut OsRng)?;

        // Genesis
        let (mut chain, mark_0) = FrostPmChain::new_chain(
            *res,
            date_0,
            info_0,
            group.clone(),
            signature_0,
            &commitments_1,
        )?;

        // The client keeps the seq1_nonces for the first append_mark
        let mut current_nonces = nonces_1;
        let mut current_commitments = commitments_1;

        println!(
            "   ✓ Genesis mark: {} (link: {} bytes)",
            mark_0.identifier(),
            mark_0.key().len()
        );
        println!("   Chain ID: {}", hex::encode(mark_0.chain_id()));

        // Store all marks for final validation
        let mut all_marks = vec![mark_0];

        print!("   Creating marks: ");
        for seq in 1..MARK_COUNT {
            // Vary the content for each mark
            let info =
                Some(format!("Edition #{} of collection #{}", seq, i + 1));
            let date = Date::now();

            // Client generates message and Round-2 signature
            let message = chain.message_next(date, info.clone());

            let signers = &["Alice", "Bob"];

            let signature = chain.group().round_2_sign(
                signers,
                &current_commitments,
                &current_nonces,
                message.as_bytes(),
            )?;

            // Generate commitments for next sequence
            let (next_commitments, new_nonces) =
                chain.group().round_1_commit(signers, &mut OsRng)?;

            let mark = chain.append_mark(
                date,
                info,
                &current_commitments,
                signature,
                &next_commitments,
            )?;

            // Update for next iteration
            current_nonces = new_nonces;
            current_commitments = next_commitments;

            all_marks.push(mark);

            // Progress indicator - print every 10 marks
            if seq % 10 == 0 {
                print!("{}.", seq);
            } else if seq % 5 == 0 {
                print!("•");
            }
        }
        println!(" ✓ Complete!");

        // Show sample marks from the chain
        let last_mark_index = MARK_COUNT - 1;
        let mid_mark_index = MARK_COUNT / 2 - 1;
        let last_mark = &all_marks[last_mark_index];
        let mid_mark = &all_marks[mid_mark_index];
        println!("   Sample marks:");
        println!(
            "     Mark #1:  {} (seq={})",
            all_marks[1].identifier(),
            all_marks[1].seq()
        );
        println!(
            "     Mark #{}: {} (seq={})",
            mid_mark_index + 1,
            mid_mark.identifier(),
            mid_mark.seq()
        );
        println!(
            "     Mark #{}: {} (seq={})",
            last_mark_index + 1,
            last_mark.identifier(),
            last_mark.seq()
        );

        // Comprehensive chain validation
        print!("   Validating {}-mark chain... ", MARK_COUNT);
        let start_time = std::time::Instant::now();

        let genesis_check = all_marks[0].is_genesis();
        let sequence_valid =
            provenance_mark::ProvenanceMark::is_sequence_valid(&all_marks);

        // Spot check precedence for performance (checking all 99 links would be
        // slow)
        let mut spot_checks_passed = 0;
        let check_indices: Vec<usize> =
            (0..MARK_COUNT - 1).step_by((MARK_COUNT - 1) / 7).collect();
        for &i in &check_indices {
            if all_marks[i].precedes(&all_marks[i + 1]) {
                spot_checks_passed += 1;
            }
        }
        let precedence_valid = spot_checks_passed == check_indices.len();

        // Check resolution consistency
        let resolution_consistent = all_marks.iter().all(|m| m.res() == *res);

        let validation_time = start_time.elapsed();
        println!("Done ({:.2}ms)", validation_time.as_secs_f64() * 1000.0);

        println!("   📋 Chain Verification:");
        println!(
            "     Genesis check: {}",
            if genesis_check { "✅" } else { "❌" }
        );
        println!(
            "     Sequence validity: {}",
            if sequence_valid { "✅" } else { "❌" }
        );
        println!(
            "     Precedence spot checks ({}/{}): {}",
            spot_checks_passed,
            check_indices.len(),
            if precedence_valid { "✅" } else { "❌" }
        );
        println!(
            "     Resolution consistency: {}",
            if resolution_consistent { "✅" } else { "❌" }
        );
        println!("     Chain length: {} marks", all_marks.len());

        if genesis_check
            && sequence_valid
            && precedence_valid
            && resolution_consistent
        {
            println!(
                "   {} {} resolution {}-mark chain verified successfully!\n",
                icon, res, MARK_COUNT
            );
        } else {
            bail!("Chain verification failed for {} resolution", res);
        }
    }

    println!("🎉 {}-Mark Chain Demo Complete!", MARK_COUNT);

    Ok(())
}
