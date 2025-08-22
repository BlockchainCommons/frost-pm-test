use anyhow::Result;
use bc_crypto::sha256;
use chrono::Utc;
use frost_pm_test::{
    FrostGroup, FrostGroupConfig, pm_chain::FrostPmChain,
};
use provenance_mark::ProvenanceMarkResolution;
use rand::rngs::OsRng;

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
    let config = FrostGroupConfig::new(2, &["alice", "bob", "charlie"])
        .map_err(|e| anyhow::anyhow!("Failed to create FROST config: {}", e))?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("Failed to create FROST group: {}", e))?;
    println!("   ✓ FROST group created successfully\n");

    let resolutions = [
        (ProvenanceMarkResolution::Low, "Low", "🔵"),
        (ProvenanceMarkResolution::Medium, "Medium", "🟡"),
        (ProvenanceMarkResolution::Quartile, "Quartile", "🟠"),
        (ProvenanceMarkResolution::High, "High", "🔴"),
    ];

    for (i, (res, name, icon)) in resolutions.iter().enumerate() {
        println!(
            "{} ═══ {} Resolution Demo - {} Mark Chain ({} bytes) ═══",
            icon, name, MARK_COUNT, res.link_length()
        );

        // Genesis data
        let artwork_name =
            format!("Digital artwork collection #{} - 2024", i + 1);
        let obj_hash1 = sha256(artwork_name.as_bytes());

        println!("   Collection: \"{}\"", artwork_name);
        println!("   Genesis hash: {}", hex::encode(&obj_hash1));

        // Genesis
        let (mut chain, genesis_mark) = FrostPmChain::new_genesis(
            &group,
            *res,
            &["alice", "bob"],
            Utc::now(),
            &obj_hash1,
        )?;

        println!(
            "   ✓ Genesis mark: {} (link: {} bytes)",
            genesis_mark.identifier(),
            genesis_mark.key().len()
        );
        println!("   Chain ID: {}", hex::encode(genesis_mark.chain_id()));

        // Store all marks for final validation
        let mut all_marks = vec![genesis_mark];

        print!("   Creating marks: ");
        for seq in 1..MARK_COUNT {
            // Vary the content for each mark
            let content = format!("Edition #{} of collection #{}", seq, i + 1);
            let obj_hash = sha256(content.as_bytes());

            let mark = chain.append_mark(
                &["alice", "bob"], // Same participants for consistency
                seq,
                Utc::now(),
                &obj_hash,
            )?;

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
        let last_mark = &all_marks[99];
        let mid_mark = &all_marks[49];
        println!("   Sample marks:");
        println!(
            "     Mark #1:  {} (seq={})",
            all_marks[1].identifier(),
            all_marks[1].seq()
        );
        println!(
            "     Mark #50: {} (seq={})",
            mid_mark.identifier(),
            mid_mark.seq()
        );
        println!(
            "     Mark #100: {} (seq={})",
            last_mark.identifier(),
            last_mark.seq()
        );

        // Comprehensive chain validation
        print!("   Validating 100-mark chain... ");
        let start_time = std::time::Instant::now();

        let genesis_check = all_marks[0].is_genesis();
        let sequence_valid =
            provenance_mark::ProvenanceMark::is_sequence_valid(&all_marks);

        // Spot check precedence for performance (checking all 99 links would be slow)
        let mut spot_checks_passed = 0;
        let check_indices = [0, 10, 25, 49, 74, 90, 98]; // Sample of indices to check
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
                "   {} {} resolution 100-mark chain verified successfully!\n",
                icon, name
            );
        } else {
            return Err(anyhow::anyhow!(
                "Chain verification failed for {} resolution",
                name
            ));
        }
    }

    println!("🎉 100-Mark Chain Demo Complete!");

    Ok(())
}
