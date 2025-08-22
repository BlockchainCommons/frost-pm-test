use anyhow::Result;
use frost_ed25519 as frost;
use frost_pm_test::FrostGroupConfig;

// Test helper functions
fn corporate_board_config() -> Result<FrostGroupConfig> {
    FrostGroupConfig::new(3, &["CEO", "CFO", "CTO", "COO", "CLO"], "Corporate board governance for strategic decisions".to_string())
}

fn family_config() -> Result<FrostGroupConfig> {
    FrostGroupConfig::new(2, &["Alice", "Bob", "Charlie", "Diana"], "Family trust fund management".to_string())
}

#[test]
fn test_default_config() {
    let config = FrostGroupConfig::default();
    assert_eq!(config.min_signers(), 2);
    assert_eq!(config.max_signers(), 3);
    assert_eq!(config.participant_ids().len(), 3);

    let names = config.participant_names_string();
    assert_eq!(names, "Alice, Bob, Eve");
}

#[test]
fn test_corporate_board_config() {
    let config = corporate_board_config().unwrap();
    assert_eq!(config.min_signers(), 3);
    assert_eq!(config.max_signers(), 5);
    assert_eq!(config.participant_ids().len(), 5);

    let names = config.participant_names_string();
    assert!(names.contains("CEO"));
    assert!(names.contains("CFO"));
    assert!(names.contains("CTO"));
    assert!(names.contains("COO"));
    assert!(names.contains("CLO"));
}

#[test]
fn test_family_config() {
    let config = family_config().unwrap();
    assert_eq!(config.min_signers(), 2);
    assert_eq!(config.max_signers(), 4);
    assert_eq!(config.participant_ids().len(), 4);

    let names = config.participant_names_string();
    assert!(names.contains("Alice"));
    assert!(names.contains("Bob"));
    assert!(names.contains("Charlie"));
    assert!(names.contains("Diana"));
}

#[test]
fn test_config_validation() {
    // Test min_signers = 0
    let result = FrostGroupConfig::new(0, &["Alice", "Bob"], "Test charter".to_string());
    assert!(result.is_err());

    // Test min_signers > max_signers
    let result = FrostGroupConfig::new(5, &["Alice", "Bob"], "Test charter".to_string());
    assert!(result.is_err());

    // Test valid config
    let result = FrostGroupConfig::new(2, &["Alice", "Bob", "Charlie"], "Test charter".to_string());
    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.min_signers(), 2);
    assert_eq!(config.max_signers(), 3);
    assert_eq!(config.charter(), "Test charter");
}

#[test]
fn test_genesis_message() {
    let config = FrostGroupConfig::new(
        2, 
        &["Alice", "Bob", "Charlie"], 
        "Test charter for genesis".to_string()
    ).unwrap();
    
    let genesis_msg = config.genesis_message();
    
    // Verify the format and content
    assert!(genesis_msg.contains("FROST Genesis"));
    assert!(genesis_msg.contains("Threshold: 2 of 3"));
    assert!(genesis_msg.contains("Participants: Alice, Bob, Charlie"));
    assert!(genesis_msg.contains("Charter: Test charter for genesis"));
    
    // Verify the exact format
    let expected = "FROST Genesis\nThreshold: 2 of 3\nParticipants: Alice, Bob, Charlie\nCharter: Test charter for genesis";
    assert_eq!(genesis_msg, expected);
}

#[test]
fn test_genesis_message_integration_with_pm_chain() {
    use frost_pm_test::{FrostGroup, FrostPmChain};
    use provenance_mark::ProvenanceMarkResolution;
    use dcbor::Date;

    // Create a config with a specific charter
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Charlie"], 
        "Test governance charter for integration test".to_string()
    ).unwrap();
    
    let mut rng = rand::thread_rng();
    let group = FrostGroup::new_with_trusted_dealer(config, &mut rng).unwrap();
    
    // Verify that the config's genesis message is accessible through the group
    let expected_genesis = "FROST Genesis\nThreshold: 2 of 3\nParticipants: Alice, Bob, Charlie\nCharter: Test governance charter for integration test";
    assert_eq!(group.config().genesis_message(), expected_genesis);
    
    // Create a provenance mark chain - this will use the genesis message internally
    let (_chain, genesis_mark, _receipt, _nonces) = FrostPmChain::new_genesis(
        group,
        ProvenanceMarkResolution::Medium,
        &["Alice", "Bob"],
        Date::now(),
        Some("Test genesis content"),
    ).unwrap();
    
    // Verify the genesis mark was created successfully
    assert!(genesis_mark.is_genesis());
    assert_eq!(genesis_mark.seq(), 0);
    
    // The chain should be properly initialized
    assert_eq!(genesis_mark.chain_id(), genesis_mark.key()); // Genesis invariant
}

#[test]
fn test_participant_name_lookup() {
    let config = FrostGroupConfig::default();
    let participant_ids = config.participant_ids();

    // Test that we can look up participant names
    for id in &participant_ids {
        let name = config.participant_name(id);
        assert_ne!(name, "Unknown");
        assert!(["Alice", "Bob", "Eve"].contains(&name));
    }

    // Test unknown identifier
    let unknown_id = frost::Identifier::try_from(99u16).unwrap();
    assert_eq!(config.participant_name(&unknown_id), "Unknown");
}

#[test]
fn test_participant_names_string() {
    let config = FrostGroupConfig::default();
    let names = config.participant_names_string();
    // BTreeMap maintains sorted order, so we can predict the output
    assert_eq!(names, "Alice, Bob, Eve");
}
