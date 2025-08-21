use frost_ed25519 as frost;
use frost_pm_test::GroupConfig;

// Test helper functions
fn corporate_board_config() -> Result<GroupConfig, Box<dyn std::error::Error>> {
    GroupConfig::new(3, &["CEO", "CFO", "CTO", "COO", "CLO"])
}

fn family_config() -> Result<GroupConfig, Box<dyn std::error::Error>> {
    GroupConfig::new(2, &["Alice", "Bob", "Charlie", "Diana"])
}

#[test]
fn test_default_config() {
    let config = GroupConfig::default();
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
    let result = GroupConfig::new(0, &["Alice", "Bob"]);
    assert!(result.is_err());

    // Test min_signers > max_signers
    let result = GroupConfig::new(5, &["Alice", "Bob"]);
    assert!(result.is_err());

    // Test valid config
    let result = GroupConfig::new(2, &["Alice", "Bob", "Charlie"]);
    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.min_signers(), 2);
    assert_eq!(config.max_signers(), 3);
}

#[test]
fn test_participant_name_lookup() {
    let config = GroupConfig::default();
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
    let config = GroupConfig::default();
    let names = config.participant_names_string();
    // BTreeMap maintains sorted order, so we can predict the output
    assert_eq!(names, "Alice, Bob, Eve");
}
