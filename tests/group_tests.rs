use frost_pm_test::{Group, GroupConfig};

// Test helper functions
pub fn corporate_board_config()
-> Result<GroupConfig, Box<dyn std::error::Error>> {
    GroupConfig::new(3, &["CEO", "CFO", "CTO", "COO", "CLO"])
}

pub fn family_config() -> Result<GroupConfig, Box<dyn std::error::Error>> {
    GroupConfig::new(2, &["Alice", "Bob", "Charlie", "Diana"])
}

#[test]
fn test_group_creation_with_trusted_dealer() {
    let config = GroupConfig::default();
    let mut rng = rand::thread_rng();

    let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();

    assert_eq!(group.min_signers(), 2);
    assert_eq!(group.max_signers(), 3);
    assert_eq!(group.participant_names().len(), 3);
    assert_eq!(group.participant_names_string(), "Alice, Bob, Eve");

    // Verify all participants have key packages
    for participant_name in group.participant_names() {
        assert!(group.key_package(participant_name).is_ok());
    }
}

#[test]
fn test_group_signing() {
    let config = GroupConfig::default();
    let mut rng = rand::thread_rng();

    let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();
    let message = b"Test message for FROST signing";

    // Select signers
    let signers = group.select_signers(None);
    assert_eq!(signers.len(), 2); // min_signers

    // Perform signing
    let signature = group.sign(message, &signers, &mut rng).unwrap();

    // Verify signature
    assert!(group.verify(message, &signature).is_ok());

    // Verify with wrong message fails
    let wrong_message = b"Wrong message";
    assert!(group.verify(wrong_message, &signature).is_err());
}

#[test]
fn test_group_insufficient_signers() {
    let config = GroupConfig::default();
    let mut rng = rand::thread_rng();

    let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();
    let message = b"Test message";

    // Try to sign with only 1 signer (need 2 for threshold)
    let insufficient_signers = vec![group.participant_names()[0]];

    let result = group.sign(message, &insufficient_signers, &mut rng);
    assert!(result.is_err());
    if let Err(error) = result {
        assert!(error.to_string().contains("Need at least 2 signers"));
    }
}

#[test]
fn test_corporate_board_signing() {
    let config = corporate_board_config().unwrap();
    let mut rng = rand::thread_rng();

    let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();
    assert_eq!(group.min_signers(), 3);
    assert_eq!(group.max_signers(), 5);

    let message = b"Corporate board resolution";
    let signers = group.select_signers(None); // Should select 3 signers
    assert_eq!(signers.len(), 3);

    let signature = group.sign(message, &signers, &mut rng).unwrap();
    assert!(group.verify(message, &signature).is_ok());
}

#[test]
fn test_group_signer_selection() {
    let config = GroupConfig::default();
    let mut rng = rand::thread_rng();

    let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();

    // Test default selection (should use min_signers)
    let default_signers = group.select_signers(None);
    assert_eq!(default_signers.len(), group.min_signers() as usize);

    // Test custom selection
    let custom_signers = group.select_signers(Some(3));
    assert_eq!(custom_signers.len(), 3);

    // Test selection that exceeds max_signers (should be capped)
    let capped_signers = group.select_signers(Some(10));
    assert_eq!(capped_signers.len(), group.max_signers() as usize);
}

#[test]
fn test_group_participant_management() {
    let config = GroupConfig::default();
    let mut rng = rand::thread_rng();

    let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();

    // Test participant names retrieval
    let participant_names = group.participant_names();
    assert_eq!(participant_names.len(), 3);

    // Test that all names are valid
    for name in &participant_names {
        assert!(["Alice", "Bob", "Eve"].contains(name));
        assert!(group.has_participant(name));
    }

    // Test participant names string
    let names_string = group.participant_names_string();
    assert_eq!(names_string, "Alice, Bob, Eve");
}

#[test]
fn test_group_basic_functionality() {
    // Test that demonstrates the basic functionality works
    let config = GroupConfig::default();
    let mut rng = rand::thread_rng();

    let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();

    // Verify basic properties
    assert_eq!(group.min_signers(), 2);
    assert_eq!(group.max_signers(), 3);
    assert_eq!(group.participant_names().len(), 3);

    // Verify signing works
    let message = b"Test message";
    let signers = group.select_signers(None);

    let signature = group.sign(message, &signers, &mut rng).unwrap();
    assert!(group.verify(message, &signature).is_ok());

    // Verify wrong message fails verification
    let wrong_message = b"Wrong message";
    assert!(group.verify(wrong_message, &signature).is_err());
}
