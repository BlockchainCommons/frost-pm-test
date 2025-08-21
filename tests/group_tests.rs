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
    assert_eq!(group.participant_names().join(", "), "Alice, Bob, Eve");

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
    let participant_names = group.participant_names();
    let signers: Vec<&str> = participant_names
        .iter()
        .take(group.min_signers() as usize)
        .copied()
        .collect();
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

    // Select first 3 participants as signers (threshold)
    let participant_names = group.participant_names();
    let signers: Vec<&str> = participant_names
        .iter()
        .take(group.min_signers() as usize)
        .copied()
        .collect();
    assert_eq!(signers.len(), 3);

    let signature = group.sign(message, &signers, &mut rng).unwrap();
    assert!(group.verify(message, &signature).is_ok());
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
    let names_string = group.participant_names().join(", ");
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

    // Select first 2 participants as signers
    let participant_names = group.participant_names();
    let signers: Vec<&str> = participant_names
        .iter()
        .take(group.min_signers() as usize)
        .copied()
        .collect();

    let signature = group.sign(message, &signers, &mut rng).unwrap();
    assert!(group.verify(message, &signature).is_ok());

    // Verify wrong message fails verification
    let wrong_message = b"Wrong message";
    assert!(group.verify(wrong_message, &signature).is_err());
}
