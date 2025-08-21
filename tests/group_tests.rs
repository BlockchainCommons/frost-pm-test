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
    assert_eq!(group.key_packages().len(), 3);
    assert_eq!(group.participant_names_string(), "Alice, Bob, Eve");

    // Verify all participants have key packages
    for participant_id in group.participant_ids() {
        assert!(group.key_package(&participant_id).is_some());
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
    let insufficient_signers = vec![group.participant_ids()[0]];

    let result = group.sign(message, &insufficient_signers, &mut rng);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Need at least 2 signers")
    );
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

    // Test participant ID retrieval
    let participant_ids = group.participant_ids();
    assert_eq!(participant_ids.len(), 3);

    // Test participant name lookup
    for id in &participant_ids {
        let name = group.participant_name(id);
        assert!(["Alice", "Bob", "Eve"].contains(&name));
    }

    // Test participant names string
    let names_string = group.participant_names_string();
    assert_eq!(names_string, "Alice, Bob, Eve");
}

#[test]
fn test_group_new_from_key_material() {
    let config = GroupConfig::default();
    let mut rng = rand::thread_rng();

    // First create a group with trusted dealer to get valid key material
    let trusted_group =
        Group::new_with_trusted_dealer(config, &mut rng).unwrap();

    // Extract the key material
    let key_packages = trusted_group.key_packages().clone();
    let public_key_package = trusted_group.public_key_package().clone();

    // Now create a new group using the extracted key material
    let config2 = GroupConfig::default();
    let material_group =
        Group::new_from_key_material(config2, key_packages, public_key_package)
            .unwrap();

    // Verify the groups have the same properties
    assert_eq!(material_group.min_signers(), trusted_group.min_signers());
    assert_eq!(material_group.max_signers(), trusted_group.max_signers());
    assert_eq!(
        material_group.participant_names_string(),
        trusted_group.participant_names_string()
    );

    // Verify both groups can sign and produce valid signatures
    let message = b"Test message for both groups";
    let signers = trusted_group.select_signers(None);

    let sig1 = trusted_group.sign(message, &signers, &mut rng).unwrap();
    let sig2 = material_group.sign(message, &signers, &mut rng).unwrap();

    // Both groups should be able to verify each other's signatures
    assert!(trusted_group.verify(message, &sig1).is_ok());
    assert!(trusted_group.verify(message, &sig2).is_ok());
    assert!(material_group.verify(message, &sig1).is_ok());
    assert!(material_group.verify(message, &sig2).is_ok());
}

#[test]
fn test_group_new_from_key_material_validation() {
    let config = GroupConfig::default();
    let mut rng = rand::thread_rng();

    // Create a group to get valid key material
    let group = Group::new_with_trusted_dealer(config, &mut rng).unwrap();
    let mut key_packages = group.key_packages().clone();
    let public_key_package = group.public_key_package().clone();

    // Test with missing key package
    let participant_id = key_packages.keys().next().unwrap().clone();
    key_packages.remove(&participant_id);

    let config2 = GroupConfig::default();
    let result =
        Group::new_from_key_material(config2, key_packages, public_key_package);
    assert!(result.is_err());
    if let Err(error) = result {
        let error_msg = error.to_string();
        assert!(error_msg.contains("Expected 3 key packages, got 2"));
    }
}
