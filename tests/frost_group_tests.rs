use anyhow::Result;
use frost_pm_test::{FrostGroup, FrostGroupConfig};
use rand::rngs::OsRng;

// Test helper functions
pub fn corporate_board_config() -> FrostGroupConfig {
    FrostGroupConfig::new(
        3,
        &["CEO", "CFO", "CTO", "COO", "CLO"],
        "Corporate board governance for strategic decisions".to_string(),
    ).unwrap()
}

pub fn family_config() -> FrostGroupConfig {
    FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Charlie", "Diana"],
        "Family trust fund management".to_string(),
    ).unwrap()
}

#[test]
fn test_group_creation_with_trusted_dealer() -> Result<()> {
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Eve"],
        "Default FROST group for testing".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

    assert_eq!(group.min_signers(), 2);
    assert_eq!(group.max_signers(), 3);
    assert_eq!(group.participant_names().len(), 3);
    assert_eq!(group.participant_names().join(", "), "Alice, Bob, Eve");

    // Verify all participants have key packages
    for participant_name in group.participant_names() {
        assert!(group.key_package(&participant_name).is_ok());
    }
    Ok(())
}

#[test]
fn test_group_signing() -> Result<()> {
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Eve"],
        "Default FROST group for testing".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    let message = b"Test message for FROST signing";

    // Select signers
    let participant_names = group.participant_names();
    let signers: Vec<&str> = participant_names
        .iter()
        .take(group.min_signers() as usize)
        .map(|s| s.as_str())
        .collect();
    assert_eq!(signers.len(), 2); // min_signers

    // Perform signing
    let (commitments, nonces) =
        group.round_1_commit(&["Alice", "Bob"], &mut OsRng)?;
    let signature = group.round_2_sign(
        &["Alice", "Bob"],
        &commitments,
        &nonces,
        message,
    )?;

    // Verify signature
    assert!(group.verify(message, &signature).is_ok());

    // Verify with wrong message fails
    let wrong_message = b"Wrong message";
    assert!(group.verify(wrong_message, &signature).is_err());
    Ok(())
}

#[test]
fn test_group_insufficient_signers() -> Result<()> {
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Eve"],
        "Default FROST group for testing".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

    // Try to sign with only 1 signer (need 2 for threshold)
    let participant_names = group.participant_names();
    let insufficient_signers = vec![participant_names[0].as_str()];

    let result = group.round_1_commit(&insufficient_signers, &mut OsRng);
    assert!(result.is_err());
    if let Err(error) = result {
        assert!(error.to_string().contains("Need at least 2 signers"));
    }

    Ok(())
}

#[test]
fn test_corporate_board_signing() -> Result<()> {
    let config = corporate_board_config();
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;
    assert_eq!(group.min_signers(), 3);
    assert_eq!(group.max_signers(), 5);

    let message = b"Corporate board resolution";

    // Select first 3 participants as signers (threshold)
    let participant_names = group.participant_names();
    let signers: Vec<&str> = participant_names
        .iter()
        .take(group.min_signers() as usize)
        .map(|s| s.as_str())
        .collect();
    assert_eq!(signers.len(), 3);

    let (commitments, nonces) = group.round_1_commit(&signers, &mut OsRng)?;
    let signature =
        group.round_2_sign(&signers, &commitments, &nonces, message)?;
    assert!(group.verify(message, &signature).is_ok());
    Ok(())
}

#[test]
fn test_group_participant_management() -> Result<()> {
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Eve"],
        "Default FROST group for testing".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

    // Test participant names retrieval
    let participant_names = group.participant_names();
    assert_eq!(participant_names.len(), 3);

    // Test that all names are valid
    for name in &participant_names {
        assert!(["Alice", "Bob", "Eve"].contains(&name.as_str()));
        assert!(group.has_participant(name));
    }

    // Test participant names string
    let names_string = group.participant_names().join(", ");
    assert_eq!(names_string, "Alice, Bob, Eve");
    Ok(())
}

#[test]
fn test_group_basic_functionality() -> Result<()> {
    // Test that demonstrates the basic functionality works
    let config = FrostGroupConfig::new(
        2,
        &["Alice", "Bob", "Eve"],
        "Default FROST group for testing".to_string(),
    )?;
    let group = FrostGroup::new_with_trusted_dealer(config, &mut OsRng)?;

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
        .map(|s| s.as_str())
        .collect();

    let (commitments, nonces) = group.round_1_commit(&signers, &mut OsRng)?;
    let signature =
        group.round_2_sign(&signers, &commitments, &nonces, message)?;
    assert!(group.verify(message, &signature).is_ok());

    // Verify wrong message fails verification
    let wrong_message = b"Wrong message";
    assert!(group.verify(wrong_message, &signature).is_err());
    Ok(())
}
