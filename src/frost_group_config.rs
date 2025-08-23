use std::collections::BTreeMap;

use anyhow::{Result, bail};
use frost_ed25519::Identifier;

/// Configuration for the FROST group parameters
#[derive(Debug, Clone)]
pub struct FrostGroupConfig {
    /// Minimum number of signers required (threshold)
    min_signers: usize,
    /// Mapping of human-readable names to FROST identifiers
    participants: BTreeMap<String, Identifier>,
    /// Reverse mapping from FROST identifiers to human-readable names
    id_to_name: BTreeMap<Identifier, String>,
    /// Charter describing the purpose of this group
    charter: String,
}

impl FrostGroupConfig {
    /// Create a new FROSTGroupConfig with the specified threshold and
    /// participant names The maximum number of signers is automatically
    /// derived from the participant names array
    pub fn new(
        min_signers: usize,
        participant_names: &[&'static str],
        charter: String,
    ) -> Result<Self> {
        let max_signers = participant_names.len();

        if min_signers > max_signers {
            bail!(
                "min_signers ({}) cannot be greater than max_signers ({})",
                min_signers,
                max_signers
            );
        }

        if min_signers == 0 {
            bail!("min_signers must be at least 1");
        }

        let mut participants = BTreeMap::new();
        let mut id_to_name = BTreeMap::new();

        for (i, name) in participant_names.iter().enumerate() {
            let id = Identifier::try_from((i + 1) as u16)?;
            participants.insert((*name).to_string(), id);
            id_to_name.insert(id, (*name).to_string());
        }

        Ok(Self { min_signers, participants, id_to_name, charter })
    }

    /// Get the minimum number of signers required (threshold)
    pub fn min_signers(&self) -> usize { self.min_signers }

    /// Get the maximum number of participants
    pub fn max_signers(&self) -> usize { self.participants.len() }

    /// Get the list of participant identifiers
    pub fn participant_ids(&self) -> Vec<Identifier> {
        self.participants.values().cloned().collect()
    }

    /// Get the group's charter
    pub fn charter(&self) -> &str { &self.charter }

    /// Get participant name by identifier
    pub fn participant_name(&self, id: &Identifier) -> &str {
        self.id_to_name
            .get(id)
            .map(|s| s.as_str())
            .unwrap_or("Unknown")
    }

    /// Get participant names as a comma-separated string
    pub fn participant_names_string(&self) -> String {
        self.participants
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Get a reference to the participants mapping (for internal use)
    pub(crate) fn participants(&self) -> &BTreeMap<String, Identifier> {
        &self.participants
    }
}

impl Default for FrostGroupConfig {
    fn default() -> Self {
        Self::new(
            2,
            &["Alice", "Bob", "Eve"],
            "Default FROST group for testing".to_string(),
        )
        .expect("Default FROSTGroupConfig should be valid")
    }
}
