use anyhow::{Result, bail};
use frost_ed25519::Identifier;
use std::collections::BTreeMap;

/// Configuration for the FROST group parameters
pub struct FrostGroupConfig {
    /// Minimum number of signers required (threshold)
    min_signers: u16,
    /// Maximum number of participants
    max_signers: u16,
    /// Mapping of human-readable names to FROST identifiers
    participants: BTreeMap<&'static str, Identifier>,
    /// Reverse mapping from FROST identifiers to human-readable names
    id_to_name: BTreeMap<Identifier, &'static str>,
}

impl FrostGroupConfig {
    /// Create a new FROSTGroupConfig with the specified threshold and participant names
    /// The maximum number of signers is automatically derived from the participant names array
    pub fn new(
        min_signers: u16,
        participant_names: &[&'static str],
    ) -> Result<Self> {
        let max_signers = participant_names.len() as u16;

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
            participants.insert(*name, id);
            id_to_name.insert(id, *name);
        }

        Ok(Self { min_signers, max_signers, participants, id_to_name })
    }

    /// Get the minimum number of signers required (threshold)
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Get the maximum number of participants
    pub fn max_signers(&self) -> u16 {
        self.max_signers
    }

    /// Get the list of participant identifiers
    pub fn participant_ids(&self) -> Vec<Identifier> {
        self.participants.values().cloned().collect()
    }

    /// Get participant name by identifier
    pub fn participant_name(&self, id: &Identifier) -> &'static str {
        self.id_to_name.get(id).unwrap_or(&"Unknown")
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
    pub(crate) fn participants(&self) -> &BTreeMap<&'static str, Identifier> {
        &self.participants
    }
}

impl Default for FrostGroupConfig {
    fn default() -> Self {
        Self::new(2, &["Alice", "Bob", "Eve"])
            .expect("Default FROSTGroupConfig should be valid")
    }
}
