//! Static service capability restrictions, independent of caller authorization.

use schemars::JsonSchema;
use serde::Serialize;

/// metadata, secrets, pkiSsh, or full; Infisical still enforces machine-identity permissions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum OperationProfile {
    Metadata,
    Secrets,
    PkiSsh,
    #[default]
    Full,
}

impl OperationProfile {
    /// Parse the closed startup configuration without reflecting invalid input.
    ///
    /// # Errors
    /// Returns fixed guidance when the profile is not supported.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "metadata" => Ok(Self::Metadata),
            "secrets" => Ok(Self::Secrets),
            "pkiSsh" => Ok(Self::PkiSsh),
            "full" => Ok(Self::Full),
            _ => Err("use metadata, secrets, pkiSsh, or full"),
        }
    }

    pub(crate) const fn allows(self, facts: PolicyFacts) -> bool {
        match self {
            Self::Metadata => facts.metadata,
            Self::Secrets => facts.secrets,
            Self::PkiSsh => facts.pki_ssh,
            Self::Full => true,
        }
    }
}

#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct PolicyFacts {
    pub reviewed: bool,
    pub metadata: bool,
    pub secrets: bool,
    pub pki_ssh: bool,
    pub credential_disclosure: bool,
}
