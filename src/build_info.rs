// Compile-time identity shared by the CLI and daemon. The source digest comes
// from scripts/source-fingerprint.sh and is verified again by package builders.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BuildInfo {
    pub version: String,
    pub build_id: String,
    pub target: String,
    pub profile: String,
    pub source_date_epoch: Option<String>,
}

impl BuildInfo {
    pub fn current() -> Self {
        let epoch = env!("WALDEN_BUILD_EPOCH");
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_id: env!("WALDEN_BUILD_ID").to_string(),
            target: env!("WALDEN_BUILD_TARGET").to_string(),
            profile: env!("WALDEN_BUILD_PROFILE").to_string(),
            source_date_epoch: (epoch != "not-set").then(|| epoch.to_string()),
        }
    }

    pub fn short_build_id(&self) -> &str {
        self.build_id.get(..12).unwrap_or(&self.build_id)
    }

    pub fn is_same_release(&self, other: &Self) -> bool {
        self == other
    }
}

pub fn binary_marker() -> &'static str {
    concat!("WALDEN_BUILD_ID=", env!("WALDEN_BUILD_ID"))
}

pub fn profile_marker() -> &'static str {
    concat!("WALDEN_BUILD_PROFILE=", env!("WALDEN_BUILD_PROFILE"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_identity_contains_a_full_source_digest() {
        let build = BuildInfo::current();
        assert_eq!(build.build_id.len(), 64);
        assert!(build.build_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(build.short_build_id().len(), 12);
        assert!(binary_marker().ends_with(&build.build_id));
        assert!(profile_marker().ends_with(&build.profile));
    }
}
