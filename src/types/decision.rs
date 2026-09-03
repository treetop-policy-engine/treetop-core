//! Authorization decision types with policy metadata.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::error::PolicyError;
use crate::labels::LabelSetVersion;

/// A permit policy that permitted a specific action on a resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
pub struct PermitPolicy {
    #[schema(value_type = String)]
    pub literal: Arc<str>,
    #[schema(value_type = serde_json::Value)]
    pub json: Arc<Value>,
    #[schema(value_type = Option<String>)]
    pub annotation_id: Option<Arc<str>>,
    #[schema(value_type = String)]
    pub cedar_id: Arc<str>,
}

impl PermitPolicy {
    pub fn new(literal: String, json: Value, cedar_id: String) -> Self {
        let annotation_id = Self::extract_annotation_id(&literal, &json);
        Self {
            literal: literal.into(),
            json: Arc::new(json),
            annotation_id,
            cedar_id: cedar_id.into(),
        }
    }

    /// Returns the ID of the policy if available.
    ///
    /// IDs should be in annotations > id field in the JSON representation, or an @id line in the literal.
    pub fn id(&self) -> &str {
        match &self.annotation_id {
            Some(id) => id.as_ref(),
            None => self.cedar_id.as_ref(),
        }
    }

    fn extract_annotation_id(literal: &str, json: &Value) -> Option<Arc<str>> {
        if let Some(annotations) = json.get("annotations")
            && let Some(id_value) = annotations.get("id")
            && let Some(id_str) = id_value.as_str()
        {
            return Some(Arc::from(id_str));
        }

        for line in literal.lines() {
            let trimmed = line.trim();
            if let Some(value) = trimmed
                .strip_prefix("@id(")
                .and_then(|value| value.strip_suffix(')'))
                && let Ok(id) = serde_json::from_str::<String>(value.trim())
            {
                return Some(id.into());
            }
        }

        None
    }
}

/// A collection of permit policies with optimized access patterns.
///
/// This wrapper provides efficient methods for common operations like
/// displaying policies, extracting IDs, and iterating over policies.
///
/// Serializes as a flat array instead of a nested object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
#[serde(transparent)]
pub struct PermitPolicies(Vec<PermitPolicy>);

impl PermitPolicies {
    /// Create a new collection from a vector of policies.
    pub fn new(policies: Vec<PermitPolicy>) -> Self {
        Self(policies)
    }

    /// Create an empty collection.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of policies in this collection.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get policy IDs as a sorted vector of strings.
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.0.iter().map(|p| p.id().to_string()).collect();
        ids.sort();
        ids
    }

    /// Get an iterator over the policies.
    pub fn iter(&self) -> impl Iterator<Item = &PermitPolicy> {
        self.0.iter()
    }

    /// Consume self and return the inner vector of policies.
    pub fn into_inner(self) -> Vec<PermitPolicy> {
        self.0
    }

    /// Get a reference to the inner vector of policies.
    pub fn as_slice(&self) -> &[PermitPolicy] {
        &self.0
    }
}

impl Display for PermitPolicies {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Get sorted literals for consistent display
        let mut literals: Vec<&str> = self.0.iter().map(|p| p.literal.as_ref()).collect();
        literals.sort();
        write!(f, "{}", literals.join("; "))
    }
}

impl IntoIterator for PermitPolicies {
    type Item = PermitPolicy;
    type IntoIter = std::vec::IntoIter<PermitPolicy>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a PermitPolicies {
    type Item = &'a PermitPolicy;
    type IntoIter = std::slice::Iter<'a, PermitPolicy>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl From<Vec<PermitPolicy>> for PermitPolicies {
    fn from(policies: Vec<PermitPolicy>) -> Self {
        Self::new(policies)
    }
}

impl FromIterator<PermitPolicy> for PermitPolicies {
    fn from_iter<I: IntoIterator<Item = PermitPolicy>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

/// Version metadata for the complete engine state used during an evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
pub struct PolicyVersion {
    /// Hash of the policy source (e.g. SHA-256 of the policy text).
    #[schema(value_type = String)]
    pub hash: Arc<str>,
    /// When this policy set was loaded into the engine.
    #[schema(value_type = String)]
    pub loaded_at: Arc<str>,
    /// Application-defined label-set version, when the installed registry has one.
    #[serde(default)]
    pub label_set: Option<LabelSetVersion>,
    /// Monotonic generation within this engine instance.
    #[serde(default)]
    pub generation: u64,
}

impl Display for PolicyVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} @ {} (generation {})",
            self.hash, self.loaded_at, self.generation
        )
    }
}

/// Allow or deny decision produced by a trusted engine evaluation.
///
/// This type intentionally does not implement `Deserialize`. Use
/// [`DecisionDto`] for untrusted or persisted wire data; a DTO is never
/// authorization evidence.
///
/// Its non-exhaustive variants cannot be constructed outside this crate:
///
/// ```compile_fail
/// use treetop_core::{Decision, PolicyVersion};
///
/// let version = PolicyVersion {
///     hash: "hash".into(),
///     loaded_at: "2026-09-04T00:00:00Z".into(),
///     label_set: None,
///     generation: 1,
/// };
/// let forged = Decision::Deny { version };
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash, ToSchema)]
#[non_exhaustive]
pub enum Decision {
    #[non_exhaustive]
    Allow {
        policies: PermitPolicies,
        version: PolicyVersion,
    },
    #[non_exhaustive]
    Deny { version: PolicyVersion },
}

/// Serializable and deserializable decision-shaped data without authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
#[non_exhaustive]
pub enum DecisionDto {
    Allow {
        policies: PermitPolicies,
        version: PolicyVersion,
    },
    Deny {
        version: PolicyVersion,
    },
}

/// Authorization decision plus deny-side forbid diagnostics.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash, ToSchema)]
pub struct DecisionDiagnostics {
    decision: Decision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    matched_forbid_policy_ids: Vec<String>,
}

impl Decision {
    /// Whether this trusted decision allows the request.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Complete engine-state version used for evaluation.
    pub fn version(&self) -> &PolicyVersion {
        match self {
            Self::Allow { version, .. } | Self::Deny { version, .. } => version,
        }
    }

    /// Permit policies for an allow decision.
    pub fn permit_policies(&self) -> Option<&PermitPolicies> {
        match self {
            Self::Allow { policies, .. } => Some(policies),
            Self::Deny { .. } => None,
        }
    }
}

impl DecisionDiagnostics {
    pub(crate) fn new(decision: Decision, matched_forbid_policy_ids: Vec<String>) -> Self {
        Self {
            decision,
            matched_forbid_policy_ids,
        }
    }

    /// Borrow the trusted authorization decision.
    pub fn decision(&self) -> &Decision {
        &self.decision
    }

    /// Consume diagnostics and return the trusted authorization decision.
    pub fn into_decision(self) -> Decision {
        self.decision
    }

    /// Borrow matching forbid policy IDs disclosed for this denial.
    pub fn matched_forbid_policy_ids(&self) -> &[String] {
        &self.matched_forbid_policy_ids
    }
}

impl From<&Decision> for DecisionDto {
    fn from(decision: &Decision) -> Self {
        match decision {
            Decision::Allow {
                policies, version, ..
            } => Self::Allow {
                policies: policies.clone(),
                version: version.clone(),
            },
            Decision::Deny { version, .. } => Self::Deny {
                version: version.clone(),
            },
        }
    }
}

impl Display for Decision {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Decision::Allow {
                policies, version, ..
            } => {
                write!(f, "Allow(hash={}; [{}])", version.hash, policies)
            }
            Decision::Deny { version, .. } => write!(f, "Deny(hash={})", version.hash),
        }
    }
}

/// Convert a Cedar decision plus precomputed policy metadata into a decision.
///
/// The conversion fails closed if Cedar reports `Allow` but no matching permit
/// policy metadata is available.
impl Decision {
    pub(crate) fn from_cedar(
        response: cedar_policy::Decision,
        policies: PermitPolicies,
        version: PolicyVersion,
    ) -> Result<Self, PolicyError> {
        match response {
            cedar_policy::Decision::Allow => {
                if policies.is_empty() {
                    return Err(PolicyError::EvalError(
                        "Cedar returned Allow without a matching permit policy".to_string(),
                    ));
                }
                Ok(Decision::Allow { policies, version })
            }
            cedar_policy::Decision::Deny => Ok(Decision::Deny { version }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version() -> PolicyVersion {
        PolicyVersion {
            hash: "abc123".into(),
            loaded_at: "2023-01-01T00:00:00Z".into(),
            label_set: None,
            generation: 7,
        }
    }

    fn policy() -> PermitPolicy {
        PermitPolicy::new(
            "@id(\"allow_read\")\npermit(principal, action, resource);".to_string(),
            serde_json::json!({"effect": "permit"}),
            "policy0".to_string(),
        )
    }

    #[test]
    fn trusted_allow_exposes_evidence_and_metadata() {
        let decision = Decision::from_cedar(
            cedar_policy::Decision::Allow,
            vec![policy()].into(),
            version(),
        )
        .unwrap();

        assert!(decision.is_allowed());
        assert_eq!(decision.version().generation, 7);
        assert_eq!(decision.permit_policies().unwrap().ids(), ["allow_read"]);
        assert!(decision.to_string().contains("Allow"));
    }

    #[test]
    fn allow_without_permit_metadata_fails_closed() {
        let result = Decision::from_cedar(
            cedar_policy::Decision::Allow,
            PermitPolicies::empty(),
            version(),
        );
        assert!(matches!(result, Err(PolicyError::EvalError(_))));
    }

    #[test]
    fn trusted_deny_has_no_permit_policies() {
        let decision = Decision::from_cedar(
            cedar_policy::Decision::Deny,
            PermitPolicies::empty(),
            version(),
        )
        .unwrap();

        assert!(!decision.is_allowed());
        assert!(decision.permit_policies().is_none());
        assert!(decision.to_string().contains("Deny"));
    }

    #[test]
    fn trusted_decision_serializes_to_untrusted_dto_shape() {
        let decision = Decision::from_cedar(
            cedar_policy::Decision::Allow,
            vec![policy()].into(),
            version(),
        )
        .unwrap();
        let serialized = serde_json::to_value(&decision).unwrap();
        let dto: DecisionDto = serde_json::from_value(serialized.clone()).unwrap();

        assert!(serialized["Allow"]["policies"].is_array());
        assert!(matches!(dto, DecisionDto::Allow { .. }));
        assert_eq!(DecisionDto::from(&decision), dto);
    }

    #[test]
    fn policy_version_round_trips() {
        let version = version();
        let serialized = serde_json::to_value(&version).unwrap();
        let deserialized: PolicyVersion = serde_json::from_value(serialized).unwrap();
        assert_eq!(version, deserialized);
        assert!(version.to_string().contains("generation 7"));
    }

    #[test]
    fn permit_policy_uses_annotation_id() {
        assert_eq!(policy().id(), "allow_read");
    }

    #[test]
    fn permit_policies_are_iterable_and_display_deterministically() {
        let first = PermitPolicy::new(
            "permit(principal, action, resource == File::\"z\");".to_string(),
            serde_json::json!({}),
            "z".to_string(),
        );
        let second = PermitPolicy::new(
            "permit(principal, action, resource == File::\"a\");".to_string(),
            serde_json::json!({}),
            "a".to_string(),
        );
        let policies = PermitPolicies::new(vec![first, second]);

        assert_eq!(policies.len(), 2);
        assert_eq!(policies.ids(), ["a", "z"]);
        assert!(policies.to_string().contains("; "));
        assert_eq!((&policies).into_iter().count(), 2);
    }

    #[test]
    fn diagnostics_disclose_forbids_without_changing_decision() {
        let decision = Decision::from_cedar(
            cedar_policy::Decision::Deny,
            PermitPolicies::empty(),
            version(),
        )
        .unwrap();
        let diagnostics = DecisionDiagnostics::new(decision, vec!["deny_delete".to_string()]);

        assert!(!diagnostics.decision().is_allowed());
        assert_eq!(diagnostics.matched_forbid_policy_ids(), ["deny_delete"]);
        let serialized = serde_json::to_value(&diagnostics).unwrap();
        assert_eq!(serialized["matched_forbid_policy_ids"][0], "deny_delete");
    }
}
