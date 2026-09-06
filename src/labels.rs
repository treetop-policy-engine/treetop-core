use cedar_policy::{EntityTypeName, RestrictedExpression};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use utoipa::{PartialSchema, ToSchema};

use crate::error::PolicyError;
use crate::traits::CedarAtom;
use crate::types::{AttrValue, Resource};

/// Stable application-defined identity for one complete labeling configuration.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct LabelSetVersion(Arc<str>);

impl LabelSetVersion {
    fn new(value: impl AsRef<str>) -> Result<Self, PolicyError> {
        let value = value.as_ref();
        if value.trim().is_empty() {
            return Err(PolicyError::LabelConfigError(
                "label-set version must not be empty".to_string(),
            ));
        }
        Ok(Self(value.into()))
    }

    /// Borrow the application-defined version string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for LabelSetVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LabelSetVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

impl PartialSchema for LabelSetVersion {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        <String as PartialSchema>::schema()
    }
}

impl ToSchema for LabelSetVersion {}

/// Exclusive ownership of one attribute on one exact Cedar resource type.
///
/// Resource types include their complete namespace: `App::Host` and `Other::Host`
/// are distinct scopes. Wildcards and resource entity IDs are not scopes.
/// Construction and deserialization validate both components once.
///
/// ```
/// use treetop_core::LabelTarget;
/// let target = LabelTarget::new("App::Host", "labels")?;
/// assert_eq!(target.resource_type(), "App::Host");
/// # Ok::<(), treetop_core::PolicyError>(())
/// ```
///
/// ```compile_fail
/// use treetop_core::LabelTarget;
/// let target = LabelTarget { resource_type: "*".into(), attribute: "id".into() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LabelTarget {
    resource_type: String,
    attribute: String,
    #[serde(skip)]
    entity_type: EntityTypeName,
}

impl Hash for LabelTarget {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.entity_type.hash(state);
        self.attribute.hash(state);
    }
}

impl LabelTarget {
    /// Validate an exact resource type and a nonempty, nonreserved attribute.
    ///
    /// Returns `LabelConfigError` for an invalid Cedar type or attribute, including
    /// wildcards and the reserved canonical `id` attribute.
    pub fn new(
        resource_type: impl AsRef<str>,
        attribute: impl Into<String>,
    ) -> Result<Self, PolicyError> {
        let resource_type = resource_type.as_ref();
        let entity_type: EntityTypeName = resource_type.parse().map_err(|error| {
            PolicyError::LabelConfigError(format!(
                "invalid label resource type '{resource_type}': {error}"
            ))
        })?;
        let attribute = attribute.into();
        validate_output(&attribute)?;
        Ok(Self {
            resource_type: entity_type.to_string(),
            attribute,
            entity_type,
        })
    }

    /// Canonical, fully qualified Cedar resource type.
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// The resource attribute owned within this type.
    pub fn attribute(&self) -> &str {
        &self.attribute
    }

    fn matches(&self, resource: &Resource) -> bool {
        resource.cedar_entity_uid().type_name() == &self.entity_type
    }
}

impl<'de> Deserialize<'de> for LabelTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireTarget {
            resource_type: String,
            attribute: String,
        }
        let wire = WireTarget::deserialize(deserializer)?;
        Self::new(wire.resource_type, wire.attribute).map_err(D::Error::custom)
    }
}

/// Derives one trusted attribute within one declared resource scope.
///
/// Implementations declare a validated target and receive an immutable resource.
/// Core enforces the scope and owns all replacement/removal. A registry captures
/// the target at construction; later evaluation uses that frozen declaration.
pub trait Labeler: Send + Sync {
    /// Declare the exact resource type and attribute this labeler owns.
    fn target(&self) -> &LabelTarget;

    /// Derive the declared output from trusted identity or input attributes.
    ///
    /// Controlled application removes the owned output before calling this
    /// method. Returning `None` leaves the output absent. Implementations must
    /// be fast, deterministic, side-effect-free, and must not block.
    fn derive(&self, resource: &Resource) -> Option<AttrValue>;
}

/// Controlled, scope-enforcing application available on every labeler.
///
/// This blanket implementation cannot be replaced by individual labelers.
/// `labeler.apply(&mut resource)` leaves other resource types untouched.
pub trait LabelerApply: Labeler {
    /// Replace or remove the owned attribute when the exact resource type matches.
    fn apply(&self, resource: &mut Resource) {
        let target = self.target();
        if !target.matches(resource) {
            return;
        }
        resource.attrs().remove(target.attribute());
        if let Some(value) = self.derive(resource) {
            resource
                .attrs()
                .insert(target.attribute().to_string(), value);
        }
    }
}

impl<T: Labeler + ?Sized> LabelerApply for T {}

/// A labeler that uses regular expressions for matching on resource attributes.
#[derive(Debug, Clone)]
pub struct RegexLabeler {
    target: LabelTarget,
    /// attribute to read from, e.g. "name"
    field: String,
    /// Rulesets for matching resource attributes
    table: Vec<(String, Regex)>,
}

impl RegexLabeler {
    /// Create a regex-based labeler.
    ///
    /// - `target`: validated resource type and derived attribute ownership
    /// - `field`: attribute to read from (e.g., "name")
    /// - `table`: vector of `(label, regex)` pairs
    ///
    /// Configure `field` and the target attribute as distinct attributes so repeated
    /// application remains idempotent. `field` reads the resource attribute
    /// map; it does not expose canonical entity fields. In particular, an
    /// attribute named `id` is not the canonical [`Resource::id`] value during
    /// labeling. Use a custom [`Labeler`] that reads [`Resource::id`] when
    /// labels must derive from the resource identity.
    pub fn new(
        target: LabelTarget,
        field: impl Into<String>,
        table: Vec<(String, Regex)>,
    ) -> Result<Self, PolicyError> {
        let field = field.into();
        if field.trim().is_empty() {
            return Err(PolicyError::LabelConfigError(
                "regex labeler input field must not be empty".to_string(),
            ));
        }
        if field == target.attribute() {
            return Err(PolicyError::LabelConfigError(format!(
                "regex labeler input and output must differ ('{field}')"
            )));
        }
        Ok(Self {
            target,
            field,
            table,
        })
    }
}

impl Labeler for RegexLabeler {
    fn target(&self) -> &LabelTarget {
        &self.target
    }

    fn derive(&self, resource: &Resource) -> Option<AttrValue> {
        let Some(AttrValue::String(value)) = resource.attributes().get(&self.field) else {
            return None;
        };
        let out = self
            .table
            .iter()
            .filter(|(_, re)| re.is_match(value))
            .map(|(label, _)| AttrValue::String(label.clone()))
            .collect();

        Some(AttrValue::Set(out))
    }
}

fn validate_output(output: &str) -> Result<(), PolicyError> {
    if output.trim().is_empty() {
        return Err(PolicyError::LabelConfigError(
            "labeler output must not be empty".to_string(),
        ));
    }
    if output == "id" {
        return Err(PolicyError::LabelConfigError(
            "labeler output 'id' is reserved for the canonical resource ID".to_string(),
        ));
    }
    // Construct the same restricted record used by Context::from_pairs without
    // evaluating it. The value is a literal, so evaluation cannot add validation;
    // creating a Context would unnecessarily initialize all Cedar extensions.
    RestrictedExpression::new_record([(output.to_string(), RestrictedExpression::new_bool(true))])
        .map_err(|error| {
            PolicyError::LabelConfigError(format!(
                "invalid Cedar attribute name '{output}': {error}"
            ))
        })?;
    Ok(())
}

/// Immutable collection of labelers indexed by their declared resource type.
///
/// Each `(resource type, attribute)` has one owner. Outputs on unrelated types
/// remain application-owned inputs. Versions identify complete configurations;
/// engine generations distinguish atomic registry replacements.
#[derive(Clone)]
pub struct LabelRegistry {
    version: Option<LabelSetVersion>,
    scopes: Arc<HashMap<EntityTypeName, Vec<RegisteredLabeler>>>,
}

struct RegisteredLabeler {
    target: LabelTarget,
    labeler: Arc<dyn Labeler>,
}

impl RegisteredLabeler {
    fn apply(&self, resource: &mut Resource) {
        resource.attrs().remove(self.target.attribute());
        if let Some(value) = self.labeler.derive(resource) {
            resource
                .attrs()
                .insert(self.target.attribute().to_string(), value);
        }
    }
}

impl LabelRegistry {
    /// Application-defined identity of this complete configuration.
    pub fn version(&self) -> Option<&LabelSetVersion> {
        self.version.as_ref()
    }

    /// Clone only when at least one target owns an attribute on this resource type.
    pub(crate) fn apply_to_clone_if_applicable(&self, resource: &Resource) -> Option<Resource> {
        let labelers = self.scopes.get(resource.cedar_entity_uid().type_name())?;
        let mut labelled = resource.clone();
        Self::apply_scope(labelers, &mut labelled);
        Some(labelled)
    }

    /// Clear all outputs owned on this type, then derive in registration order.
    ///
    /// Clearing before any derivation prevents an earlier labeler from trusting
    /// a caller-supplied value owned by a later labeler. Other types are unchanged.
    pub fn apply(&self, resource: &mut Resource) {
        if let Some(labelers) = self.scopes.get(resource.cedar_entity_uid().type_name()) {
            Self::apply_scope(labelers, resource);
        }
    }

    fn apply_scope(labelers: &[RegisteredLabeler], resource: &mut Resource) {
        for labeler in labelers {
            resource.attrs().remove(labeler.target.attribute());
        }
        for labeler in labelers {
            labeler.apply(resource);
        }
    }
}

/// Builder for creating a LabelRegistry with labelers.
///
/// This uses a builder pattern to ensure labelers are properly initialized
/// before the registry is used.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use treetop_core::{LabelTarget, LabelRegistryBuilder, RegexLabeler};
/// use regex::Regex;
///
/// let registry = LabelRegistryBuilder::new()
///     .add_labeler(Arc::new(RegexLabeler::new(LabelTarget::new("Host", "nameLabels").unwrap(), "name",
///         vec![("prod".to_string(), Regex::new(r"\.prod\.").unwrap())],
///     ).unwrap()))
///     .build()
///     .unwrap();
/// ```
///
/// Use [`LabelRegistryBuilder::versioned`] when decisions must identify the
/// label configuration across processes or restarts.
#[derive(Default)]
pub struct LabelRegistryBuilder {
    version: Option<String>,
    labelers: Vec<Arc<dyn Labeler>>,
}

impl LabelRegistryBuilder {
    /// Create an unversioned label registry builder.
    ///
    /// Replacements remain distinguishable by the engine's monotonic
    /// generation. Use [`Self::versioned`] when a stable application identifier
    /// is also needed for audit correlation across processes or restarts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry builder with a stable application-defined version.
    pub fn versioned(version: impl Into<String>) -> Self {
        Self {
            version: Some(version.into()),
            labelers: Vec::new(),
        }
    }

    /// Add a labeler to the registry.
    ///
    /// This can be called repeatedly to build up a registry before `build()`.
    pub fn add_labeler(mut self, labeler: Arc<dyn Labeler>) -> Self {
        self.labelers.push(labeler);
        self
    }

    /// Validate and build the immutable label registry.
    ///
    /// Fails for an empty configured version or duplicate `(resource type,
    /// attribute)` ownership. Targets have already validated reserved names.
    /// Consumes the builder and returns a registry ready to install with
    /// `PolicyEngine::with_label_registry`.
    pub fn build(self) -> Result<LabelRegistry, PolicyError> {
        let version = self.version.map(LabelSetVersion::new).transpose()?;
        let mut targets = HashSet::with_capacity(self.labelers.len());
        let mut scopes: HashMap<EntityTypeName, Vec<RegisteredLabeler>> = HashMap::new();
        for labeler in &self.labelers {
            let target = labeler.target();
            if !targets.insert(target) {
                return Err(PolicyError::LabelConfigError(format!(
                    "multiple labelers own target ({}, {})",
                    target.resource_type(),
                    target.attribute()
                )));
            }
            let target = target.clone();
            scopes
                .entry(target.entity_type.clone())
                .or_default()
                .push(RegisteredLabeler {
                    target,
                    labeler: Arc::clone(labeler),
                });
        }
        Ok(LabelRegistry {
            version,
            scopes: Arc::new(scopes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use yare::parameterized;

    #[test]
    fn targets_validate_and_round_trip_through_the_same_boundary() {
        let target = LabelTarget::new("App::Host", "labels").unwrap();
        let json = serde_json::json!({"resource_type": "App::Host", "attribute": "labels"});
        assert_eq!(serde_json::to_value(&target).unwrap(), json);
        assert_eq!(serde_json::from_value::<LabelTarget>(json).unwrap(), target);
        for resource_type in ["", "*", "App::*", "App::", "App::Host::\"one\""] {
            assert!(LabelTarget::new(resource_type, "labels").is_err());
            assert!(
                serde_json::from_value::<LabelTarget>(serde_json::json!({
                    "resource_type": resource_type, "attribute": "labels"
                }))
                .is_err()
            );
        }
        for attribute in ["", " ", "id"] {
            assert!(LabelTarget::new("App::Host", attribute).is_err());
            assert!(
                serde_json::from_value::<LabelTarget>(serde_json::json!({
                    "resource_type": "App::Host", "attribute": attribute
                }))
                .is_err()
            );
        }
        for json in [
            serde_json::json!({"kind": "App::Host", "output": "labels"}),
            serde_json::json!({"resource_type": "App::Host"}),
            serde_json::json!({"resource_type": "App::Host", "attribute": "labels", "extra": true}),
        ] {
            assert!(serde_json::from_value::<LabelTarget>(json).is_err());
        }
    }

    #[test]
    fn identical_attribute_names_have_independent_qualified_type_owners() {
        let mut builder = LabelRegistryBuilder::new();
        let pattern = Regex::new("prod").unwrap();
        for resource_type in ["App::Host", "Other::Host"] {
            builder = builder.add_labeler(Arc::new(
                RegexLabeler::new(
                    LabelTarget::new(resource_type, "labels").unwrap(),
                    "name",
                    vec![(resource_type.to_string(), pattern.clone())],
                )
                .unwrap(),
            ));
        }
        let registry = builder.build().unwrap();
        for resource_type in ["App::Host", "Other::Host"] {
            let mut resource = Resource::new(resource_type, "one")
                .unwrap()
                .with_attr("name", AttrValue::String("prod".into()))
                .with_attr("labels", AttrValue::String("forged".into()));
            registry.apply(&mut resource);
            assert_eq!(
                resource.attributes().get("labels"),
                Some(&AttrValue::Set(vec![AttrValue::String(
                    resource_type.to_string()
                )]))
            );
            let first = resource.clone();
            registry.apply(&mut resource);
            assert_eq!(resource, first);
        }
    }

    #[test]
    fn direct_application_enforces_the_declared_scope() {
        let labeler = EchoOwnedOutput(LabelTarget::new("App::Host", "labels").unwrap());
        let mut other = Resource::new("Other::Host", "one")
            .unwrap()
            .with_attr("labels", AttrValue::String("application input".into()));
        let original = other.clone();
        labeler.apply(&mut other);
        assert_eq!(other, original);
        let mut matching = Resource::new("App::Host", "one")
            .unwrap()
            .with_attr("labels", AttrValue::String("forged".into()));
        labeler.apply(&mut matching);
        assert!(!matching.attributes().contains_key("labels"));
    }

    #[test]
    fn registry_freezes_targets_at_construction() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct ChangingDeclaration {
            original: LabelTarget,
            replacement: LabelTarget,
            changed: AtomicBool,
        }
        impl Labeler for ChangingDeclaration {
            fn target(&self) -> &LabelTarget {
                if self.changed.load(Ordering::Relaxed) {
                    &self.replacement
                } else {
                    &self.original
                }
            }
            fn derive(&self, _: &Resource) -> Option<AttrValue> {
                Some(AttrValue::Bool(true))
            }
        }
        let labeler = Arc::new(ChangingDeclaration {
            original: LabelTarget::new("App::Host", "labels").unwrap(),
            replacement: LabelTarget::new("Other::Host", "other").unwrap(),
            changed: AtomicBool::new(false),
        });
        let registry = LabelRegistryBuilder::new()
            .add_labeler(labeler.clone())
            .build()
            .unwrap();
        labeler.changed.store(true, Ordering::Relaxed);
        let mut original = Resource::new("App::Host", "one").unwrap();
        registry.apply(&mut original);
        assert_eq!(
            original.attributes().get("labels"),
            Some(&AttrValue::Bool(true))
        );
        assert!(!original.attributes().contains_key("other"));
        let other = Resource::new("Other::Host", "one").unwrap();
        assert!(registry.apply_to_clone_if_applicable(&other).is_none());
    }

    struct EchoOwnedOutput(LabelTarget);

    impl Labeler for EchoOwnedOutput {
        fn target(&self) -> &LabelTarget {
            &self.0
        }
        fn derive(&self, resource: &Resource) -> Option<AttrValue> {
            resource
                .attributes()
                .get(self.target().attribute())
                .cloned()
        }
    }

    struct CopyAttribute {
        target: LabelTarget,
        input: &'static str,
    }

    impl Labeler for CopyAttribute {
        fn target(&self) -> &LabelTarget {
            &self.target
        }
        fn derive(&self, resource: &Resource) -> Option<AttrValue> {
            resource.attributes().get(self.input).cloned()
        }
    }

    fn compile(rules: Vec<(&str, &str)>) -> Vec<(String, Regex)> {
        rules
            .into_iter()
            .map(|(l, p)| (l.to_string(), Regex::new(p).unwrap()))
            .collect()
    }

    fn get_label_strings(res: &mut Resource, key: &str) -> BTreeSet<String> {
        match res.attrs().get(key) {
            Some(AttrValue::Set(v)) => v
                .iter()
                .filter_map(|a| {
                    if let AttrValue::String(s) = a {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    #[parameterized(
        simple_match = {
            "Host", "name", "nameLabels",
            vec![("prod", r"(^|\.)prod\.example\.com$")],
            "db12.prod.example.com",
            &["prod"]
        },
        no_match = {
            "Host", "name", "nameLabels",
            vec![("corp", r"(^|\.)corp\.example\.com$")],
            "web.dev.example.com",
            &[]
        },
        multi_match = {
            "Host", "name", "nameLabels",
            vec![("prod", r"(^|\.)prod\."), ("db", r"(^|\.)db\d+\.")],
            "db42.prod.example.com",
            &["db","prod"]
        }
    )]
    fn regex_labeler_apply_basic(
        kind: &str,
        field: &str,
        output: &str,
        rules: Vec<(&str, &str)>,
        input: &str,
        expected: &[&str],
    ) {
        let labeler = RegexLabeler::new(
            LabelTarget::new(kind, output).unwrap(),
            field,
            compile(rules),
        )
        .unwrap();

        let mut res = Resource::new(kind, input).unwrap();
        res.attrs()
            .insert(field.to_string(), AttrValue::String(input.to_string()));

        labeler.apply(&mut res);

        let got = get_label_strings(&mut res, output);
        let want: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn regex_labeler_missing_input_field_is_noop() {
        let labeler = RegexLabeler::new(
            LabelTarget::new("Host", "nameLabels").unwrap(),
            "name",
            compile(vec![("prod", r"(^|\.)prod\.")]),
        )
        .unwrap();

        let mut res = Resource::new("Host", "db99.prod.example.com").unwrap();
        // no "name" inserted

        labeler.apply(&mut res);
        assert!(res.attrs().get("nameLabels").is_none());
    }

    #[test]
    fn regex_labeler_replaces_untrusted_existing_set() {
        let labeler = RegexLabeler::new(
            LabelTarget::new("Host", "nameLabels").unwrap(),
            "name",
            compile(vec![("prod", r"(^|\.)prod\."), ("db", r"(^|\.)db\d+\.")]),
        )
        .unwrap();

        let mut res = Resource::new("Host", "db99.prod.example.com").unwrap();
        res.attrs().insert(
            "name".into(),
            AttrValue::String("db99.prod.example.com".into()),
        );
        res.attrs().insert(
            "nameLabels".into(),
            AttrValue::Set(vec![AttrValue::String("pre".into())]),
        );

        labeler.apply(&mut res);

        let labels = get_label_strings(&mut res, "nameLabels");
        assert!(!labels.contains("pre"));
        assert!(labels.contains("prod"));
        assert!(labels.contains("db"));
    }

    #[test]
    fn regex_labeler_replaces_untrusted_set_when_no_rule_matches() {
        let labeler = RegexLabeler::new(
            LabelTarget::new("Host", "nameLabels").unwrap(),
            "name",
            compile(vec![("prod", r"(^|\.)prod\.")]),
        )
        .unwrap();
        let mut res = Resource::new("Host", "public.example.com")
            .unwrap()
            .with_attr("name", AttrValue::String("public.example.com".into()))
            .with_attr(
                "nameLabels",
                AttrValue::Set(vec![AttrValue::String("prod".into())]),
            );

        labeler.apply(&mut res);

        assert_eq!(
            res.attributes().get("nameLabels"),
            Some(&AttrValue::Set(Vec::new()))
        );
    }

    #[test]
    fn regex_labeler_removes_untrusted_output_when_input_is_missing() {
        let labeler = RegexLabeler::new(
            LabelTarget::new("Host", "nameLabels").unwrap(),
            "name",
            compile(vec![("prod", r"(^|\.)prod\.")]),
        )
        .unwrap();
        let mut res = Resource::new("Host", "public.example.com")
            .unwrap()
            .with_attr(
                "nameLabels",
                AttrValue::Set(vec![AttrValue::String("prod".into())]),
            );

        labeler.apply(&mut res);

        assert!(!res.attributes().contains_key("nameLabels"));
    }

    #[test]
    fn custom_labeler_cannot_observe_or_preserve_untrusted_owned_output() {
        let mut resource = Resource::new("Host", "attacker.invalid")
            .unwrap()
            .with_attr("labels", AttrValue::String("forged".into()));

        EchoOwnedOutput(LabelTarget::new("Host", "labels").unwrap()).apply(&mut resource);

        assert!(!resource.attributes().contains_key("labels"));
    }

    #[test]
    fn registry_preserves_other_types_attributes_without_cloning() {
        let registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(EchoOwnedOutput(
                LabelTarget::new("Host", "labels").unwrap(),
            )))
            .build()
            .unwrap();
        let resource = Resource::new("Document", "report")
            .unwrap()
            .with_attr("labels", AttrValue::String("forged".into()));

        assert!(registry.apply_to_clone_if_applicable(&resource).is_none());
        let mut applied = resource.clone();
        registry.apply(&mut applied);
        assert_eq!(applied, resource);
        assert_eq!(
            resource.attributes().get("labels"),
            Some(&AttrValue::String("forged".into()))
        );
    }

    #[test]
    fn registry_clears_later_owned_output_before_earlier_derivation() {
        let registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(CopyAttribute {
                target: LabelTarget::new("Host", "labels").unwrap(),
                input: "laterLabels",
            }))
            .add_labeler(Arc::new(CopyAttribute {
                target: LabelTarget::new("Host", "laterLabels").unwrap(),
                input: "unused",
            }))
            .build()
            .unwrap();
        let mut resource = Resource::new("Host", "attacker.invalid")
            .unwrap()
            .with_attr("laterLabels", AttrValue::String("forged".into()));

        registry.apply(&mut resource);

        assert!(!resource.attributes().contains_key("labels"));
        assert!(!resource.attributes().contains_key("laterLabels"));
    }

    #[test]
    fn registry_rejects_ambiguous_or_reserved_outputs() {
        let first = RegexLabeler::new(
            LabelTarget::new("Host", "labels").unwrap(),
            "name",
            Vec::new(),
        )
        .unwrap();
        let second = RegexLabeler::new(
            LabelTarget::new("Host", "labels").unwrap(),
            "owner",
            Vec::new(),
        )
        .unwrap();
        let duplicate = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(first))
            .add_labeler(Arc::new(second))
            .build();
        assert!(matches!(duplicate, Err(PolicyError::LabelConfigError(_))));

        assert!(LabelTarget::new("Host", "id").is_err());
        assert!(
            RegexLabeler::new(
                LabelTarget::new("Host", "name").unwrap(),
                "name",
                Vec::new()
            )
            .is_err()
        );
        assert!(LabelRegistryBuilder::versioned("").build().is_err());
    }

    #[test]
    fn output_validation_preserves_cedar_record_key_semantics() {
        // Cedar record keys are strings, including keys accessed with bracket
        // syntax. Constructing a Context must not narrow that accepted set.
        for output in [
            "labels",
            "has space",
            "hyphen-name",
            "名前",
            "quote\"",
            "a\0b",
            "id ",
        ] {
            assert!(
                cedar_policy::Context::from_pairs([(
                    output.to_string(),
                    RestrictedExpression::new_bool(true),
                )])
                .is_ok()
            );
            assert!(validate_output(output).is_ok(), "{output:?}");
            assert!(
                RegexLabeler::new(
                    LabelTarget::new("Host", output).unwrap(),
                    "name",
                    Vec::new()
                )
                .is_ok()
            );
        }
        for output in ["", " ", "\t\n", "id"] {
            assert!(matches!(
                validate_output(output),
                Err(PolicyError::LabelConfigError(_))
            ));
        }
    }

    #[test]
    fn controlled_apply_is_idempotent() {
        let labeler = RegexLabeler::new(
            LabelTarget::new("Host", "labels").unwrap(),
            "name",
            compile(vec![("prod", "prod")]),
        )
        .unwrap();
        let mut resource = Resource::new("Host", "prod")
            .unwrap()
            .with_attr("name", AttrValue::String("prod".into()))
            .with_attr(
                "labels",
                AttrValue::Set(vec![AttrValue::String("forged".into())]),
            );

        labeler.apply(&mut resource);
        let once = resource.clone();
        labeler.apply(&mut resource);
        assert_eq!(resource, once);
    }
}
