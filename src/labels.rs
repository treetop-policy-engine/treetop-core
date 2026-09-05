use cedar_policy::{EntityTypeName, RestrictedExpression};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::collections::HashSet;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;
use utoipa::{PartialSchema, ToSchema};

use crate::error::PolicyError;
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

/// Derives one trusted resource attribute from an immutable resource view.
///
/// The blanket [`LabelerApply`] operation owns mutation of the resource: it
/// always replaces the declared output when derivation returns Some, or removes
/// it when derivation returns None. Caller-provided values therefore cannot
/// survive as trusted labels.
pub trait Labeler: Send + Sync {
    /// Returns true if this labeler applies to resources of the given kind.
    ///
    /// e.g. "Host", "Database::Table"; you can also support wildcard/globs if you want.
    fn applies_to(&self, kind: &str) -> bool;

    /// Name of the single derived attribute this labeler owns.
    fn output(&self) -> &str;

    /// Derive the output from trusted resource identity or input attributes.
    ///
    /// The controlled [`LabelerApply::apply`] operation removes this labeler's
    /// declared output before calling `derive`, so the resource view cannot
    /// expose a caller-provided value for that output.
    ///
    /// Implementations must be fast, deterministic, side-effect-free, and
    /// must not perform blocking I/O.
    fn derive(&self, resource: &Resource) -> Option<AttrValue>;
}

/// Controlled application operation available on every labeler.
///
/// This blanket implementation cannot be replaced by individual labelers:
/// implementers only provide read-only derivation, while this method owns the
/// replace-or-remove mutation rule.
pub trait LabelerApply: Labeler {
    /// Apply this labeler's derived output using replace-or-remove semantics.
    ///
    /// Keeping application as `labeler.apply(&mut resource)` ties the operation
    /// to the deriving type while the blanket implementation prevents custom
    /// labelers from weakening the mutation rule.
    fn apply(&self, resource: &mut Resource) {
        let output = self.output();
        // The declared output is untrusted input until this labeler derives it.
        // Hide it from custom derivations so they cannot echo a forged value.
        resource.attrs().remove(output);

        if let Some(value) = self.derive(resource) {
            resource.attrs().insert(output.to_string(), value);
        }
    }
}

impl<T: Labeler + ?Sized> LabelerApply for T {}

/// A labeler that uses regular expressions for matching on resource attributes.
#[derive(Debug, Clone)]
pub struct RegexLabeler {
    /// The kind of resource this labeler applies to, e.g. "Host"
    kind: String,
    /// attribute to read from, e.g. "name"
    field: String,
    /// attribute to write to, e.g. "nameLabels"
    output: String,
    /// Rulesets for matching resource attributes
    table: Vec<(String, Regex)>,
}

impl RegexLabeler {
    /// Create a regex-based labeler.
    ///
    /// - `kind`: resource kind this applies to (e.g., "Host")
    /// - `field`: attribute to read from (e.g., "name")
    /// - `output`: attribute to write labels to (e.g., "nameLabels")
    /// - `table`: vector of `(label, regex)` pairs
    ///
    /// Configure `field` and `output` as distinct attributes so repeated
    /// application remains idempotent. `field` reads the resource attribute
    /// map; it does not expose canonical entity fields. In particular, an
    /// attribute named `id` is not the canonical [`Resource::id`] value during
    /// labeling. Use a custom [`Labeler`] that reads [`Resource::id`] when
    /// labels must derive from the resource identity.
    pub fn new(
        kind: impl Into<String>,
        field: impl Into<String>,
        output: impl Into<String>,
        table: Vec<(String, Regex)>,
    ) -> Result<Self, PolicyError> {
        let kind = kind.into();
        let field = field.into();
        let output = output.into();
        let _: EntityTypeName = kind.parse().map_err(|error| {
            PolicyError::LabelConfigError(format!(
                "invalid resource type '{kind}' for regex labeler: {error}"
            ))
        })?;
        if field.trim().is_empty() {
            return Err(PolicyError::LabelConfigError(
                "regex labeler input field must not be empty".to_string(),
            ));
        }
        validate_output(&output)?;
        if field == output {
            return Err(PolicyError::LabelConfigError(format!(
                "regex labeler input and output must differ ('{field}')"
            )));
        }
        Ok(Self {
            kind,
            field,
            output,
            table,
        })
    }
}

impl Labeler for RegexLabeler {
    fn applies_to(&self, kind: &str) -> bool {
        self.kind == kind
    }

    fn output(&self) -> &str {
        &self.output
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

/// Immutable collection of trusted resource labelers.
///
/// A registry can carry an application-defined version for audit correlation
/// across processes and restarts. Engine generations still distinguish
/// unversioned registry replacements within one engine instance.
#[derive(Clone)]
pub struct LabelRegistry {
    version: Option<LabelSetVersion>,
    labelers: Arc<[Arc<dyn Labeler>]>,
}

impl LabelRegistry {
    /// Return the application-defined identity of this complete label set.
    pub fn version(&self) -> Option<&LabelSetVersion> {
        self.version.as_ref()
    }

    /// Clone and sanitize a resource when it contains a registry-owned output,
    /// or clone and label it when at least one labeler applies.
    ///
    /// A resource with no registry-owned output is cloned only when a labeler
    /// applies, so registries serving other resource kinds retain the no-clone
    /// fast path. All owned outputs are removed before any derivation, and each
    /// applicability predicate is evaluated at most once in insertion order.
    pub(crate) fn apply_to_clone_if_applicable(&self, res: &Resource) -> Option<Resource> {
        let has_owned_output = self
            .labelers
            .iter()
            .any(|labeler| res.attributes().contains_key(labeler.output()));

        if has_owned_output {
            let mut labelled = res.clone();
            self.apply(&mut labelled);
            return Some(labelled);
        }

        let first_match = self
            .labelers
            .iter()
            .position(|labeler| labeler.applies_to(res.kind()))?;

        let mut labelled = res.clone();
        self.clear_owned_outputs(&mut labelled);
        self.labelers[first_match].apply(&mut labelled);
        for labeler in &self.labelers[first_match + 1..] {
            if labeler.applies_to(labelled.kind()) {
                labeler.apply(&mut labelled);
            }
        }
        Some(labelled)
    }

    /// Applies all labelers in the registry to the given resource.
    ///
    /// All registry-owned outputs are removed before checking applicability or
    /// running derivations. Applicable labelers then run in insertion order and
    /// own distinct output attributes.
    pub fn apply(&self, res: &mut Resource) {
        self.clear_owned_outputs(res);
        for labeler in self.labelers.iter() {
            if labeler.applies_to(res.kind()) {
                labeler.apply(res);
            }
        }
    }

    fn clear_owned_outputs(&self, res: &mut Resource) {
        for labeler in self.labelers.iter() {
            res.attrs().remove(labeler.output());
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
/// use treetop_core::{LabelRegistryBuilder, RegexLabeler};
/// use regex::Regex;
///
/// let registry = LabelRegistryBuilder::new()
///     .add_labeler(Arc::new(RegexLabeler::new(
///         "Host",
///         "name",
///         "nameLabels",
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
    /// Fails for an empty configured version, a reserved output, or duplicate
    /// output ownership. Consumes the builder and returns a registry ready to
    /// install with PolicyEngine::with_label_registry.
    pub fn build(self) -> Result<LabelRegistry, PolicyError> {
        let version = self.version.map(LabelSetVersion::new).transpose()?;
        let mut outputs = HashSet::with_capacity(self.labelers.len());
        for labeler in &self.labelers {
            validate_output(labeler.output())?;
            if !outputs.insert(labeler.output()) {
                return Err(PolicyError::LabelConfigError(format!(
                    "multiple labelers own output '{}'",
                    labeler.output()
                )));
            }
        }
        Ok(LabelRegistry {
            version,
            labelers: self.labelers.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use yare::parameterized;

    struct EchoOwnedOutput;

    impl Labeler for EchoOwnedOutput {
        fn applies_to(&self, kind: &str) -> bool {
            kind == "Host"
        }

        fn output(&self) -> &str {
            "labels"
        }

        fn derive(&self, resource: &Resource) -> Option<AttrValue> {
            resource.attributes().get(self.output()).cloned()
        }
    }

    struct CopyAttribute {
        kind: &'static str,
        input: &'static str,
        output: &'static str,
    }

    impl Labeler for CopyAttribute {
        fn applies_to(&self, kind: &str) -> bool {
            kind == self.kind
        }

        fn output(&self) -> &str {
            self.output
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
        let labeler = RegexLabeler::new(kind, field, output, compile(rules)).unwrap();

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
            "Host",
            "name",
            "nameLabels",
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
            "Host",
            "name",
            "nameLabels",
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
            "Host",
            "name",
            "nameLabels",
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
            "Host",
            "name",
            "nameLabels",
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

        EchoOwnedOutput.apply(&mut resource);

        assert!(!resource.attributes().contains_key("labels"));
    }

    #[test]
    fn registry_removes_owned_output_when_no_labeler_applies() {
        let registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(EchoOwnedOutput))
            .build()
            .unwrap();
        let resource = Resource::new("Document", "report")
            .unwrap()
            .with_attr("labels", AttrValue::String("forged".into()));

        let labelled = registry
            .apply_to_clone_if_applicable(&resource)
            .expect("an owned input attribute must produce a sanitized clone");

        assert!(!labelled.attributes().contains_key("labels"));
        assert_eq!(
            resource.attributes().get("labels"),
            Some(&AttrValue::String("forged".into()))
        );
    }

    #[test]
    fn registry_clears_later_owned_output_before_earlier_derivation() {
        let registry = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(CopyAttribute {
                kind: "Host",
                input: "laterLabels",
                output: "labels",
            }))
            .add_labeler(Arc::new(CopyAttribute {
                kind: "Document",
                input: "unused",
                output: "laterLabels",
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
        let first = RegexLabeler::new("Host", "name", "labels", Vec::new()).unwrap();
        let second = RegexLabeler::new("Host", "owner", "labels", Vec::new()).unwrap();
        let duplicate = LabelRegistryBuilder::new()
            .add_labeler(Arc::new(first))
            .add_labeler(Arc::new(second))
            .build();
        assert!(matches!(duplicate, Err(PolicyError::LabelConfigError(_))));

        assert!(RegexLabeler::new("Host", "name", "id", Vec::new()).is_err());
        assert!(RegexLabeler::new("Host", "name", "name", Vec::new()).is_err());
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
            assert!(RegexLabeler::new("Host", "name", output, Vec::new()).is_ok());
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
        let labeler =
            RegexLabeler::new("Host", "name", "labels", compile(vec![("prod", "prod")])).unwrap();
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
