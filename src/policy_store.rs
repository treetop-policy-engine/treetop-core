//! Policy-store configuration and namespace-based routing.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;

use cedar_policy::pst::{
    ActionConstraint, Clause, EntityOrSlot, Expr, Literal, PrincipalConstraint, ResourceConstraint,
};
use cedar_policy::{EntityTypeName, Policy};

use crate::error::PolicyError;
use crate::types::{Action, Resource};

/// Reserved policy annotation used for explicit local or global assignment.
pub const POLICY_STORE_ANNOTATION: &str = "treetop_store";

/// A stable application-defined policy-store identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyStoreId(Arc<str>);

impl PolicyStoreId {
    /// Construct a non-empty policy-store identifier.
    pub fn new(value: impl AsRef<str>) -> Result<Self, PolicyError> {
        let value = value.as_ref();
        if value.trim().is_empty() {
            return Err(PolicyError::PolicyStoreConfigError(
                "policy-store ID must not be empty".to_string(),
            ));
        }
        if value == "*" {
            return Err(PolicyError::PolicyStoreConfigError(
                "policy-store ID '*' is reserved for global policies".to_string(),
            ));
        }
        Ok(Self(value.into()))
    }

    /// Borrow the configured identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for PolicyStoreId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for PolicyStoreId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// One declared policy store and the Cedar namespace subtree it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStoreConfig {
    id: PolicyStoreId,
    namespace: Arc<str>,
}

impl PolicyStoreConfig {
    /// Declare a store whose requests and ordinary policies use `namespace`.
    ///
    /// The namespace is a Cedar-qualified name such as `ExampleCo::DNS`. The
    /// store also owns nested namespaces such as `ExampleCo::DNS::Admin`.
    pub fn new(id: impl AsRef<str>, namespace: impl AsRef<str>) -> Result<Self, PolicyError> {
        let id = PolicyStoreId::new(id)?;
        let namespace = namespace.as_ref();
        let _: EntityTypeName = namespace.parse().map_err(|error| {
            PolicyError::PolicyStoreConfigError(format!(
                "policy store '{id}' has invalid Cedar namespace '{namespace}': {error}"
            ))
        })?;
        Ok(Self {
            id,
            namespace: namespace.into(),
        })
    }

    /// Return the stable store identifier.
    pub fn id(&self) -> &PolicyStoreId {
        &self.id
    }

    /// Return the namespace subtree owned by this store.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[derive(Debug, Default)]
struct NamespaceRouter {
    root: NamespaceNode,
}

#[derive(Debug, Default)]
struct NamespaceNode {
    store_index: Option<usize>,
    children: HashMap<String, NamespaceNode>,
}

impl NamespaceRouter {
    fn insert(&mut self, namespace: &str, store_index: usize) -> Option<usize> {
        let mut node = &mut self.root;
        for component in namespace.split("::") {
            if let Some(existing_store) = node.store_index {
                return Some(existing_store);
            }
            node = node.children.entry(component.to_string()).or_default();
        }
        if let Some(existing_store) = node.store_index.or_else(|| node.first_store_index()) {
            return Some(existing_store);
        }
        node.store_index = Some(store_index);
        None
    }

    fn resolve<'a>(&self, components: impl IntoIterator<Item = &'a str>) -> Option<usize> {
        let mut node = &self.root;
        for component in components {
            node = node.children.get(component)?;
            if let Some(store_index) = node.store_index {
                return Some(store_index);
            }
        }
        None
    }

    fn resolve_qualified_name(&self, name: &str) -> Option<usize> {
        self.resolve(name.split("::"))
    }
}

impl NamespaceNode {
    fn first_store_index(&self) -> Option<usize> {
        self.store_index.or_else(|| {
            self.children
                .values()
                .find_map(NamespaceNode::first_store_index)
        })
    }
}

/// Validated configuration for namespace-partitioned policy stores.
///
/// Policies are assigned from the configured namespace references in their
/// scope constraints and conditions. Policies whose `@id` value is registered
/// as global, or which carry
/// `@treetop_store("*")`, are installed in every store. An otherwise unscoped
/// policy can use `@treetop_store("store-id")` for an explicit assignment.
/// Entity namespaces outside every configured store may be shared across
/// stores; they do not participate in assignment or request routing.
#[derive(Debug, Clone)]
pub struct PolicyStoreLayout {
    stores: Arc<[PolicyStoreConfig]>,
    global_policy_ids: Arc<HashSet<String>>,
    namespace_router: Arc<NamespaceRouter>,
}

impl PolicyStoreLayout {
    /// Create a layout containing non-overlapping store namespaces.
    pub fn new(stores: impl IntoIterator<Item = PolicyStoreConfig>) -> Result<Self, PolicyError> {
        let stores = stores.into_iter().collect::<Vec<_>>();
        if stores.is_empty() {
            return Err(PolicyError::PolicyStoreConfigError(
                "a policy-store layout must declare at least one store".to_string(),
            ));
        }

        let mut ids = HashSet::with_capacity(stores.len());
        for store in &stores {
            if !ids.insert(store.id().clone()) {
                return Err(PolicyError::PolicyStoreConfigError(format!(
                    "duplicate policy-store ID '{}'",
                    store.id()
                )));
            }
        }
        let mut namespace_router = NamespaceRouter::default();
        for (index, store) in stores.iter().enumerate() {
            if let Some(existing_index) = namespace_router.insert(store.namespace(), index) {
                return Err(PolicyError::PolicyStoreConfigError(format!(
                    "policy-store namespaces '{}' and '{}' overlap",
                    stores[existing_index].namespace(),
                    store.namespace()
                )));
            }
        }

        Ok(Self {
            stores: stores.into(),
            global_policy_ids: Arc::new(HashSet::new()),
            namespace_router: Arc::new(namespace_router),
        })
    }

    /// Register policy `@id` values that must be installed in every store.
    ///
    /// Every registered ID must exist in the loaded policy source. This catches
    /// stale or misspelled global-policy assignments during snapshot creation.
    pub fn with_global_policy_ids<I, S>(self, policy_ids: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut global_policy_ids = self.global_policy_ids.as_ref().clone();
        for policy_id in policy_ids {
            let policy_id = policy_id.as_ref();
            if policy_id.trim().is_empty() {
                return Err(PolicyError::PolicyStoreConfigError(
                    "global policy ID must not be empty".to_string(),
                ));
            }
            global_policy_ids.insert(policy_id.to_string());
        }
        Ok(Self {
            stores: self.stores,
            global_policy_ids: Arc::new(global_policy_ids),
            namespace_router: self.namespace_router,
        })
    }

    /// Return the configured stores in declaration order.
    pub fn stores(&self) -> &[PolicyStoreConfig] {
        &self.stores
    }

    pub(crate) fn global_policy_ids(&self) -> &HashSet<String> {
        &self.global_policy_ids
    }

    pub(crate) fn explicit_policy_store(
        &self,
        policy: &Policy,
    ) -> Result<Option<ExplicitPolicyStore>, PolicyError> {
        let Some(value) = policy.annotation(POLICY_STORE_ANNOTATION) else {
            return Ok(None);
        };
        if value == "*" {
            return Ok(Some(ExplicitPolicyStore::Global));
        }
        let store_index = self.store_index_by_id(value).ok_or_else(|| {
            PolicyError::PolicyStoreConfigError(format!(
                "policy '{}' names unknown policy store '{value}' in @{POLICY_STORE_ANNOTATION}",
                display_policy_id(policy)
            ))
        })?;
        Ok(Some(ExplicitPolicyStore::Store(store_index)))
    }

    pub(crate) fn policy_candidates(&self, policy: &Policy) -> Result<Vec<usize>, PolicyError> {
        let pst = policy.to_pst().map_err(|error| {
            PolicyError::PolicyStoreConfigError(format!(
                "policy '{}' cannot be inspected for policy-store assignment: {error}",
                display_policy_id(policy)
            ))
        })?;
        let body = pst.body();
        let mut references = Vec::new();

        match &body.principal {
            PrincipalConstraint::Any => {}
            PrincipalConstraint::Eq(value) | PrincipalConstraint::In(value) => {
                collect_entity_or_slot(value, &mut references);
            }
            PrincipalConstraint::Is(entity_type) => {
                references.push(entity_type.to_string());
            }
            PrincipalConstraint::IsIn(entity_type, value) => {
                references.push(entity_type.to_string());
                collect_entity_or_slot(value, &mut references);
            }
        }
        let mut candidates = BTreeSet::new();
        match &body.action {
            ActionConstraint::Any => {}
            ActionConstraint::Eq(uid) => {
                references.push(uid.ty.to_string());
            }
            ActionConstraint::In(uids) => {
                for uid in uids {
                    references.push(uid.ty.to_string());
                }
            }
        }
        match &body.resource {
            ResourceConstraint::Any => {}
            ResourceConstraint::Eq(value) | ResourceConstraint::In(value) => {
                collect_entity_or_slot(value, &mut references);
            }
            ResourceConstraint::Is(entity_type) => {
                references.push(entity_type.to_string());
            }
            ResourceConstraint::IsIn(entity_type, value) => {
                references.push(entity_type.to_string());
                collect_entity_or_slot(value, &mut references);
            }
        }
        for clause in body.clauses() {
            let expression = match clause {
                Clause::When(expression) | Clause::Unless(expression) => expression,
            };
            collect_expr_references(expression, &mut references);
        }
        for reference in references {
            self.insert_name_candidate(&reference, &mut candidates);
        }

        if candidates.len() > 1 {
            let names = candidates
                .iter()
                .map(|index| self.stores[*index].id().as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(PolicyError::PolicyStoreConfigError(format!(
                "policy '{}' spans multiple policy stores ({names}); split it or mark it global",
                display_policy_id(policy)
            )));
        }
        Ok(candidates.into_iter().collect())
    }

    pub(crate) fn resolve_request(
        &self,
        action: &Action,
        resource: &Resource,
    ) -> Result<usize, PolicyError> {
        let action_store = self
            .namespace_router
            .resolve(action.namespace().iter().map(String::as_str));
        let resource_store = self
            .namespace_router
            .resolve_qualified_name(resource.kind());

        match (action_store, resource_store) {
            (Some(action_store), Some(resource_store)) if action_store != resource_store => {
                Err(PolicyError::PolicyStoreRoutingError(format!(
                    "request action namespace '{}' and resource type '{}' resolve to different policy stores ({}, {})",
                    display_action_namespace(action),
                    resource.kind(),
                    self.stores[action_store].id(),
                    self.stores[resource_store].id()
                )))
            }
            (Some(index), _) | (_, Some(index)) => Ok(index),
            (None, None) => Err(PolicyError::PolicyStoreRoutingError(format!(
                "request action namespace '{}' and resource type '{}' do not belong to a configured policy store",
                display_action_namespace(action),
                resource.kind()
            ))),
        }
    }

    fn store_index_by_id(&self, id: &str) -> Option<usize> {
        self.stores
            .iter()
            .position(|store| store.id().as_str() == id)
    }

    fn insert_name_candidate(&self, name: &str, candidates: &mut BTreeSet<usize>) {
        if let Some(index) = self.namespace_router.resolve_qualified_name(name) {
            candidates.insert(index);
        }
    }
}

fn display_action_namespace(action: &Action) -> String {
    if action.namespace().is_empty() {
        "<none>".to_string()
    } else {
        action.namespace().join("::")
    }
}

fn collect_entity_or_slot(value: &EntityOrSlot, references: &mut Vec<String>) {
    if let EntityOrSlot::Entity(uid) = value {
        references.push(uid.ty.to_string());
    }
}

fn collect_expr_references(expression: &Expr, references: &mut Vec<String>) {
    match expression {
        Expr::Literal(Literal::EntityUID(uid)) => references.push(uid.ty.to_string()),
        Expr::UnaryOp { expr, .. }
        | Expr::GetAttr { expr, .. }
        | Expr::HasAttr { expr, .. }
        | Expr::Like { expr, .. } => collect_expr_references(expr, references),
        Expr::BinaryOp { left, right, .. } => {
            collect_expr_references(left, references);
            collect_expr_references(right, references);
        }
        Expr::Is {
            expr,
            entity_type,
            in_expr,
        } => {
            references.push(entity_type.to_string());
            collect_expr_references(expr, references);
            if let Some(in_expr) = in_expr {
                collect_expr_references(in_expr, references);
            }
        }
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_expr_references(cond, references);
            collect_expr_references(then_expr, references);
            collect_expr_references(else_expr, references);
        }
        Expr::Set(expressions) => {
            for expression in expressions {
                collect_expr_references(expression, references);
            }
        }
        Expr::Record(expressions) => {
            for expression in expressions.values() {
                collect_expr_references(expression, references);
            }
        }
        _ => {}
    }
}

pub(crate) enum ExplicitPolicyStore {
    Global,
    Store(usize),
}

pub(crate) fn display_policy_id(policy: &Policy) -> &str {
    policy
        .annotation("id")
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| policy.id().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, Resource};

    fn layout() -> PolicyStoreLayout {
        PolicyStoreLayout::new([
            PolicyStoreConfig::new("dns", "ExampleCo::DNS").unwrap(),
            PolicyStoreConfig::new("www", "ExampleCo::WWW").unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn rejects_overlapping_namespaces() {
        let result = PolicyStoreLayout::new([
            PolicyStoreConfig::new("parent", "ExampleCo").unwrap(),
            PolicyStoreConfig::new("child", "ExampleCo::DNS").unwrap(),
        ]);
        assert!(matches!(
            result,
            Err(PolicyError::PolicyStoreConfigError(_))
        ));

        let reverse = PolicyStoreLayout::new([
            PolicyStoreConfig::new("child", "ExampleCo::DNS").unwrap(),
            PolicyStoreConfig::new("parent", "ExampleCo").unwrap(),
        ]);
        assert!(matches!(
            reverse,
            Err(PolicyError::PolicyStoreConfigError(_))
        ));
    }

    #[test]
    fn rejects_invalid_layout_entries() {
        assert!(matches!(
            PolicyStoreConfig::new("dns", "not a namespace"),
            Err(PolicyError::PolicyStoreConfigError(_))
        ));
        assert!(matches!(
            PolicyStoreLayout::new([
                PolicyStoreConfig::new("duplicate", "ExampleCo::DNS").unwrap(),
                PolicyStoreConfig::new("duplicate", "ExampleCo::WWW").unwrap(),
            ]),
            Err(PolicyError::PolicyStoreConfigError(_))
        ));
    }

    #[test]
    fn routes_namespaced_requests() {
        let layout = layout();
        let store = layout
            .resolve_request(
                &Action::new("read", Some(vec!["ExampleCo".into(), "DNS".into()])).unwrap(),
                &Resource::new("ExampleCo::DNS::Host", "host-1").unwrap(),
            )
            .unwrap();
        assert_eq!(layout.stores()[store].id().as_str(), "dns");
    }

    #[test]
    fn rejects_cross_store_requests() {
        let result = layout().resolve_request(
            &Action::new("read", Some(vec!["ExampleCo".into(), "DNS".into()])).unwrap(),
            &Resource::new("ExampleCo::WWW::Page", "page-1").unwrap(),
        );
        assert!(matches!(
            result,
            Err(PolicyError::PolicyStoreRoutingError(_))
        ));
    }

    #[test]
    fn namespace_matching_is_segment_aware() {
        let result = layout().resolve_request(
            &Action::new("read", Some(vec!["ExampleCo".into(), "DNSAdmin".into()])).unwrap(),
            &Resource::new("ExampleCo::DNSAdmin::Host", "host-1").unwrap(),
        );
        assert!(matches!(
            result,
            Err(PolicyError::PolicyStoreRoutingError(_))
        ));
    }
}
