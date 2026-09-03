use cedar_policy::{
    Authorizer, Entities, Entity, Policy, PolicyId, PolicySet, Request as CedarRequest, Schema,
};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use std::vec;

use crate::labels::LabelRegistry;
use crate::policy_match::{
    action_match_reason, matches_effect, principal_match_reason, resource_match_reason,
};
use crate::policy_store::{
    ExplicitPolicyStore, PolicyStoreId, PolicyStoreLayout, display_policy_id,
};
use crate::query::{ActionQuery, PrincipalQuery, ResourceQuery};
use crate::timers::PhaseTimer;
use crate::traits::CedarAtom;
use crate::types::{
    Decision, DecisionDiagnostics, PermitPolicies, PermitPolicy, PolicyCandidates,
    PolicyEffectFilter, PolicyMatchReason, PolicyVersion, Request, RequestContext, Resource,
};
use crate::{Groups, Principal};
use crate::{error::PolicyError, loader};
use arc_swap::ArcSwap;

use sha2::{Digest, Sha256};
use tracing::debug;
#[cfg(feature = "observability")]
use tracing::info_span;

#[cfg(feature = "observability")]
use crate::metrics::{
    EvaluationObservation, EvaluationPhases, MatchedPolicySource, get_sink, metrics_enabled,
    record_evaluation_observation, record_reload,
};

/// Static cached Authorizer instance (stateless, reusable across evaluations).
fn get_authorizer() -> &'static Authorizer {
    static AUTHORIZER: OnceLock<Authorizer> = OnceLock::new();
    AUTHORIZER.get_or_init(Authorizer::new)
}

/// Aggregates timing information for all evaluation phases.
#[derive(Debug)]
struct EvalTimers {
    /// Total elapsed time from start of evaluation
    total_start: Option<Instant>,
    /// Whether individual phase timers should sample the clock.
    measure_enabled: bool,
    /// Whether debug tracing was enabled when evaluation started.
    debug_enabled: bool,
    /// Time spent applying labels
    labels: Duration,
    /// Time spent constructing Cedar request
    construct_req: Duration,
    /// Time spent building Cedar entities
    entities: Duration,
    /// Time spent resolving groups
    groups: Duration,
    /// Time spent performing authorization
    authz: Duration,
}

impl EvalTimers {
    fn start(measure_enabled: bool, debug_enabled: bool) -> Self {
        Self {
            total_start: measure_enabled.then(Instant::now),
            measure_enabled,
            debug_enabled,
            labels: Duration::ZERO,
            construct_req: Duration::ZERO,
            entities: Duration::ZERO,
            groups: Duration::ZERO,
            authz: Duration::ZERO,
        }
    }

    fn total_elapsed(&self) -> Duration {
        self.total_start
            .map_or(Duration::ZERO, |start| start.elapsed())
    }
}

/// Result of preparing a request for authorization: Cedar request, entities, snapshot, and phase timings.
struct PreparedRequest {
    cedar_req: CedarRequest,
    entities: Entities,
    timers: EvalTimers,
    #[cfg(feature = "observability")]
    sink: crate::metrics::SinkGuard,
    #[cfg(feature = "observability")]
    metrics_enabled: bool,
}

/// Compiled authorization policy sets for a monolithic or partitioned engine.
#[derive(Debug)]
enum PolicySets {
    Monolithic(Box<PolicySet>),
    Scoped {
        layout: PolicyStoreLayout,
        stores: Vec<PolicySet>,
    },
}

enum PolicySetIter<'a> {
    Monolithic(std::iter::Once<&'a PolicySet>),
    Scoped(std::slice::Iter<'a, PolicySet>),
}

impl<'a> Iterator for PolicySetIter<'a> {
    type Item = &'a PolicySet;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Monolithic(iter) => iter.next(),
            Self::Scoped(iter) => iter.next(),
        }
    }
}

impl PolicySets {
    fn layout(&self) -> Option<&PolicyStoreLayout> {
        match self {
            Self::Monolithic(_) => None,
            Self::Scoped { layout, .. } => Some(layout),
        }
    }

    fn resolve(&self, request: &Request) -> Result<&PolicySet, PolicyError> {
        match self {
            Self::Monolithic(set) => Ok(set),
            Self::Scoped { layout, stores } => {
                let index = layout.resolve_request(&request.action, &request.resource)?;
                stores.get(index).ok_or_else(|| {
                    PolicyError::PolicyStoreRoutingError(format!(
                        "configured policy-store index {index} is outside layout length {}",
                        layout.stores().len()
                    ))
                })
            }
        }
    }

    fn iter(&self) -> PolicySetIter<'_> {
        match self {
            Self::Monolithic(set) => PolicySetIter::Monolithic(std::iter::once(set)),
            Self::Scoped { stores, .. } => PolicySetIter::Scoped(stores.iter()),
        }
    }

    fn store_ids(&self) -> Option<Vec<PolicyStoreId>> {
        let Self::Scoped { layout, .. } = self else {
            return None;
        };
        Some(
            layout
                .stores()
                .iter()
                .map(|store| store.id().clone())
                .collect(),
        )
    }
}

/// Immutable snapshot of compiled policy sets, along with metadata.
#[derive(Debug)]
struct PolicySnapshot {
    sets: PolicySets,
    revision: PolicyRevision,
    permit_policies: HashMap<PolicyId, PermitPolicy>,
    forbid_policy_ids: HashMap<PolicyId, String>,
    schema: Option<Arc<Schema>>,
}

/// Policy-only metadata that cannot be mistaken for a published engine version.
#[derive(Debug)]
struct PolicyRevision {
    hash: Arc<str>,
    loaded_at: Arc<str>,
}

/// Convenience alias for a shared policy snapshot.
type Snapshot = Arc<PolicySnapshot>;

/// One coherent, immutable generation of all authorization behavior.
struct EngineState {
    policy: Snapshot,
    label_registry: Option<LabelRegistry>,
    generation: u64,
}

type State = Arc<EngineState>;

impl EngineState {
    fn version(&self) -> PolicyVersion {
        PolicyVersion {
            hash: Arc::clone(&self.policy.revision.hash),
            loaded_at: Arc::clone(&self.policy.revision.loaded_at),
            label_set: self
                .label_registry
                .as_ref()
                .and_then(|registry| registry.version().cloned()),
            generation: self.generation,
        }
    }
}

impl PolicySnapshot {
    fn from_policy_text(policy_text: &str) -> Result<Self, PolicyError> {
        Self::from_policy_text_with_schema_and_stores(policy_text, None, None)
    }

    fn from_policy_text_with_schema(
        policy_text: &str,
        schema: Option<Arc<Schema>>,
    ) -> Result<Self, PolicyError> {
        Self::from_policy_text_with_schema_and_stores(policy_text, schema, None)
    }

    fn from_policy_text_with_schema_and_stores(
        policy_text: &str,
        schema: Option<Arc<Schema>>,
        layout: Option<PolicyStoreLayout>,
    ) -> Result<Self, PolicyError> {
        let set = match schema.as_deref() {
            Some(schema) => loader::compile_policy_with_schema(policy_text, schema)?,
            None => loader::compile_policy(policy_text)?,
        };
        let permit_policies = loader::precompute_permit_policies(&set)?;
        let forbid_policy_ids = loader::precompute_forbid_policy_ids(&set);
        let sets = match layout {
            Some(layout) => partition_policy_set(&set, layout)?,
            None => PolicySets::Monolithic(Box::new(set)),
        };

        let mut hasher = Sha256::new();
        hasher.update(policy_text.as_bytes());
        let digest = hasher.finalize();
        let mut hash = String::with_capacity(digest.len() * 2);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            hash.push(char::from(HEX[usize::from(byte >> 4)]));
            hash.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }

        Ok(PolicySnapshot {
            sets,
            revision: PolicyRevision {
                hash: hash.into(),
                loaded_at: humantime::format_rfc3339(SystemTime::now())
                    .to_string()
                    .into(),
            },
            permit_policies,
            forbid_policy_ids,
            schema,
        })
    }

    fn schema(&self) -> Option<&Schema> {
        self.schema.as_deref()
    }
}

fn partition_policy_set(
    source: &PolicySet,
    layout: PolicyStoreLayout,
) -> Result<PolicySets, PolicyError> {
    let mut stores = (0..layout.stores().len())
        .map(|_| PolicySet::new())
        .collect::<Vec<_>>();
    let mut found_global_policy_ids = HashSet::new();

    for policy in source.policies() {
        let display_id = display_policy_id(policy);
        let registered_global = policy
            .annotation("id")
            .is_some_and(|id| layout.global_policy_ids().contains(id));
        if registered_global {
            found_global_policy_ids.insert(display_id.to_string());
        }

        let explicit = layout.explicit_policy_store(policy)?;
        if registered_global
            && let Some(ExplicitPolicyStore::Store(store_index)) = explicit.as_ref()
        {
            return Err(PolicyError::PolicyStoreConfigError(format!(
                "policy '{display_id}' is registered as global but @{POLICY_STORE_ANNOTATION} assigns it to store '{}'",
                layout.stores()[*store_index].id(),
                POLICY_STORE_ANNOTATION = crate::POLICY_STORE_ANNOTATION
            )));
        }
        let target_indexes = if registered_global
            || matches!(explicit, Some(ExplicitPolicyStore::Global))
        {
            (0..layout.stores().len()).collect::<Vec<_>>()
        } else {
            let candidates = layout.policy_candidates(policy)?;
            match explicit {
                Some(ExplicitPolicyStore::Store(store_index)) => {
                    if candidates
                        .first()
                        .is_some_and(|candidate| *candidate != store_index)
                    {
                        return Err(PolicyError::PolicyStoreConfigError(format!(
                            "policy '{display_id}' is assigned to store '{}' but its scope identifies store '{}'",
                            layout.stores()[store_index].id(),
                            layout.stores()[candidates[0]].id()
                        )));
                    }
                    vec![store_index]
                }
                None => match candidates.as_slice() {
                    [store_index] => vec![*store_index],
                    [] => {
                        return Err(PolicyError::PolicyStoreConfigError(format!(
                            "policy '{display_id}' cannot be assigned from its configured namespace references; add @{POLICY_STORE_ANNOTATION}(\"store-id\") or mark it global",
                            POLICY_STORE_ANNOTATION = crate::POLICY_STORE_ANNOTATION
                        )));
                    }
                    _ => {
                        return Err(PolicyError::PolicyStoreConfigError(format!(
                            "policy '{display_id}' has an ambiguous policy-store assignment"
                        )));
                    }
                },
                Some(ExplicitPolicyStore::Global) => {
                    return Err(PolicyError::PolicyStoreConfigError(format!(
                        "policy '{display_id}' has an inconsistent global assignment"
                    )));
                }
            }
        };

        for target_index in target_indexes {
            let target_id = layout.stores()[target_index].id();
            let target = stores.get_mut(target_index).ok_or_else(|| {
                PolicyError::PolicyStoreConfigError(format!(
                    "policy '{display_id}' resolved to missing store '{target_id}'"
                ))
            })?;
            target.add(policy.clone()).map_err(|error| {
                PolicyError::PolicyStoreConfigError(format!(
                    "failed to add policy '{display_id}' to store '{target_id}': {error}"
                ))
            })?;
        }
    }

    let mut missing_global_policy_ids = layout
        .global_policy_ids()
        .difference(&found_global_policy_ids)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_global_policy_ids.is_empty() {
        missing_global_policy_ids.sort();
        return Err(PolicyError::PolicyStoreConfigError(format!(
            "global policy IDs were not found in the policy source: {}",
            missing_global_policy_ids.join(", ")
        )));
    }

    Ok(PolicySets::Scoped { layout, stores })
}

/// Extract all permit policies from the Cedar authorization result.
#[inline]
fn extract_permit_policies(
    snapshot: &PolicySnapshot,
    result: &cedar_policy::Response,
) -> PermitPolicies {
    if result.decision() != cedar_policy::Decision::Allow {
        return PermitPolicies::empty();
    }

    result
        .diagnostics()
        .reason()
        .filter_map(|reason| snapshot.permit_policies.get(reason))
        .cloned()
        .collect()
}

/// Extract matched forbid policy IDs from a Cedar authorization result.
#[inline]
fn extract_forbid_policy_ids(
    snapshot: &PolicySnapshot,
    result: &cedar_policy::Response,
) -> Vec<String> {
    if result.decision() != cedar_policy::Decision::Deny {
        return Vec::new();
    }

    let mut ids: Vec<String> = result
        .diagnostics()
        .reason()
        .filter_map(|reason| snapshot.forbid_policy_ids.get(reason).cloned())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Iterate over groups from a request principal.
#[inline]
fn request_groups(request: &Request) -> Option<&Groups> {
    match &request.principal {
        Principal::User(user) => Some(user.groups()),
        Principal::Group(_) => None,
    }
}

/// Apply label augmentations to a resource.
#[inline]
fn apply_labels(
    registry: &LabelRegistry,
    resource: &crate::types::Resource,
    timers: &mut EvalTimers,
) -> Option<crate::types::Resource> {
    let measure_enabled = timers.measure_enabled;
    let _timer = PhaseTimer::new_if(&mut timers.labels, measure_enabled);
    #[cfg(feature = "observability")]
    let _label_span = info_span!("apply_labels").entered();
    registry.apply_to_clone_if_applicable(resource)
}

/// Build the Cedar request context from the optional typed context.
#[inline]
fn build_effective_context(
    request_context: Option<&RequestContext>,
) -> Result<cedar_policy::Context, PolicyError> {
    match request_context {
        Some(context) if !context.is_empty() => context.to_cedar_context(),
        _ => Ok(cedar_policy::Context::empty()),
    }
}

/// Build a Cedar request from the authorization request and resource.
/// UIDs should be pre-converted to avoid redundant conversions.
#[inline]
fn build_cedar_req(
    principal_uid: cedar_policy::EntityUid,
    action_uid: cedar_policy::EntityUid,
    resource_uid: cedar_policy::EntityUid,
    context: cedar_policy::Context,
    schema: Option<&Schema>,
    timers: &mut EvalTimers,
) -> Result<CedarRequest, PolicyError> {
    let measure_enabled = timers.measure_enabled;
    let _timer = PhaseTimer::new_if(&mut timers.construct_req, measure_enabled);
    #[cfg(feature = "observability")]
    let _req_span = info_span!("construct_cedar_req").entered();

    Ok(CedarRequest::new(
        principal_uid,
        action_uid,
        resource_uid,
        context,
        schema,
    )?)
}

/// Build Cedar entities for the principal, resource, and groups.
/// UIDs should be pre-converted to avoid redundant conversions.
#[inline]
fn build_entities(
    principal_uid: cedar_policy::EntityUid,
    resource_uid: cedar_policy::EntityUid,
    resource: &crate::types::Resource,
    groups: Option<&Groups>,
    schema: Option<&Schema>,
    timers: &mut EvalTimers,
) -> Result<Entities, PolicyError> {
    let group_uids = {
        let measure_enabled = timers.measure_enabled;
        let _timer = PhaseTimer::new_if(&mut timers.groups, measure_enabled);
        #[cfg(feature = "observability")]
        let _groups_span = info_span!("resolve_groups").entered();

        let mut group_uids = HashSet::with_capacity(groups.map_or(0, Groups::len));
        if let Some(groups) = groups {
            for group in groups {
                group_uids.insert(group.cedar_entity_uid().clone());
            }
        }
        group_uids
    };

    // Group resolution is deliberately measured outside this phase so phase
    // totals are non-overlapping.
    let entities = {
        let measure_enabled = timers.measure_enabled;
        let _timer = PhaseTimer::new_if(&mut timers.entities, measure_enabled);
        #[cfg(feature = "observability")]
        let _entity_span = info_span!("construct_entities").entered();

        // Construct resource entity
        let resource_attrs = resource.cedar_attr();
        let resource_entity =
            cedar_policy::Entity::new(resource_uid, resource_attrs, Default::default())?;

        // Construct group entities before moving the parent set into the
        // principal. This avoids cloning the complete HashSet allocation.
        let mut all_entities = Vec::with_capacity(group_uids.len() + 2);
        all_entities.extend(group_uids.iter().cloned().map(Entity::with_uid));

        // Construct principal entity with groups as parents, then batch all
        // entities into a single call. Entity order has no Cedar semantics.
        let principal_entity = Entity::new(principal_uid, HashMap::new(), group_uids)?;
        all_entities.push(principal_entity);
        all_entities.push(resource_entity);

        // Combine all entities in a single call to reduce overhead
        Entities::empty().add_entities(all_entities, schema)?
    };

    if timers.debug_enabled {
        debug!(
            event = "Request",
            phase = "Entities",
            time = timers.entities.as_micros(),
            entity_count = entities.iter().count()
        );
    }

    Ok(entities)
}

/// The main engine handle. Thread-safe and cheaply cloneable.
///
/// Cloning is cheap (just increments Arc refcounts), but for multithreaded
/// applications, wrapping in `Arc<PolicyEngine>` and using `Arc::clone()`
/// is more idiomatic and makes ownership clearer.
///
/// For single-threaded use or when passing the engine to a single thread,
/// you can simply clone it directly.
mod validation_mode_private {
    pub trait Sealed {}
}

/// Type-level policy for Cedar schema enforcement.
pub trait ValidationMode: validation_mode_private::Sealed {}

/// Marker for an engine that does not use a Cedar schema.
///
/// Schema-replacing reloads are intentionally unavailable in this mode:
///
/// ```compile_fail
/// use treetop_core::{PolicyEngine, Schema};
///
/// let engine = PolicyEngine::new_from_str("permit(principal, action, resource);").unwrap();
/// let schema: Schema = "entity User;".parse().unwrap();
/// engine.reload_from_str_with_schema("permit(principal, action, resource);", schema);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SchemaFree;

/// Marker for an engine that always validates with a Cedar schema.
#[derive(Debug, Clone, Copy)]
pub struct SchemaEnforcing;

impl validation_mode_private::Sealed for SchemaFree {}
impl validation_mode_private::Sealed for SchemaEnforcing {}
impl ValidationMode for SchemaFree {}
impl ValidationMode for SchemaEnforcing {}

#[derive(Clone)]
pub struct PolicyEngine<M: ValidationMode = SchemaFree> {
    /// Shared pointer to the atomically replaceable authorization state.
    inner: Arc<ArcSwap<EngineState>>,
    mode: PhantomData<fn() -> M>,
}

/// A frozen, cheaply cloneable authorization-state generation.
///
/// Every evaluation through a session uses the same policies, schema, policy
/// stores, labelers, and version. Create a new session to observe a successful
/// reload.
#[derive(Clone)]
pub struct EvaluationSession<M: ValidationMode = SchemaFree> {
    state: State,
    mode: PhantomData<fn() -> M>,
}

impl<M: ValidationMode> From<PolicyEngine<M>> for PolicyVersion {
    fn from(engine: PolicyEngine<M>) -> Self {
        engine.current_version()
    }
}

impl<M: ValidationMode> From<&PolicyEngine<M>> for PolicyVersion {
    fn from(engine: &PolicyEngine<M>) -> Self {
        engine.current_version()
    }
}

impl<M: ValidationMode> PolicyEngine<M> {
    fn from_snapshot(snapshot: PolicySnapshot) -> Self {
        let state = EngineState {
            policy: Arc::new(snapshot),
            label_registry: None,
            generation: 1,
        };
        Self {
            inner: Arc::new(ArcSwap::from(Arc::new(state))),
            mode: PhantomData,
        }
    }
}

impl PolicyEngine<SchemaFree> {
    pub fn new_from_str(policy_text: &str) -> Result<Self, PolicyError> {
        Ok(Self::from_snapshot(PolicySnapshot::from_policy_text(
            policy_text,
        )?))
    }

    /// Create an engine that partitions policies into namespace-owned stores.
    ///
    /// Existing monolithic constructors remain unchanged. Store assignment is
    /// validated before the engine is returned, and each request must resolve
    /// to exactly one declared store or evaluation fails closed.
    pub fn new_from_str_with_policy_stores(
        policy_text: &str,
        layout: PolicyStoreLayout,
    ) -> Result<Self, PolicyError> {
        Ok(Self::from_snapshot(
            PolicySnapshot::from_policy_text_with_schema_and_stores(
                policy_text,
                None,
                Some(layout),
            )?,
        ))
    }

    /// Create a new policy engine with schema-based policy and request validation.
    pub fn new_from_str_with_schema(
        policy_text: &str,
        schema: Schema,
    ) -> Result<PolicyEngine<SchemaEnforcing>, PolicyError> {
        Ok(PolicyEngine::<SchemaEnforcing>::from_snapshot(
            PolicySnapshot::from_policy_text_with_schema(policy_text, Some(Arc::new(schema)))?,
        ))
    }

    /// Create a namespace-partitioned engine with schema validation.
    pub fn new_from_str_with_schema_and_policy_stores(
        policy_text: &str,
        schema: Schema,
        layout: PolicyStoreLayout,
    ) -> Result<PolicyEngine<SchemaEnforcing>, PolicyError> {
        Ok(PolicyEngine::<SchemaEnforcing>::from_snapshot(
            PolicySnapshot::from_policy_text_with_schema_and_stores(
                policy_text,
                Some(Arc::new(schema)),
                Some(layout),
            )?,
        ))
    }

    /// Create a new policy engine from policy text and Cedar schema text.
    pub fn new_from_str_with_cedarschema(
        policy_text: &str,
        schema_text: &str,
    ) -> Result<PolicyEngine<SchemaEnforcing>, PolicyError> {
        let schema: Schema = schema_text
            .parse()
            .map_err(|e| PolicyError::ParseError(format!("failed to parse Cedar schema: {e}")))?;
        Self::new_from_str_with_schema(policy_text, schema)
    }

    /// Create a namespace-partitioned engine from policy and Cedar schema text.
    pub fn new_from_str_with_cedarschema_and_policy_stores(
        policy_text: &str,
        schema_text: &str,
        layout: PolicyStoreLayout,
    ) -> Result<PolicyEngine<SchemaEnforcing>, PolicyError> {
        let schema: Schema = schema_text
            .parse()
            .map_err(|e| PolicyError::ParseError(format!("failed to parse Cedar schema: {e}")))?;
        Self::new_from_str_with_schema_and_policy_stores(policy_text, schema, layout)
    }
}

impl<M: ValidationMode> PolicyEngine<M> {
    /// Create a new policy engine with a label registry.
    ///
    /// This is a convenience method that combines `new_from_str` and `with_label_registry`.
    pub fn with_label_registry(self, registry: LabelRegistry) -> Self {
        self.set_label_registry(registry);
        self
    }

    /// Set or replace the label registry for this engine.
    ///
    /// This allows updating the labelers after the engine has been created.
    pub fn set_label_registry(&self, registry: LabelRegistry) {
        self.inner.rcu(|current| {
            Arc::new(EngineState {
                policy: Arc::clone(&current.policy),
                label_registry: Some(registry.clone()),
                generation: current.generation.saturating_add(1),
            })
        });
    }

    /// Clone the current immutable label registry, if one is configured.
    pub fn label_registry(&self) -> Option<LabelRegistry> {
        self.current_state().label_registry.clone()
    }

    pub fn reload_from_str(&self, policy_text: &str) -> Result<(), PolicyError> {
        let had_schema = 'compile: loop {
            let mut expected = self.current_state();
            let had_schema = expected.policy.schema.is_some();
            let schema = expected.policy.schema.clone();
            let layout = expected.policy.sets.layout().cloned();
            let new_snapshot: Snapshot =
                Arc::new(PolicySnapshot::from_policy_text_with_schema_and_stores(
                    policy_text,
                    schema,
                    layout,
                )?);

            loop {
                match self.install_policy_if_current(&expected, Arc::clone(&new_snapshot)) {
                    Ok(()) => break 'compile had_schema,
                    Err(latest) if Arc::ptr_eq(&expected.policy, &latest.policy) => {
                        // A label-only update won the race. The compiled policy
                        // still uses the current schema and store layout, so
                        // retry publication while preserving the newer labels.
                        expected = latest;
                    }
                    Err(_) => {
                        // Another policy/schema generation won the race. Compile
                        // again against that generation so a normal reload can
                        // never restore a superseded schema.
                        continue 'compile;
                    }
                }
            }
        };
        debug!(
            event = "PolicyReload",
            schema_enabled = had_schema,
            schema_reloaded = false
        );
        // Track reloads for metrics (no-op if feature disabled or no sink configured)
        #[cfg(feature = "observability")]
        record_reload();
        Ok(())
    }

    /// Get the current immutable snapshot.
    fn current_state(&self) -> State {
        self.inner.load_full()
    }

    fn current_snapshot(&self) -> Snapshot {
        Arc::clone(&self.current_state().policy)
    }

    fn install_policy(&self, policy: Snapshot) {
        self.inner.rcu(|current| {
            Arc::new(EngineState {
                policy: Arc::clone(&policy),
                label_registry: current.label_registry.clone(),
                generation: current.generation.saturating_add(1),
            })
        });
    }

    /// Publish a compiled policy only if its source state is still current.
    fn install_policy_if_current(&self, expected: &State, policy: Snapshot) -> Result<(), State> {
        let replacement = Arc::new(EngineState {
            policy,
            label_registry: expected.label_registry.clone(),
            generation: expected.generation.saturating_add(1),
        });
        let previous = self.inner.compare_and_swap(expected, replacement);
        if Arc::ptr_eq(expected, &previous) {
            Ok(())
        } else {
            Err(Arc::clone(&previous))
        }
    }

    /// Get the complete current authorization-state version.
    ///
    /// The policy hash, policy load time, label-set version, and engine
    /// generation all come from the same atomic state load.
    pub fn current_version(&self) -> PolicyVersion {
        self.current_state().version()
    }

    /// Capture one coherent authorization-state generation for batch work.
    pub fn session(&self) -> EvaluationSession<M> {
        EvaluationSession {
            state: self.current_state(),
            mode: PhantomData,
        }
    }

    /// Return configured policy-store IDs, or `None` for a monolithic engine.
    pub fn policy_store_ids(&self) -> Option<Vec<PolicyStoreId>> {
        self.current_state().policy.sets.store_ids()
    }

    /// Prepare a request for authorization: accumulate labels, build Cedar entities, resolve groups.
    ///
    /// This separates request preparation from the authorization decision, making both
    /// more testable and the main hot path more readable.
    fn prepare(
        state: &EngineState,
        request: &Request,
        request_context: Option<&RequestContext>,
    ) -> Result<PreparedRequest, PolicyError> {
        let schema = state.policy.schema();
        #[cfg(feature = "observability")]
        let sink = get_sink();
        #[cfg(feature = "observability")]
        let metrics_enabled = metrics_enabled(&sink);
        #[cfg(not(feature = "observability"))]
        let metrics_enabled = false;
        let debug_enabled = tracing::enabled!(tracing::Level::DEBUG);
        let mut timers = EvalTimers::start(debug_enabled || metrics_enabled, debug_enabled);

        let groups = request_groups(request);

        if timers.debug_enabled {
            debug!(
                event = "Request",
                phase = "Evaluation",
                group_count = groups.map_or(0, Groups::len)
            );
        }

        // Convert each UID once after trusted label derivation is complete.
        let principal_uid = request.principal.cedar_entity_uid().clone();
        let action_uid = request.action.cedar_entity_uid().clone();

        let labelled_resource = if let Some(registry) = &state.label_registry {
            let labelled_resource = apply_labels(registry, &request.resource, &mut timers);
            if timers.debug_enabled {
                let resource_for_metrics = labelled_resource.as_ref().unwrap_or(&request.resource);
                debug!(
                    event = "Request",
                    phase = "LabelsApplied",
                    time = timers.labels.as_micros(),
                    attribute_count = resource_for_metrics.attributes().len()
                );
            }
            labelled_resource
        } else {
            if timers.debug_enabled {
                debug!(
                    event = "Request",
                    phase = "LabelsApplied",
                    time = timers.labels.as_micros()
                );
            }
            None
        };
        let resource_for_entities = labelled_resource.as_ref().unwrap_or(&request.resource);
        let resource_uid = resource_for_entities.cedar_entity_uid().clone();
        let context = build_effective_context(request_context)?;

        if timers.debug_enabled {
            debug!(
                event = "Request",
                phase = "Parsed",
                group_count = groups.map_or(0, Groups::len),
                attribute_count = resource_for_entities.attributes().len(),
                request_context_attribute_count = request_context.map_or(0, RequestContext::len)
            );
        }

        // The request and entity graph both own the same principal and resource
        // IDs. Clone each UID once, then move both copies into Cedar instead of
        // cloning again inside both builders.
        let principal_uid_for_entities = principal_uid.clone();
        let resource_uid_for_entities = resource_uid.clone();

        // Build Cedar request with pre-converted UIDs
        let cedar_req = build_cedar_req(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            schema,
            &mut timers,
        )?;

        // Build entities with pre-converted UIDs and potentially-modified resource
        let entities = build_entities(
            principal_uid_for_entities,
            resource_uid_for_entities,
            resource_for_entities,
            groups,
            schema,
            &mut timers,
        )?;

        if timers.debug_enabled {
            debug!(
                event = "Request",
                phase = "GroupsResolved",
                time = timers.groups.as_micros(),
            );
        }

        Ok(PreparedRequest {
            cedar_req,
            entities,
            timers,
            #[cfg(feature = "observability")]
            sink,
            #[cfg(feature = "observability")]
            metrics_enabled,
        })
    }

    /// Evaluate a policy request against the currently loaded policy set.
    ///
    /// This method performs a complete Cedar policy evaluation:
    /// 1. Applies any registered labelers to augment resource attributes
    /// 2. Constructs Cedar entities for the principal (including groups), action, and resource
    /// 3. Executes the Cedar authorization decision
    /// 4. Returns either `Allow` (with the matching policy) or `Deny`, both including version metadata
    ///
    /// # Arguments
    ///
    /// * `request` - The authorization request containing the principal, action, and resource
    ///
    /// # Returns
    ///
    /// * `Ok(Decision::Allow)` - If at least one permit policy matches and no forbid policies match
    /// * `Ok(Decision::Deny)` - If no permit policies match or if a forbid policy matches
    /// * `Err(PolicyError)` - If there's an error constructing entities, parsing the request, or during evaluation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use treetop_core::{PolicyEngine, Request, Principal, User, Action, Resource};
    ///
    /// let policies = r#"
    ///     permit (
    ///         principal == User::"alice",
    ///         action == Action::"read",
    ///         resource == Document::"doc1"
    ///     );
    /// "#;
    ///
    /// let engine = PolicyEngine::new_from_str(policies).unwrap();
    ///
    /// let request = Request {
    ///     principal: Principal::User(User::new("alice", None, None).unwrap()),
    ///     action: Action::new("read", None).unwrap(),
    ///     resource: Resource::new("Document", "doc1").unwrap(),
    /// };
    ///
    /// let decision = engine.evaluate(&request).unwrap();
    /// assert!(decision.is_allowed());
    ///
    /// // Access version information
    /// println!("Allowed by policy version: {}", decision.version().hash);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and lock-free. Multiple threads can evaluate requests
    /// concurrently without blocking each other.
    #[cfg_attr(
        feature = "observability",
        tracing::instrument(name = "policy_evaluation", skip_all)
    )]
    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        Ok(self
            .evaluate_internal(request, None, false)?
            .into_decision())
    }

    /// Evaluate a request with explicit Cedar request context.
    pub fn evaluate_with_context(
        &self,
        request: &Request,
        request_context: &RequestContext,
    ) -> Result<Decision, PolicyError> {
        Ok(self
            .evaluate_internal(request, Some(request_context), false)?
            .into_decision())
    }

    /// Evaluate a request and include deny-side forbid diagnostics.
    pub fn evaluate_with_diagnostics(
        &self,
        request: &Request,
    ) -> Result<DecisionDiagnostics, PolicyError> {
        self.evaluate_internal(request, None, true)
    }

    /// Evaluate a request with explicit context and include deny diagnostics.
    pub fn evaluate_with_context_and_diagnostics(
        &self,
        request: &Request,
        request_context: &RequestContext,
    ) -> Result<DecisionDiagnostics, PolicyError> {
        self.evaluate_internal(request, Some(request_context), true)
    }

    fn evaluate_internal(
        &self,
        request: &Request,
        request_context: Option<&RequestContext>,
        include_forbid_diagnostics: bool,
    ) -> Result<DecisionDiagnostics, PolicyError> {
        let state = self.current_state();
        Self::evaluate_state(&state, request, request_context, include_forbid_diagnostics)
    }

    fn evaluate_state(
        state: &EngineState,
        request: &Request,
        request_context: Option<&RequestContext>,
        include_forbid_diagnostics: bool,
    ) -> Result<DecisionDiagnostics, PolicyError> {
        let policy_set = state.policy.sets.resolve(request)?;
        // Prepare the request: apply labels, build entities, resolve groups
        let mut prepared = Self::prepare(state, request, request_context)?;

        // Perform authorization with RAII timing (using cached Authorizer)
        let result = {
            let measure_enabled = prepared.timers.measure_enabled;
            let _timer = PhaseTimer::new_if(&mut prepared.timers.authz, measure_enabled);
            #[cfg(feature = "observability")]
            let _authz_span = info_span!("authorize").entered();
            get_authorizer().is_authorized(&prepared.cedar_req, policy_set, &prepared.entities)
        };

        if prepared.timers.debug_enabled {
            debug!(
                event = "Request",
                phase = "Authorized",
                time = prepared.timers.authz.as_micros(),
                decision = ?result.decision(),
            );
        }

        let version = state.version();
        if prepared.timers.debug_enabled {
            debug!(
                event = "Request",
                phase = "Result",
                time = prepared.timers.total_elapsed().as_micros(),
                result = ?result.decision(),
                policy_hash = %version.hash,
                policy_loaded_at = %version.loaded_at,
            );
        }

        // Permit metadata is part of Allow decisions. Forbid IDs are only
        // materialized when the caller explicitly requests diagnostics. Metrics
        // borrow matching IDs from the Cedar response and compiled snapshot.
        let permit_policies = extract_permit_policies(&state.policy, &result);
        let collect_forbid_ids = include_forbid_diagnostics;
        let forbid_policy_ids = if collect_forbid_ids {
            extract_forbid_policy_ids(&state.policy, &result)
        } else {
            Vec::new()
        };
        let decision = Decision::from_cedar(result.decision(), permit_policies, version)?;

        // Record metrics (no-op when no sink is configured or feature disabled)
        #[cfg(feature = "observability")]
        {
            if prepared.metrics_enabled {
                let dur = prepared.timers.total_elapsed();
                let allowed = result.decision() == cedar_policy::Decision::Allow;
                let phases = EvaluationPhases {
                    apply_labels_ms: prepared.timers.labels.as_secs_f64() * 1000.0,
                    construct_entities_ms: prepared.timers.entities.as_secs_f64() * 1000.0,
                    resolve_groups_ms: prepared.timers.groups.as_secs_f64() * 1000.0,
                    authorize_ms: prepared.timers.authz.as_secs_f64() * 1000.0,
                    total_ms: dur.as_secs_f64() * 1000.0,
                };
                let matched_policies = match &decision {
                    Decision::Allow { policies, .. } => MatchedPolicySource::Allow(policies),
                    Decision::Deny { .. } => MatchedPolicySource::Deny {
                        diagnostics: result.diagnostics(),
                        policy_ids: &state.policy.forbid_policy_ids,
                    },
                };
                let observation = EvaluationObservation::new(
                    dur,
                    allowed,
                    &request.action,
                    phases,
                    matched_policies,
                );

                record_evaluation_observation(&prepared.sink, &observation);
            }
        }

        Ok(DecisionDiagnostics::new(decision, forbid_policy_ids))
    }

    /// List permit-policy candidates whose scope matches a user.
    ///
    /// This mirrors [`PolicyEngine::evaluate`] input shape for principal identity:
    /// user id + groups + shared namespace.
    ///
    /// Matching includes all Cedar principal-constraint forms:
    /// - `principal == User::"..."`
    /// - `principal in Group::"..."`
    /// - `principal`
    /// - `principal is User`
    /// - `principal is User in Group::"..."`
    ///
    /// Cedar `when` and `unless` clauses are not evaluated. The result is not
    /// an authorization decision; use [`PolicyEngine::evaluate`] to authorize.
    /// Resource constraints are not applied in this method. To additionally
    /// filter by policy resource constraints, use
    /// [`PolicyEngine::list_policies_for_user_with_resource`].
    ///
    /// Output is deterministic: policies are sorted by Cedar policy ID.
    /// Each returned policy includes match reasons via `PolicyCandidates::matches()`.
    ///
    /// # Arguments
    ///
    /// * `user` - User ID
    /// * `groups` - Group IDs the user belongs to
    /// * `namespace` - Optional shared namespace path for both user and groups
    ///
    /// # Returns
    ///
    /// * `Ok(PolicyCandidates)` - Matching policies and match metadata
    /// * `Err(PolicyError)` - If entity UID construction fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use treetop_core::PolicyEngine;
    ///
    /// let policies = r#"
    ///     permit (principal == User::"alice", action, resource);
    ///     permit (principal in Group::"admins", action, resource);
    /// "#;
    ///
    /// let engine = PolicyEngine::new_from_str(policies).unwrap();
    /// let candidates = engine.list_policies_for_user("alice", &["admins"], &[]).unwrap();
    ///
    /// assert_eq!(candidates.policies().len(), 2);
    /// assert!(!candidates.matches().is_empty());
    /// ```
    pub fn list_policies_for_user(
        &self,
        user: &str,
        groups: &[&str],
        namespace: &[&str],
    ) -> Result<PolicyCandidates, PolicyError> {
        self.list_policies_for_user_with_resource_and_effect(
            user,
            groups,
            namespace,
            None,
            PolicyEffectFilter::Permit,
        )
    }

    /// List permit-policy candidates whose scope matches a concrete request.
    ///
    /// This mirrors [`PolicyEngine::evaluate`] by accepting `&Request` and uses:
    /// - the request principal (including user group membership, if any)
    /// - the request action
    /// - the request resource
    ///
    /// Cedar `when` and `unless` clauses are not evaluated. The result is not
    /// an authorization decision. This method defaults to permit policies; use
    /// [`PolicyEngine::list_policies_with_effect`] for an explicit effect.
    pub fn list_policies(&self, request: &Request) -> Result<PolicyCandidates, PolicyError> {
        self.list_policies_with_effect(request, PolicyEffectFilter::Permit)
    }

    /// List policy candidates for a request, with explicit effect filtering.
    ///
    /// Cedar `when` and `unless` clauses are not evaluated.
    pub fn list_policies_with_effect(
        &self,
        request: &Request,
        effect_filter: PolicyEffectFilter,
    ) -> Result<PolicyCandidates, PolicyError> {
        let principal = PrincipalQuery::from_principal(&request.principal);
        let action = ActionQuery::from_action(&request.action);
        self.list_policies_dispatch(
            &request.principal.to_string(),
            &principal,
            Some(&action),
            Some(&request.resource),
            effect_filter,
        )
    }

    /// List all policies applicable to a user, optionally filtering by resource constraints.
    ///
    /// This variant applies both principal and resource constraints:
    /// - principal constraints as described in [`PolicyEngine::list_policies_for_user`]
    /// - resource constraints (`==`, `in`, `is`, `is in`, `any`) when `resource` is provided
    ///
    /// When `resource` is `None`, behavior is equivalent to
    /// [`PolicyEngine::list_policies_for_user`].
    ///
    /// Returned `PolicyCandidates` includes match reasons for principal and, when
    /// applicable, resource matches.
    pub fn list_policies_for_user_with_resource(
        &self,
        user: &str,
        groups: &[&str],
        namespace: &[&str],
        resource: Option<&Resource>,
    ) -> Result<PolicyCandidates, PolicyError> {
        self.list_policies_for_user_with_resource_and_effect(
            user,
            groups,
            namespace,
            resource,
            PolicyEffectFilter::Permit,
        )
    }

    /// List all policies applicable to a user with optional resource and effect filtering.
    pub fn list_policies_for_user_with_resource_and_effect(
        &self,
        user: &str,
        groups: &[&str],
        namespace: &[&str],
        resource: Option<&Resource>,
        effect_filter: PolicyEffectFilter,
    ) -> Result<PolicyCandidates, PolicyError> {
        let principal = PrincipalQuery::for_user(user, groups, namespace)?;
        self.list_policies_dispatch(user, &principal, None, resource, effect_filter)
    }

    /// List all policies applicable to a group principal.
    ///
    /// Useful when callers model group identities directly as principals
    /// (mirroring `Principal::Group` in [`PolicyEngine::evaluate`]).
    ///
    /// Resource constraints are not applied in this method. To also filter by
    /// resource constraints, use
    /// [`PolicyEngine::list_policies_for_group_with_resource`].
    pub fn list_policies_for_group(
        &self,
        group: &str,
        namespace: &[&str],
    ) -> Result<PolicyCandidates, PolicyError> {
        self.list_policies_for_group_with_resource_and_effect(
            group,
            namespace,
            None,
            PolicyEffectFilter::Permit,
        )
    }

    /// List all policies applicable to a group principal, optionally filtering by resource constraints.
    ///
    /// This applies principal constraints for a group principal and, when
    /// `resource` is provided, resource constraints as well.
    pub fn list_policies_for_group_with_resource(
        &self,
        group: &str,
        namespace: &[&str],
        resource: Option<&Resource>,
    ) -> Result<PolicyCandidates, PolicyError> {
        self.list_policies_for_group_with_resource_and_effect(
            group,
            namespace,
            resource,
            PolicyEffectFilter::Permit,
        )
    }

    /// List all policies applicable to a group principal with optional resource and effect filtering.
    pub fn list_policies_for_group_with_resource_and_effect(
        &self,
        group: &str,
        namespace: &[&str],
        resource: Option<&Resource>,
        effect_filter: PolicyEffectFilter,
    ) -> Result<PolicyCandidates, PolicyError> {
        let principal = PrincipalQuery::for_group(group, namespace)?;
        self.list_policies_dispatch(group, &principal, None, resource, effect_filter)
    }

    fn list_policies_dispatch(
        &self,
        principal_id: &str,
        principal: &PrincipalQuery,
        action: Option<&ActionQuery>,
        resource: Option<&Resource>,
        effect_filter: PolicyEffectFilter,
    ) -> Result<PolicyCandidates, PolicyError> {
        let snapshot = self.current_snapshot();
        let resource_query = resource.map(ResourceQuery::from_resource);
        let mut matching_policies: Vec<(Policy, Vec<PolicyMatchReason>)> = Vec::new();
        let mut seen_policy_ids = HashSet::new();

        for set in snapshot.sets.iter() {
            for policy in set.policies() {
                if !seen_policy_ids.insert(policy.id().clone()) {
                    continue;
                }
                if !matches_effect(policy.effect(), effect_filter) {
                    continue;
                }

                let Some(principal_reason) =
                    principal_match_reason(policy.principal_constraint(), principal)
                else {
                    continue;
                };

                let Some(action_reason) = action_match_reason(policy.action_constraint(), action)
                else {
                    continue;
                };

                let Some(resource_reason) =
                    resource_match_reason(policy.resource_constraint(), resource_query.as_ref())
                else {
                    continue;
                };

                let mut reasons = vec![principal_reason];
                if let Some(action_reason) = action_reason {
                    reasons.push(action_reason);
                }
                if let Some(resource_reason) = resource_reason {
                    reasons.push(resource_reason);
                }

                matching_policies.push((policy.clone(), reasons));
            }
        }

        Ok(PolicyCandidates::new_with_matches(
            principal_id,
            matching_policies,
        ))
    }

    /// Return all policies in the current coherent engine state.
    pub fn policies(&self) -> Vec<Policy> {
        let snapshot = self.current_snapshot();
        match &snapshot.sets {
            PolicySets::Monolithic(set) => set.policies().cloned().collect(),
            PolicySets::Scoped { .. } => {
                let mut seen_policy_ids = HashSet::new();
                let mut policies = snapshot
                    .sets
                    .iter()
                    .flat_map(PolicySet::policies)
                    .filter(|policy| seen_policy_ids.insert(policy.id().clone()))
                    .cloned()
                    .collect::<Vec<_>>();
                policies.sort_by(|left, right| left.id().cmp(right.id()));
                policies
            }
        }
    }
}

impl PolicyEngine<SchemaEnforcing> {
    /// Reload policies and replace the enforced schema in one atomic update.
    pub fn reload_from_str_with_schema(
        &self,
        policy_text: &str,
        schema: Schema,
    ) -> Result<(), PolicyError> {
        let current_state = self.current_state();
        let current_snapshot = &current_state.policy;
        let layout = current_snapshot.sets.layout().cloned();
        let new_snapshot: Snapshot =
            Arc::new(PolicySnapshot::from_policy_text_with_schema_and_stores(
                policy_text,
                Some(Arc::new(schema)),
                layout,
            )?);
        self.install_policy(new_snapshot);
        debug!(
            event = "PolicyReload",
            schema_enabled = true,
            schema_reloaded = true,
            schema_previously_enabled = true
        );
        #[cfg(feature = "observability")]
        record_reload();
        Ok(())
    }

    /// Reload policies and replace the enforced schema from Cedar schema text.
    pub fn reload_from_str_with_cedarschema(
        &self,
        policy_text: &str,
        schema_text: &str,
    ) -> Result<(), PolicyError> {
        let schema: Schema = schema_text
            .parse()
            .map_err(|e| PolicyError::ParseError(format!("failed to parse Cedar schema: {e}")))?;
        self.reload_from_str_with_schema(policy_text, schema)
    }
}

impl<M: ValidationMode> EvaluationSession<M> {
    /// Return the complete version used by every evaluation in this session.
    pub fn version(&self) -> PolicyVersion {
        self.state.version()
    }

    /// Evaluate a request against this session's frozen state.
    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        Ok(PolicyEngine::<M>::evaluate_state(&self.state, request, None, false)?.into_decision())
    }

    /// Evaluate a request with explicit Cedar request context.
    pub fn evaluate_with_context(
        &self,
        request: &Request,
        request_context: &RequestContext,
    ) -> Result<Decision, PolicyError> {
        Ok(
            PolicyEngine::<M>::evaluate_state(&self.state, request, Some(request_context), false)?
                .into_decision(),
        )
    }

    /// Evaluate a request and include deny-side forbid diagnostics.
    pub fn evaluate_with_diagnostics(
        &self,
        request: &Request,
    ) -> Result<DecisionDiagnostics, PolicyError> {
        PolicyEngine::<M>::evaluate_state(&self.state, request, None, true)
    }

    /// Evaluate a contextual request and include deny-side forbid diagnostics.
    pub fn evaluate_with_context_and_diagnostics(
        &self,
        request: &Request,
        request_context: &RequestContext,
    ) -> Result<DecisionDiagnostics, PolicyError> {
        PolicyEngine::<M>::evaluate_state(&self.state, request, Some(request_context), true)
    }
}

#[cfg(test)]
mod tests;
