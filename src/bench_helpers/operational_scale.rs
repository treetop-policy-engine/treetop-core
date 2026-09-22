//! A namespaced extension of the stable scale corpus, with identical request
//! outcomes in every store. This fixture has its own version so historical
//! single-thread scale results remain comparable.

use super::policy_scale::{REVIEWERS_GROUP, ScaleCorpus, TARGET_DOCUMENT, TARGET_USER};
use crate::{
    Action, AttrValue, PolicyEngine, PolicyStoreConfig, PolicyStoreLayout, Principal, Request,
    Resource, SchemaEnforcing, User,
};

/// Version of the operational corpus, including request mix and schema.
pub const OPERATIONAL_CORPUS_VERSION: u32 = 1;

/// Deterministic independent stores with one organization-wide forbid.
pub struct OperationalCorpus {
    /// Complete policies: `stores * policies_per_store + 1`.
    pub policy_text: String,
    /// Strict Cedar schema, shared by all generations.
    pub schema_text: String,
    stores: usize,
}

impl OperationalCorpus {
    /// Extend the scale fixture into independent namespaces.
    ///
    /// # Panics
    /// Requires at least one store and four policies per store.
    pub fn new(stores: usize, policies_per_store: usize, generation: usize) -> Self {
        assert!(stores > 0);
        let base = ScaleCorpus::new(policies_per_store, generation);
        let shared = "entity User in [Group];\nentity Group;\n";
        let schema_body = base.schema_text.strip_prefix(shared).unwrap();
        let mut policy_text = String::from(
            "@id(\"organization.blocked\") @treetop_store(\"*\")\nforbid(principal == User::\"blocked\", action, resource);\n",
        );
        let mut schema_text = shared.to_string();
        for store in 0..stores {
            let namespace = format!("Store{store}");
            policy_text.push_str(
                &base
                    .policy_text
                    .replace("@id(\"scale.", &format!("@id(\"store{store}.scale."))
                    .replace("Action::", &format!("{namespace}::Action::"))
                    .replace("Document::", &format!("{namespace}::Document::"))
                    .replace(
                        "resource is Document",
                        &format!("resource is {namespace}::Document"),
                    ),
            );
            schema_text.push_str(&format!("namespace {namespace} {{\n{schema_body}\n}}\n"));
        }
        Self {
            policy_text,
            schema_text,
            stores,
        }
    }

    /// Load the same policy text with or without namespace partitioning.
    pub fn engine(&self, partitioned: bool) -> PolicyEngine<SchemaEnforcing> {
        if partitioned {
            let layout = PolicyStoreLayout::new((0..self.stores).map(|store| {
                PolicyStoreConfig::new(format!("store-{store}"), format!("Store{store}")).unwrap()
            }))
            .unwrap();
            PolicyEngine::new_from_str_with_cedarschema_and_policy_stores(
                &self.policy_text,
                &self.schema_text,
                layout,
            )
            .unwrap()
        } else {
            PolicyEngine::new_from_str_with_cedarschema(&self.policy_text, &self.schema_text)
                .unwrap()
        }
    }

    /// Equal-weight allow, local forbid, group allow, no-match, and global forbid
    /// requests distributed across every store. The bool is the expected decision.
    pub fn requests(&self) -> Vec<(Request, bool)> {
        let mut requests = Vec::with_capacity(self.stores * 5);
        for store in 0..self.stores {
            for (action, user, group, allowed) in [
                ("read", TARGET_USER, false, true),
                ("delete", TARGET_USER, false, false),
                ("review", TARGET_USER, true, true),
                ("noise_00", TARGET_USER, false, false),
                ("review", "blocked", true, false),
            ] {
                requests.push((
                    Request {
                        principal: Principal::User(
                            User::new(user, group.then(|| vec![REVIEWERS_GROUP.into()]), None)
                                .unwrap(),
                        ),
                        action: Action::new(action, Some(vec![format!("Store{store}")])).unwrap(),
                        resource: Resource::new(format!("Store{store}::Document"), TARGET_DOCUMENT)
                            .unwrap()
                            .with_attr("classification", AttrValue::String("public".into())),
                    },
                    allowed,
                ));
            }
        }
        requests
    }
}
