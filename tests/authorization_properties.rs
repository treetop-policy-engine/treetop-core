//! Generated trust-boundary checks. Persist and commit minimized failure seeds.

use std::sync::Arc;

use cedar_policy::{EntityId, EntityUid};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use treetop_core::{
    Action, AttrValue, CedarIp, Group, LabelRegistryBuilder, LabelTarget, Labeler, LabelerApply,
    PolicyEngine, PolicyStoreConfig, PolicyStoreLayout, Principal, Request, RequestContext,
    Resource, User,
};

fn text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..32).prop_map(|chars| chars.into_iter().collect())
}

fn namespace() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec("Ns[a-zA-Z0-9_]{0,12}", 0..4)
}

fn round_trip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let restored: T = serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap();
    assert_eq!(value, &restored);
}

fn uid(kind: &str, id: &str) -> String {
    EntityUid::from_type_name_and_id(kind.parse().unwrap(), EntityId::new(id)).to_string()
}

#[derive(Clone)]
struct CopyLabeler {
    target: LabelTarget,
    source: String,
}

impl Labeler for CopyLabeler {
    fn target(&self) -> &LabelTarget {
        &self.target
    }

    fn derive(&self, resource: &Resource) -> Option<AttrValue> {
        resource.attributes().get(&self.source).cloned()
    }
}

fn arbitrary_attr() -> impl Strategy<Value = AttrValue> {
    prop_oneof![
        text().prop_map(AttrValue::String),
        any::<bool>().prop_map(AttrValue::Bool),
        any::<i64>().prop_map(AttrValue::Long),
        prop::collection::vec(text(), 0..4)
            .prop_map(|values| AttrValue::Set(values.into_iter().map(AttrValue::String).collect())),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/authorization_properties.proptest-regressions",
        ))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn identities_round_trip_through_cedar_and_serde(id in text(), ns in namespace()) {
        // Empty is deliberately excluded only from the valid-identity property.
        // Rejection is covered independently below.
        prop_assume!(!id.is_empty());
        let prefix = if ns.is_empty() { String::new() } else { format!("{}::", ns.join("::")) };
        let user = User::new(&id, None, Some(ns.clone())).unwrap();
        let group = Group::new(&id, Some(ns.clone())).unwrap();
        let action = Action::new(&id, Some(ns)).unwrap();
        let resource = Resource::new(format!("{prefix}Document"), &id).unwrap();
        prop_assert_eq!(uid(&format!("{prefix}User"), &id).parse::<User>().unwrap(), user.clone());
        prop_assert_eq!(uid(&format!("{prefix}Group"), &id).parse::<Group>().unwrap(), group.clone());
        prop_assert_eq!(uid(&format!("{prefix}Action"), &id).parse::<Action>().unwrap(), action.clone());
        prop_assert_eq!(uid(resource.kind(), &id).parse::<Resource>().unwrap(), resource.clone());
        round_trip(&user);
        round_trip(&group);
        round_trip(&action);
        round_trip(&resource);
    }

    #[test]
    fn constructors_and_wire_data_agree_on_invalid_boundaries(
        id in text(), kind in text(), ns in prop::collection::vec(text(), 0..4),
        attribute in text(), ip in text(),
    ) {
        prop_assert_eq!(
            Resource::new(&kind, &id).is_ok(),
            serde_json::from_value::<Resource>(json!({"kind": kind, "id": id})).is_ok()
        );
        prop_assert_eq!(
            User::new(&id, None, Some(ns.clone())).is_ok(),
            serde_json::from_value::<User>(json!({"id": id, "namespace": ns, "groups": []})).is_ok()
        );
        prop_assert_eq!(
            Group::new(&id, Some(ns.clone())).is_ok(),
            serde_json::from_value::<Group>(json!({"id": id, "namespace": ns})).is_ok()
        );
        prop_assert_eq!(
            Action::new(&id, Some(ns.clone())).is_ok(),
            serde_json::from_value::<Action>(json!({"id": id, "namespace": ns})).is_ok()
        );
        prop_assert_eq!(
            LabelTarget::new(&kind, &attribute).is_ok(),
            serde_json::from_value::<LabelTarget>(json!({"resource_type": kind, "attribute": attribute})).is_ok()
        );
        prop_assert_eq!(CedarIp::new(&ip).is_ok(), serde_json::from_value::<CedarIp>(json!(ip)).is_ok());
        prop_assert!(User::new("", None, None).is_err());
        prop_assert!(Resource::new("Document", "").is_err());
    }

    #[test]
    fn malformed_quoted_ids_and_group_suffixes_are_rejected(id in "[a-z]{1,20}") {
        for kind in ["User", "Group", "Action", "Document"] {
            for malformed in [format!("{kind}::\"{id}"), format!("{kind}::\"{id}\"trailing"), format!("{kind}::\"{id}\\q\"")] {
                prop_assert!(malformed.parse::<User>().is_err());
                prop_assert!(malformed.parse::<Group>().is_err());
                prop_assert!(malformed.parse::<Action>().is_err());
                prop_assert!(malformed.parse::<Resource>().is_err());
            }
        }
        for suffix in ["[", "[a,]", "[,a]", "[a,,b]", "[[a]]", "[a]trailing", "]"] {
            let malformed = format!("User::\"{id}\"{suffix}");
            prop_assert!(malformed.parse::<User>().is_err());
        }
    }

    #[test]
    fn user_wire_data_rejects_foreign_group_namespaces(id in "[a-z]{1,20}", ns in namespace()) {
        let user = User::new(id, Some(vec!["reviewers".into()]), Some(ns)).unwrap();
        let mut wire = serde_json::to_value(user).unwrap();
        wire["groups"][0]["namespace"] = json!(["Foreign"]);
        prop_assert!(serde_json::from_value::<User>(wire).is_err());
    }

    #[test]
    fn ip_addresses_and_networks_round_trip(octets in any::<[u8; 4]>(), prefix in 0u8..=32) {
        let address = std::net::Ipv4Addr::from(octets);
        for value in [address.to_string(), format!("{address}/{prefix}")] {
            round_trip(&CedarIp::new(&value).unwrap());
            round_trip(&AttrValue::ip(&value).unwrap());
        }
        let invalid = format!("{address}/33");
        prop_assert!(CedarIp::new(invalid).is_err());
    }

    #[test]
    fn registry_removes_forged_dependencies_and_is_idempotent(
        forged in arbitrary_attr(), trusted in prop::option::of(arbitrary_attr()),
        ns in namespace(), reverse in any::<bool>(),
    ) {
        let kind = format!("{}Document", if ns.is_empty() { String::new() } else { format!("{}::", ns.join("::")) });
        let first = CopyLabeler { target: LabelTarget::new(&kind, "first").unwrap(), source: "second".into() };
        let second = CopyLabeler { target: LabelTarget::new(&kind, "second").unwrap(), source: "trusted".into() };
        let mut builder = LabelRegistryBuilder::new();
        for labeler in if reverse { [second.clone(), first.clone()] } else { [first.clone(), second.clone()] } {
            builder = builder.add_labeler(Arc::new(labeler));
        }
        let registry = builder.build().unwrap();
        let mut input = Resource::new(&kind, "doc").unwrap()
            .with_attr("first", forged.clone()).with_attr("second", forged.clone())
            .with_attr("unowned", forged.clone());
        if let Some(value) = &trusted { input.attrs().insert("trusted".into(), value.clone()); }
        registry.apply(&mut input);
        prop_assert_eq!(input.attributes().get("first"), if reverse { trusted.as_ref() } else { None });
        prop_assert_eq!(input.attributes().get("second"), trusted.as_ref());
        prop_assert_eq!(input.attributes().get("unowned"), Some(&forged));
        let once = input.clone();
        registry.apply(&mut input);
        prop_assert_eq!(input, once);

        let mut unrelated = Resource::new("Other::Document", "doc").unwrap().with_attr("second", forged);
        let original = unrelated.clone();
        registry.apply(&mut unrelated);
        prop_assert_eq!(unrelated, original);
        prop_assert!(LabelRegistryBuilder::new().add_labeler(Arc::new(first.clone()))
            .add_labeler(Arc::new(first)).build().is_err());
    }

    #[test]
    fn direct_application_cannot_echo_its_owned_output(forged in arbitrary_attr(), name in "label_[a-z]{1,12}") {
        let labeler = CopyLabeler { target: LabelTarget::new("App::Document", &name).unwrap(), source: name.clone() };
        let mut resource = Resource::new("App::Document", "doc").unwrap().with_attr(&name, forged);
        labeler.apply(&mut resource);
        prop_assert!(!resource.attributes().contains_key(&name));
        let once = resource.clone();
        labeler.apply(&mut resource);
        prop_assert_eq!(resource, once);
    }

    #[test]
    fn forged_labels_do_not_change_authorization(forged in arbitrary_attr(), trusted in any::<bool>()) {
        let registry = LabelRegistryBuilder::new().add_labeler(Arc::new(CopyLabeler {
            target: LabelTarget::new("App::Document", "approved").unwrap(), source: "trusted".into(),
        })).build().unwrap();
        let engine = PolicyEngine::new_from_str(
            "permit(principal, action, resource is App::Document) when { resource.approved };"
        ).unwrap().with_label_registry(registry);
        let request = Request {
            principal: Principal::User(User::new("alice", None, None).unwrap()),
            action: Action::without_namespace("read").unwrap(),
            resource: Resource::new("App::Document", "doc").unwrap()
                .with_attr("approved", forged).with_attr("trusted", AttrValue::Bool(trusted)),
        };
        let decision = engine.evaluate(&request).unwrap();
        prop_assert_eq!(decision.is_allowed(), trusted);
        prop_assert_eq!(decision.version(), &engine.current_version());
    }

    #[test]
    fn partitioning_preserves_generated_policy_semantics(
        // Each rule chooses a store, principal constraint, effect, and condition.
        rules in prop::collection::vec((0usize..3, any::<bool>(), any::<bool>(), 0i64..10), 1..16),
        member in any::<bool>(), score in 0i64..10, blocked in any::<bool>(), exception in any::<bool>(),
    ) {
        let mut policies = String::from("@id(\"global\") @treetop_store(\"*\") forbid(principal,action,resource) when { context.blocked };");
        for (index, (store, group, forbid, threshold)) in rules.iter().enumerate() {
            let effect = if *forbid { "forbid" } else { "permit" };
            let principal = if *group { "principal in Group::\"reviewers\"" } else { "principal == User::\"alice\"" };
            policies.push_str(&format!(
                "@id(\"rule{index}\") {effect}({principal}, action == Ns{store}::Action::\"read\", resource is Ns{store}::Document) when {{ resource.score >= {threshold} }} unless {{ context.exception }};"
            ));
        }
        let layout = PolicyStoreLayout::new((0..3).map(|store|
            PolicyStoreConfig::new(format!("store{store}"), format!("Ns{store}")).unwrap()
        )).unwrap();
        let monolithic = PolicyEngine::new_from_str(&policies).unwrap();
        let scoped = PolicyEngine::new_from_str_with_policy_stores(&policies, layout).unwrap();
        let context = RequestContext::new().with_attr("blocked", AttrValue::Bool(blocked))
            .with_attr("exception", AttrValue::Bool(exception));
        for store in 0..3 {
            let request = Request {
                principal: Principal::User(User::new("alice", member.then(|| vec!["reviewers".into()]), None).unwrap()),
                action: Action::new("read", Some(vec![format!("Ns{store}")])).unwrap(),
                resource: Resource::new(format!("Ns{store}::Document"), "doc").unwrap().with_attr("score", AttrValue::Long(score)),
            };
            let matches = |rule: &&(usize, bool, bool, i64)| rule.0 == store && (!rule.1 || member) && score >= rule.3 && !exception;
            let permits = rules.iter().filter(matches).any(|rule| !rule.2);
            let forbids = blocked || rules.iter().filter(matches).any(|rule| rule.2);
            let mut expected_forbids: Vec<_> = rules.iter().enumerate().filter(|(_, rule)| matches(rule) && rule.2)
                .map(|(index, _)| format!("rule{index}")).collect();
            if blocked { expected_forbids.push("global".into()); }
            expected_forbids.sort();
            for engine in [&monolithic, &scoped] {
                let diagnostics = engine.evaluate_with_context_and_diagnostics(&request, &context).unwrap();
                prop_assert_eq!(diagnostics.decision().is_allowed(), permits && !forbids);
                prop_assert_eq!(diagnostics.decision().version(), &engine.current_version());
                let mut actual = diagnostics.matched_forbid_policy_ids().to_vec();
                actual.sort();
                prop_assert_eq!(&actual, &expected_forbids);
                if let Some(policies) = diagnostics.decision().permit_policies() {
                    let mut ids = policies.ids();
                    ids.sort();
                    let mut expected: Vec<_> = rules.iter().enumerate().filter(|(_, rule)| matches(rule) && !rule.2)
                        .map(|(index, _)| format!("rule{index}")).collect();
                    expected.sort();
                    prop_assert_eq!(ids, expected);
                }
            }
        }
        let before = scoped.current_version();
        let session = scoped.session();
        prop_assert!(scoped.reload_from_str("permit (").is_err());
        prop_assert_eq!(scoped.current_version(), before.clone());
        scoped.reload_from_str(&policies).unwrap();
        prop_assert_eq!(scoped.current_version().generation, before.generation + 1);
        prop_assert_eq!(session.version(), before);
    }
}
