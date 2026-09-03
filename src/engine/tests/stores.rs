use super::*;
use crate::{PolicyStoreConfig, PolicyStoreLayout};

const SCOPED_POLICIES: &str = r#"
@id("dns.read")
permit (
    principal == User::"alice",
    action == DNS::Action::"read",
    resource is DNS::Record
);

@id("www.read")
permit (
    principal == User::"alice",
    action == WWW::Action::"read",
    resource is WWW::Page
);

@id("org.blocked")
forbid (
    principal == User::"blocked",
    action,
    resource
);
"#;

fn store_layout() -> PolicyStoreLayout {
    PolicyStoreLayout::new([
        PolicyStoreConfig::new("dns", "DNS").unwrap(),
        PolicyStoreConfig::new("www", "WWW").unwrap(),
    ])
    .unwrap()
    .with_global_policy_ids(["org.blocked"])
    .unwrap()
}

fn request(user: &str, store: &str, resource_kind: &str) -> Request {
    let namespace = (!store.is_empty()).then(|| vec![store.to_string()]);
    Request {
        principal: Principal::User(User::new(user, None, None).unwrap()),
        action: Action::new("read", namespace).unwrap(),
        resource: Resource::new(resource_kind, "resource-1").unwrap(),
    }
}

#[test]
fn scoped_engine_routes_each_request_to_one_store() {
    let engine =
        PolicyEngine::new_from_str_with_policy_stores(SCOPED_POLICIES, store_layout()).unwrap();

    assert_allow(
        &engine
            .evaluate(&request("alice", "DNS", "DNS::Record"))
            .unwrap(),
    );
    assert_allow(
        &engine
            .evaluate(&request("alice", "WWW", "WWW::Page"))
            .unwrap(),
    );

    let store_ids = engine
        .policy_store_ids()
        .unwrap()
        .into_iter()
        .map(|id| id.as_str().to_string())
        .collect::<Vec<_>>();
    assert_eq!(store_ids, ["dns", "www"]);
}

#[test]
fn scoped_engine_matches_monolithic_decisions() {
    let monolithic = PolicyEngine::new_from_str(SCOPED_POLICIES).unwrap();
    let scoped =
        PolicyEngine::new_from_str_with_policy_stores(SCOPED_POLICIES, store_layout()).unwrap();

    for request in [
        request("alice", "DNS", "DNS::Record"),
        request("alice", "WWW", "WWW::Page"),
        request("bob", "DNS", "DNS::Record"),
        request("blocked", "DNS", "DNS::Record"),
        request("blocked", "WWW", "WWW::Page"),
    ] {
        let monolithic_decision = monolithic.evaluate(&request).unwrap();
        let scoped_decision = scoped.evaluate(&request).unwrap();
        assert_eq!(
            matches!(monolithic_decision, Decision::Allow { .. }),
            matches!(scoped_decision, Decision::Allow { .. })
        );
    }
}

#[test]
fn global_forbid_is_enforced_in_every_store() {
    let engine =
        PolicyEngine::new_from_str_with_policy_stores(SCOPED_POLICIES, store_layout()).unwrap();

    assert_deny(
        &engine
            .evaluate(&request("blocked", "DNS", "DNS::Record"))
            .unwrap(),
    );
    assert_deny(
        &engine
            .evaluate(&request("blocked", "WWW", "WWW::Page"))
            .unwrap(),
    );
}

#[test]
fn cross_store_request_fails_closed() {
    let engine =
        PolicyEngine::new_from_str_with_policy_stores(SCOPED_POLICIES, store_layout()).unwrap();

    let result = engine.evaluate(&request("alice", "DNS", "WWW::Page"));
    assert!(matches!(
        result,
        Err(PolicyError::PolicyStoreRoutingError(_))
    ));
}

#[test]
fn unscoped_policy_requires_explicit_assignment() {
    let policy = r#"
        @id("ambiguous")
        permit (principal == User::"alice", action, resource);
    "#;
    let result = PolicyEngine::new_from_str_with_policy_stores(policy, store_layout());
    assert!(matches!(
        result,
        Err(PolicyError::PolicyStoreConfigError(_))
    ));
}

#[test]
fn policy_spanning_stores_is_rejected() {
    let policy = r#"
        @id("cross-store")
        permit (
            principal,
            action == DNS::Action::"read",
            resource is WWW::Page
        );
    "#;
    let result = PolicyEngine::new_from_str_with_policy_stores(policy, store_layout());
    assert!(matches!(
        result,
        Err(PolicyError::PolicyStoreConfigError(_))
    ));
}

#[test]
fn condition_referencing_another_store_is_rejected() {
    let policy = r#"
        @id("hidden-cross-store-reference")
        permit (
            principal,
            action == DNS::Action::"read",
            resource is DNS::Record
        ) when {
            resource == WWW::Page::"other"
        };
    "#;
    let result = PolicyEngine::new_from_str_with_policy_stores(policy, store_layout());
    assert!(matches!(
        result,
        Err(PolicyError::PolicyStoreConfigError(_))
    ));
}

#[test]
fn annotation_assigns_unscoped_policy() {
    let policy = r#"
        @id("dns.explicit")
        @treetop_store("dns")
        permit (principal == User::"alice", action, resource);
    "#;
    let layout = PolicyStoreLayout::new([
        PolicyStoreConfig::new("dns", "DNS").unwrap(),
        PolicyStoreConfig::new("www", "WWW").unwrap(),
    ])
    .unwrap();
    let engine = PolicyEngine::new_from_str_with_policy_stores(policy, layout).unwrap();

    assert_allow(
        &engine
            .evaluate(&request("alice", "DNS", "DNS::Record"))
            .unwrap(),
    );
    assert_deny(
        &engine
            .evaluate(&request("alice", "WWW", "WWW::Page"))
            .unwrap(),
    );
}

#[test]
fn global_annotation_installs_policy_in_every_store() {
    let policy = r#"
        @id("emergency")
        @treetop_store("*")
        forbid (principal == User::"blocked", action, resource);
    "#;
    let layout = PolicyStoreLayout::new([
        PolicyStoreConfig::new("dns", "DNS").unwrap(),
        PolicyStoreConfig::new("www", "WWW").unwrap(),
    ])
    .unwrap();
    let engine = PolicyEngine::new_from_str_with_policy_stores(policy, layout).unwrap();

    assert_deny(
        &engine
            .evaluate(&request("blocked", "DNS", "DNS::Record"))
            .unwrap(),
    );
    assert_deny(
        &engine
            .evaluate(&request("blocked", "WWW", "WWW::Page"))
            .unwrap(),
    );
}

#[test]
fn explicit_assignment_cannot_override_conflicting_scope() {
    let policy = r#"
        @id("wrong-store")
        @treetop_store("www")
        permit (principal, action == DNS::Action::"read", resource);
    "#;
    let result = PolicyEngine::new_from_str_with_policy_stores(policy, store_layout());
    assert!(matches!(
        result,
        Err(PolicyError::PolicyStoreConfigError(_))
    ));
}

#[test]
fn missing_registered_global_policy_rejects_load() {
    let layout = store_layout()
        .with_global_policy_ids(["missing.policy"])
        .unwrap();
    let result = PolicyEngine::new_from_str_with_policy_stores(SCOPED_POLICIES, layout);
    assert!(matches!(
        result,
        Err(PolicyError::PolicyStoreConfigError(_))
    ));
}

#[test]
fn registered_global_policy_cannot_have_local_annotation() {
    let policy = r#"
        @id("conflicting-global")
        @treetop_store("dns")
        forbid (principal, action, resource);
    "#;
    let layout = PolicyStoreLayout::new([
        PolicyStoreConfig::new("dns", "DNS").unwrap(),
        PolicyStoreConfig::new("www", "WWW").unwrap(),
    ])
    .unwrap()
    .with_global_policy_ids(["conflicting-global"])
    .unwrap();
    let result = PolicyEngine::new_from_str_with_policy_stores(policy, layout);
    assert!(matches!(
        result,
        Err(PolicyError::PolicyStoreConfigError(_))
    ));
}

#[test]
fn reload_preserves_store_layout_and_is_atomic_on_failure() {
    let engine =
        PolicyEngine::new_from_str_with_policy_stores(SCOPED_POLICIES, store_layout()).unwrap();
    let before = engine.current_version();

    let invalid = r#"
        @id("unroutable")
        permit (principal, action, resource);
    "#;
    assert!(matches!(
        engine.reload_from_str(invalid),
        Err(PolicyError::PolicyStoreConfigError(_))
    ));
    assert_eq!(engine.current_version(), before);
    assert_allow(
        &engine
            .evaluate(&request("alice", "DNS", "DNS::Record"))
            .unwrap(),
    );
}

#[test]
fn administrative_policy_views_deduplicate_global_policies() {
    let engine =
        PolicyEngine::new_from_str_with_policy_stores(SCOPED_POLICIES, store_layout()).unwrap();

    assert_eq!(engine.policies().len(), 3);
    let listed = engine
        .list_policies_for_user_with_resource_and_effect(
            "blocked",
            &[],
            &[],
            None,
            PolicyEffectFilter::Any,
        )
        .unwrap();
    assert_eq!(listed.policies().len(), 1);
}

#[test]
fn legacy_constructor_remains_monolithic() {
    let engine = PolicyEngine::new_from_str(
        r#"permit (principal == User::"alice", action == Action::"read", resource is Document);"#,
    )
    .unwrap();
    assert!(engine.policy_store_ids().is_none());
    assert_allow(&engine.evaluate(&request("alice", "", "Document")).unwrap());
}

#[test]
fn schema_text_constructor_validates_and_routes_stores() {
    let schema = r#"
        namespace DNS {
            entity User;
            entity Record = {
                id: String
            };
            action "read" appliesTo {
                principal: User,
                resource: Record
            };
        }
        namespace WWW {
            entity User;
            entity Page = {
                id: String
            };
            action "read" appliesTo {
                principal: User,
                resource: Page
            };
        }
    "#;
    let policies = r#"
        @id("dns.read")
        permit (
            principal == DNS::User::"alice",
            action == DNS::Action::"read",
            resource is DNS::Record
        );
        @id("www.read")
        permit (
            principal == WWW::User::"alice",
            action == WWW::Action::"read",
            resource is WWW::Page
        );
    "#;
    let layout = PolicyStoreLayout::new([
        PolicyStoreConfig::new("dns", "DNS").unwrap(),
        PolicyStoreConfig::new("www", "WWW").unwrap(),
    ])
    .unwrap();
    let engine =
        PolicyEngine::new_from_str_with_cedarschema_and_policy_stores(policies, schema, layout)
            .unwrap();
    let request = Request {
        principal: Principal::User(
            User::new("alice", None, Some(vec!["DNS".to_string()])).unwrap(),
        ),
        action: Action::new("read", Some(vec!["DNS".to_string()])).unwrap(),
        resource: Resource::new("DNS::Record", "record-1").unwrap(),
    };

    assert_allow(&engine.evaluate(&request).unwrap());
}
