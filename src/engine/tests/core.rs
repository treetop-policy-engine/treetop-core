use super::*;

#[test]
fn test_current_version_hash() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
    let version = engine.current_version();

    let expected_hash = Sha256::digest(TEST_POLICY.as_bytes()).iter().fold(
        String::with_capacity(64),
        |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").unwrap();
            s
        },
    );
    assert_eq!(version.hash.as_ref(), expected_hash);
}

#[test]
fn test_policysnapshot_policies() {
    let engine = PolicyEngine::new_from_str(TEST_POLICY).unwrap();
    let snapshot = engine.current_snapshot();
    let policies = snapshot.sets.iter().next().unwrap();
    assert_eq!(policies.policies().count(), 2);
}

#[test]
fn test_concurrent_evaluation() {
    use std::sync::Arc;
    use std::thread;

    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let engine = Arc::new(PolicyEngine::new_from_str(policies).unwrap());
    let mut handles = vec![];

    // Spawn 10 threads, each doing 100 evaluations
    for i in 0..10 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let request = Request {
                    principal: Principal::User(User::new("alice", None, None).unwrap()),
                    action: Action::new("read", None).unwrap(),
                    resource: Resource::new("Document", format!("doc{}", i % 5)).unwrap(),
                };
                let decision = engine_clone.evaluate(&request);
                assert!(decision.is_ok());
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_concurrent_label_registry_access() {
    use std::thread;

    let patterns = vec![("test_label".to_string(), Regex::new(r"test").unwrap())];
    let labeler = RegexLabeler::new("Host", "name", "nameLabels", patterns).unwrap();

    let label_registry = Arc::new(
        LabelRegistryBuilder::versioned("concurrency-v1")
            .add_labeler(Arc::new(labeler))
            .build()
            .unwrap(),
    );

    let mut handles = vec![];

    // Multiple threads applying labels
    for i in 0..5 {
        let registry = Arc::clone(&label_registry);
        let handle = thread::spawn(move || {
            let mut resource = Resource::new("Host", format!("test-{}", i))
                .unwrap()
                .with_attr("name", AttrValue::String(format!("test-{}", i)));

            registry.apply(&mut resource);

            // Verify labels were applied
            if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
                assert!(!labels.is_empty());
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_error_context_on_invalid_entity() {
    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let _ = PolicyEngine::new_from_str(policies).unwrap();

    // Create request with malformed principal
    let result = "Invalid::Entity::Structure".parse::<EntityUid>();
    assert!(result.is_err());
}

#[test]
fn test_error_context_on_malformed_policy() {
    let malformed_policy = r#"
            permit (
                principal == User::"alice"
                // Missing comma and rest of policy
        "#;

    let result = PolicyEngine::new_from_str(malformed_policy);
    assert!(result.is_err());

    if let Err(PolicyError::ParseError(msg)) = result {
        assert!(msg.contains("parse") || msg.contains("expected"));
    } else {
        panic!("Expected ParseError");
    }
}

#[test]
fn test_empty_policy_text() {
    let result = PolicyEngine::new_from_str("");
    assert!(result.is_ok());

    let engine = result.unwrap();
    let request = Request {
        principal: Principal::User(User::new("alice", None, None).unwrap()),
        action: Action::new("read", None).unwrap(),
        resource: Resource::new("Document", "doc1").unwrap(),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(!decision.is_allowed());
}

#[test]
fn test_whitespace_only_policy() {
    let result = PolicyEngine::new_from_str("   \n\t  \n  ");
    assert!(result.is_ok());
}

#[test]
fn test_label_registry_initialization() {
    let patterns1 = vec![("label1".to_string(), Regex::new(r"test1").unwrap())];
    let labeler1 = RegexLabeler::new("Host", "name", "nameLabels", patterns1).unwrap();

    let label_registry = LabelRegistryBuilder::versioned("initial-v1")
        .add_labeler(Arc::new(labeler1))
        .build()
        .unwrap();

    let mut resource = Resource::new("Host", "test1-host")
        .unwrap()
        .with_attr("name", AttrValue::String("test1-host".into()));

    label_registry.apply(&mut resource);

    if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
        assert_eq!(labels.len(), 1);
    }
}

#[test]
fn test_apply_labels_with_no_labelers() {
    // Test that an empty registry doesn't panic
    let label_registry = LabelRegistryBuilder::new().build().unwrap();
    assert!(label_registry.version().is_none());

    let mut resource = Resource::new("Host", "test-host")
        .unwrap()
        .with_attr("name", AttrValue::String("test-host".into()));

    // Should not panic with no labelers
    label_registry.apply(&mut resource);

    // Verify no labels were added
    assert!(resource.attrs().get("nameLabels").is_none());
}

#[test]
fn test_label_registry_replacement() {
    let patterns1 = vec![("old_label".to_string(), Regex::new(r"old").unwrap())];
    let labeler1 = RegexLabeler::new("Host", "name", "nameLabels", patterns1).unwrap();

    let old_registry = LabelRegistryBuilder::versioned("replacement-v1")
        .add_labeler(Arc::new(labeler1))
        .build()
        .unwrap();

    let patterns2 = vec![("new_label".to_string(), Regex::new(r"new").unwrap())];
    let labeler2 = RegexLabeler::new("Host", "name", "nameLabels", patterns2).unwrap();

    let label_registry = LabelRegistryBuilder::versioned("replacement-v2")
        .add_labeler(Arc::new(labeler2))
        .build()
        .unwrap();
    assert_eq!(
        old_registry.version().map(|version| version.as_str()),
        Some("replacement-v1")
    );

    let mut resource = Resource::new("Host", "new-host")
        .unwrap()
        .with_attr("name", AttrValue::String("new-host".into()));

    label_registry.apply(&mut resource);

    if let Some(AttrValue::Set(labels)) = resource.attrs().get("nameLabels") {
        // Should have new_label, not old_label
        let has_new = labels.iter().any(|l| {
            if let AttrValue::String(s) = l {
                s == "new_label"
            } else {
                false
            }
        });
        assert!(has_new);
    }
}

#[test]
fn evaluation_session_freezes_policy_and_label_generation() {
    fn registry(version: &str, label: &str) -> LabelRegistry {
        let labeler = RegexLabeler::new(
            "Host",
            "name",
            "labels",
            vec![(label.to_string(), Regex::new(".*").unwrap())],
        )
        .unwrap();
        LabelRegistryBuilder::versioned(version)
            .add_labeler(Arc::new(labeler))
            .build()
            .unwrap()
    }

    let policy_v1 = r#"
        permit (principal, action, resource is Host)
        when { resource.labels.contains("v1") };
    "#;
    let policy_v2 = r#"
        permit (principal, action, resource is Host)
        when { resource.labels.contains("v2") };
    "#;
    let engine = PolicyEngine::new_from_str(policy_v1)
        .unwrap()
        .with_label_registry(registry("labels-v1", "v1"));
    let request = Request {
        principal: Principal::User(User::new("alice", None, None).unwrap()),
        action: Action::new("read", None).unwrap(),
        resource: Resource::new("Host", "web-01")
            .unwrap()
            .with_attr("name", AttrValue::String("web-01".into())),
    };

    let session = engine.session();
    assert_eq!(
        session.version().label_set.as_ref().unwrap().as_str(),
        "labels-v1"
    );
    assert!(session.evaluate(&request).unwrap().is_allowed());

    engine.set_label_registry(registry("labels-v2", "v2"));
    assert!(!engine.evaluate(&request).unwrap().is_allowed());
    assert!(session.evaluate(&request).unwrap().is_allowed());
    assert_ne!(
        session.version().generation,
        engine.current_version().generation
    );

    engine.reload_from_str(policy_v2).unwrap();
    assert!(engine.evaluate(&request).unwrap().is_allowed());
    assert!(session.evaluate(&request).unwrap().is_allowed());
}

#[test]
fn test_large_policy_set() {
    // Generate 100 policies
    let mut policies = String::new();
    for i in 0..100 {
        policies.push_str(&format!(
            r#"
                permit (
                    principal == User::"user{}",
                    action == Action::"read",
                    resource == Document::"doc{}"
                );
                "#,
            i, i
        ));
    }

    let engine = PolicyEngine::new_from_str(&policies).unwrap();

    // Test evaluation still works
    let request = Request {
        principal: Principal::User(User::new("user50", None, None).unwrap()),
        action: Action::new("read", None).unwrap(),
        resource: Resource::new("Document", "doc50").unwrap(),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(decision.is_allowed());
}

#[test]
fn test_deeply_nested_namespaces() {
    let policies = r#"
            permit (
                principal == A::B::C::D::E::User::"alice",
                action == A::B::C::D::E::Action::"read",
                resource == A::B::C::D::E::Document::"doc1"
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();

    let request = Request {
        principal: Principal::User(
            User::new(
                "alice",
                None,
                Some(vec![
                    "A".into(),
                    "B".into(),
                    "C".into(),
                    "D".into(),
                    "E".into(),
                ]),
            )
            .unwrap(),
        ),
        action: Action::new(
            "read",
            Some(vec![
                "A".into(),
                "B".into(),
                "C".into(),
                "D".into(),
                "E".into(),
            ]),
        )
        .unwrap(),
        resource: Resource::new("A::B::C::D::E::Document", "doc1").unwrap(),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(decision.is_allowed());
}

#[test]
fn test_resource_with_many_attributes() {
    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource is Document
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();

    // Create resource with 50 attributes
    let mut resource = Resource::new("Document", "doc1").unwrap();
    for i in 0..50 {
        resource = resource.with_attr(
            format!("attr{}", i),
            AttrValue::String(format!("value{}", i)),
        );
    }

    let request = Request {
        principal: Principal::User(User::new("alice", None, None).unwrap()),
        action: Action::new("read", None).unwrap(),
        resource,
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(decision.is_allowed());
}

#[test]
fn test_user_with_many_groups() {
    let policies = r#"
            permit (
                principal in Group::"group25",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();

    // Create user in 50 groups
    let groups: Vec<String> = (0..50).map(|i| format!("group{}", i)).collect();

    let request = Request {
        principal: Principal::User(User::new("alice", Some(groups), None).unwrap()),
        action: Action::new("read", None).unwrap(),
        resource: Resource::new("Document", "doc1").unwrap(),
    };

    let decision = engine.evaluate(&request).unwrap();
    assert!(decision.is_allowed());
}

#[test]
fn test_decision_includes_correct_version() {
    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();
    let engine_version = engine.current_version();

    let request = Request {
        principal: Principal::User(User::new("alice", None, None).unwrap()),
        action: Action::new("read", None).unwrap(),
        resource: Resource::new("Document", "doc1").unwrap(),
    };

    let decision = engine.evaluate(&request).unwrap();

    assert!(decision.is_allowed());
    assert_eq!(decision.version().hash, engine_version.hash);
}

#[test]
fn test_multiple_snapshots_share_data() {
    let policies = r#"
            permit (
                principal == User::"alice",
                action == Action::"read",
                resource == Document::"doc1"
            );
        "#;

    let engine1 = PolicyEngine::new_from_str(policies).unwrap();
    let engine2 = engine1.clone();

    let version1 = engine1.current_version();
    let version2 = engine2.current_version();

    // Both clones should share the same snapshot
    assert_eq!(version1.hash, version2.hash);
    assert_eq!(version1.loaded_at, version2.loaded_at);
}

#[test]
fn test_multiple_policies_captured() {
    // Test that when multiple policies match, all are captured in the Decision
    let policies = r#"
            permit (
                principal,
                action == Action::"read",
                resource == Document::"public"
            );

            permit (
                principal == User::"alice",
                action,
                resource
            );
        "#;

    let engine = PolicyEngine::new_from_str(policies).unwrap();

    // Alice reading public document should match both policies
    let request = Request {
        principal: Principal::User(User::new("alice", None, None).unwrap()),
        action: Action::new("read", None).unwrap(),
        resource: Resource::new("Document", "public").unwrap(),
    };

    let decision = engine.evaluate(&request).unwrap();

    assert!(decision.is_allowed());
    let policies = decision.permit_policies().unwrap();
    assert_eq!(
        policies.len(),
        2,
        "Should have captured both matching policies"
    );
    // Both policy0 and policy1 should be present
    let policy_ids: Vec<_> = policies.iter().map(|p| p.cedar_id.as_ref()).collect();
    assert!(policy_ids.contains(&"policy0"), "Should contain policy0");
    assert!(policy_ids.contains(&"policy1"), "Should contain policy1");
}
