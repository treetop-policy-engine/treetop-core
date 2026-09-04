use treetop_core::{
    Action, Decision, DecisionDiagnostics, DecisionDto, PermitPolicies, PolicyEngine, Principal,
    Request, Resource, User,
};
use utoipa::{OpenApi, PartialSchema};

fn request() -> Request {
    Request {
        principal: Principal::User(User::new("alice", None, None).unwrap()),
        action: Action::without_namespace("read").unwrap(),
        resource: Resource::new("Document", "report").unwrap(),
    }
}

#[test]
fn editing_wire_evidence_does_not_change_a_trusted_allow() {
    let engine =
        PolicyEngine::new_from_str("@id(\"allow_read\") permit(principal, action, resource);")
            .unwrap();
    let diagnostics = engine.evaluate_with_diagnostics(&request()).unwrap();
    let decision = diagnostics.decision();
    let issued_version = engine.current_version();
    let mut dto = DecisionDto::from(decision);

    match &mut dto {
        DecisionDto::Allow { policies, version } => {
            *policies = PermitPolicies::empty();
            version.generation = u64::MAX;
            version.hash = "forged".into();
        }
        _ => panic!("expected an allow DTO"),
    }

    assert!(decision.is_allowed());
    assert_eq!(decision.permit_policies().unwrap().ids(), ["allow_read"]);
    assert_eq!(decision.version(), &issued_version);
    assert!(diagnostics.matched_forbid_policy_ids().is_empty());
    assert_ne!(DecisionDto::from(decision), dto);
}

#[test]
fn trusted_decisions_preserve_allow_and_deny_wire_shapes() {
    for (policies, allowed) in [
        ("permit(principal, action, resource);", true),
        ("forbid(principal, action, resource);", false),
    ] {
        let engine = PolicyEngine::new_from_str(policies).unwrap();
        let decision = engine.evaluate(&request()).unwrap();
        let serialized = serde_json::to_value(&decision).unwrap();
        let expected = if allowed {
            serde_json::json!({"Allow": {
                "policies": decision.permit_policies().unwrap(),
                "version": engine.current_version(),
            }})
        } else {
            serde_json::json!({"Deny": {"version": engine.current_version()}})
        };

        assert_eq!(decision.is_allowed(), allowed);
        assert_eq!(serialized, expected);
        let dto: DecisionDto = serde_json::from_value(serialized).unwrap();
        assert_eq!(dto, DecisionDto::from(&decision));
        assert_eq!(decision.clone(), decision);
    }
}

#[test]
fn trusted_decision_schema_matches_its_wire_dto() {
    let mut decision = serde_json::to_value(Decision::schema()).unwrap();
    let mut dto = serde_json::to_value(DecisionDto::schema()).unwrap();
    // Trust semantics differ in rustdoc; the serialized schema must not.
    decision.as_object_mut().unwrap().remove("description");
    dto.as_object_mut().unwrap().remove("description");
    assert_eq!(decision, dto);
    assert_eq!(decision["oneOf"].as_array().unwrap().len(), 2);
}

#[test]
fn decision_openapi_registers_transitive_wire_schemas() {
    #[derive(OpenApi)]
    #[openapi(components(schemas(DecisionDiagnostics)))]
    struct ApiDoc;

    let document = serde_json::to_value(ApiDoc::openapi()).unwrap();
    let schemas = document["components"]["schemas"].as_object().unwrap();
    for name in [
        "DecisionDiagnostics",
        "Decision",
        "PermitPolicies",
        "PermitPolicy",
        "PolicyVersion",
        "LabelSetVersion",
    ] {
        assert!(schemas.contains_key(name), "missing {name} schema");
    }
    assert_eq!(schemas["Decision"]["oneOf"].as_array().unwrap().len(), 2);
}
