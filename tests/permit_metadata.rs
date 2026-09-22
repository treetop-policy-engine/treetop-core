use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use std::thread;

use serde_json::json;
use treetop_core::{
    Action, AttrValue, DecisionDto, PermitPolicy, PolicyEngine, PolicyJson, Principal, Request,
    RequestContext, Resource, User, compile_policy,
};
use utoipa::PartialSchema;

fn request() -> Request {
    Request {
        principal: Principal::User(
            User::new("alice", Some(vec!["reviewers".into()]), None).unwrap(),
        ),
        action: Action::new("read", Some(vec!["App".into()])).unwrap(),
        resource: Resource::new("App::Document", "document")
            .unwrap()
            .with_attr("public", AttrValue::Bool(true))
            .with_attr(
                "labels",
                AttrValue::Set(vec![AttrValue::String("public".into())]),
            ),
    }
}

const POLICIES: &str = r#"
@id("group-read") @description("Quotes: \"read\"; Unicode: 文字")
permit(principal in Group::"reviewers", action == App::Action::"read", resource is App::Document)
when { resource.public && resource.labels.contains("public") && !(resource has metadata.owner) };
permit(principal == User::"alice", action, resource) unless { context.blocked };
@id("blocked") forbid(principal, action, resource) when { context.blocked };
"#;

#[test]
fn permit_metadata_schema_keeps_the_arbitrary_json_field() {
    let schema = serde_json::to_value(PermitPolicy::schema()).unwrap();
    let mut json_field = schema["properties"]["json"].clone();
    json_field.as_object_mut().unwrap().remove("description");
    assert_eq!(
        json_field,
        serde_json::to_value(serde_json::Value::schema()).unwrap()
    );
}

#[test]
fn decision_metadata_matches_cedar_json_and_round_trips() {
    let engine = PolicyEngine::new_from_str(POLICIES).unwrap();
    let request = request();
    let context = RequestContext::new().with_attr("blocked", AttrValue::Bool(false));
    let decision = engine.evaluate_with_context(&request, &context).unwrap();
    assert!(decision.is_allowed());
    assert_eq!(decision.version(), &engine.current_version());
    let expected: HashMap<_, _> = compile_policy(POLICIES)
        .unwrap()
        .policies()
        .map(|policy| (policy.id().to_string(), policy.to_json().unwrap()))
        .collect();
    let permits = decision.permit_policies().unwrap();
    assert_eq!(permits.len(), 2);
    for policy in permits {
        let expected = &expected[policy.cedar_id.as_ref()];
        assert_eq!(policy.json.to_value(), *expected);
        assert_eq!(
            serde_json::to_vec(&policy.json).unwrap(),
            serde_json::to_vec(expected).unwrap()
        );
    }
    let dto: DecisionDto = serde_json::from_slice(&serde_json::to_vec(&decision).unwrap()).unwrap();
    assert_eq!(dto, DecisionDto::from(&decision));
    let blocked = engine
        .evaluate_with_context_and_diagnostics(
            &request,
            &RequestContext::new().with_attr("blocked", AttrValue::Bool(true)),
        )
        .unwrap();
    assert!(!blocked.decision().is_allowed());
    assert_eq!(blocked.matched_forbid_policy_ids(), ["blocked"]);
    assert!(blocked.decision().permit_policies().is_none());
}

#[test]
fn first_concurrent_evaluations_share_prebuilt_json() {
    let engine =
        PolicyEngine::new_from_str("@id(\"read\") permit(principal,action,resource);").unwrap();
    let start = Barrier::new(8);
    let request = request();
    let decisions = thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (engine, start, request) = (&engine, &start, &request);
                scope.spawn(move || {
                    start.wait();
                    engine.evaluate(request).unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    let first = &decisions[0].permit_policies().unwrap().as_slice()[0].json;
    for decision in &decisions {
        assert!(decision.is_allowed());
        assert_eq!(decision.version(), decisions[0].version());
        assert!(Arc::ptr_eq(
            first,
            &decision.permit_policies().unwrap().as_slice()[0].json
        ));
    }
}

#[test]
fn returned_json_outlives_reload_and_engine_without_mutating_old_sessions() {
    let engine =
        PolicyEngine::new_from_str("@id(\"old\") permit(principal,action,resource);").unwrap();
    let session = engine.session();
    let request = request();
    let old = session.evaluate(&request).unwrap();
    let original = serde_json::to_value(&old).unwrap();
    assert!(engine.reload_from_str("permit (").is_err());
    assert_eq!(engine.current_version(), session.version());
    engine
        .reload_from_str("@id(\"new\") permit(principal,action,resource);")
        .unwrap();
    let new = engine.evaluate(&request).unwrap();
    assert_eq!(new.permit_policies().unwrap().ids(), ["new"]);
    assert_eq!(new.version().generation, old.version().generation + 1);
    let repeated = session.evaluate(&request).unwrap();
    assert_eq!(repeated.permit_policies().unwrap().ids(), ["old"]);
    assert_eq!(repeated.version(), old.version());
    let old_json = &old.permit_policies().unwrap().as_slice()[0].json;
    assert!(Arc::ptr_eq(
        old_json,
        &repeated.permit_policies().unwrap().as_slice()[0].json
    ));
    assert!(!Arc::ptr_eq(
        old_json,
        &new.permit_policies().unwrap().as_slice()[0].json
    ));
    drop(session);
    drop(engine);
    assert_eq!(serde_json::to_value(&old).unwrap(), original);
    let mut edited = old_json.to_value();
    edited["effect"] = json!("forbid");
    assert_ne!(PolicyJson::from(edited), **old_json);
}
