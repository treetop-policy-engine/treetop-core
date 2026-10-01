use serde_json::Value;
use treetop_core::{
    Action, AttrValue, CedarIp, Decision, DecisionDiagnostics, DecisionDto, Group, Groups,
    LabelSetVersion, LabelTarget, PermitPolicies, PermitPolicy, PolicyJson, PolicyVersion,
    Principal, Request, RequestContext, Resource, User,
};
use utoipa::OpenApi;

// Exercise the same schema composition API used by downstream applications.
#[derive(OpenApi)]
#[openapi(components(schemas(
    Action,
    AttrValue,
    CedarIp,
    Decision,
    DecisionDiagnostics,
    DecisionDto,
    Group,
    Groups,
    LabelSetVersion,
    LabelTarget,
    PermitPolicies,
    PermitPolicy,
    PolicyJson,
    PolicyVersion,
    Principal,
    Request,
    RequestContext,
    Resource,
    User
)))]
struct PublicApi;

fn check_references(value: &Value, document: &Value) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                let pointer = reference.strip_prefix('#').expect("local schema reference");
                assert!(
                    document.pointer(pointer).is_some(),
                    "unresolved schema reference: {reference}"
                );
            }
            for child in object.values() {
                check_references(child, document);
            }
        }
        Value::Array(array) => {
            for child in array {
                check_references(child, document);
            }
        }
        _ => {}
    }
}

#[test]
fn public_schemas_compose_without_dangling_references() {
    let document = serde_json::to_value(PublicApi::openapi()).unwrap();
    assert_eq!(document["openapi"], "3.1.0");
    check_references(&document["components"], &document);
    let schemas = document["components"]["schemas"].as_object().unwrap();
    for name in [
        "Request",
        "Decision",
        "DecisionDto",
        "PolicyVersion",
        "PermitPolicy",
    ] {
        assert!(schemas.contains_key(name), "missing public schema: {name}");
    }
}

#[test]
fn public_schema_serialization_contract() {
    let document = serde_json::to_value(PublicApi::openapi()).unwrap();
    // Exclude document info, which includes the package version and other
    // build metadata. Components contain only static public API descriptions.
    insta::assert_json_snapshot!("public_schemas", document["components"]["schemas"]);
}
