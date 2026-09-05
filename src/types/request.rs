//! Authorization request type.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::action::Action;
use super::principal::Principal;
use super::resource::Resource;

/// The API-level request, with strongly-typed principal, action, groups, resource, and context.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
pub struct Request {
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CedarAtom;
    use crate::types::{Action, Group, User};
    use insta::assert_json_snapshot;

    #[test]
    fn assert_request_serialization() {
        let request = Request {
            principal: Principal::User(User::new("alice", None, None).unwrap()),
            action: Action::new("create", None).unwrap(),
            resource: Resource::new("Host", "web-01").unwrap(),
        };
        let serialized = serde_json::to_value(&request).unwrap();

        insta::with_settings!({sort_maps => true}, {
            assert_json_snapshot!(serialized);
        });
    }

    #[test]
    fn test_request_with_group_principal() {
        let request = Request {
            principal: Principal::Group(Group::new("admins", None).unwrap()),
            action: Action::new("delete", None).unwrap(),
            resource: Resource::new("Database", "prod").unwrap(),
        };

        let serialized = serde_json::to_value(&request).unwrap();
        assert!(serialized["principal"].to_string().contains("admins"));
    }

    #[test]
    fn test_request_with_namespaced_types() {
        let request = Request {
            principal: Principal::User(
                User::new("alice", None, Some(vec!["App".to_string()])).unwrap(),
            ),
            action: Action::new("create", Some(vec!["Admin".to_string()])).unwrap(),
            resource: Resource::new("Host", "web-01").unwrap(),
        };

        let serialized = serde_json::to_value(&request).unwrap();
        let deserialized: Request = serde_json::from_value(serialized).unwrap();
        assert_eq!(
            request.principal.cedar_id(),
            deserialized.principal.cedar_id()
        );
    }

    #[test]
    fn test_request_with_resource_attributes() {
        use crate::types::AttrValue;
        let request = Request {
            principal: Principal::User(User::new("alice", None, None).unwrap()),
            action: Action::new("read", None).unwrap(),
            resource: Resource::new("Document", "doc1")
                .unwrap()
                .with_attr("owner", AttrValue::String("alice".to_string()))
                .with_attr("public", AttrValue::Bool(false)),
        };

        assert_eq!(request.resource.id(), "doc1");
    }

    #[test]
    fn test_request_clone() {
        let request = Request {
            principal: Principal::User(User::new("alice", None, None).unwrap()),
            action: Action::new("read", None).unwrap(),
            resource: Resource::new("File", "file1").unwrap(),
        };

        let cloned = request.clone();
        assert_eq!(request.principal.cedar_id(), cloned.principal.cedar_id());
        assert_eq!(request.action.cedar_id(), cloned.action.cedar_id());
        assert_eq!(request.resource.id(), cloned.resource.id());
    }

    #[test]
    fn test_request_debug() {
        let request = Request {
            principal: Principal::User(User::new("alice", None, None).unwrap()),
            action: Action::new("read", None).unwrap(),
            resource: Resource::new("File", "file1").unwrap(),
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("Request"));
    }
}
