//! Qualified identifiers for Cedar entities with namespace support.

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use utoipa::ToSchema;

use cedar_policy::{EntityId, EntityTypeName, EntityUid};

use crate::error::PolicyError;

mod private {
    pub trait Sealed {}
}

/// Marker type for Users
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum UserMarker {}

/// Marker type for Group
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum GroupMarker {}

/// Marker type for Actions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum ActionMarker {}

impl private::Sealed for UserMarker {}
impl private::Sealed for GroupMarker {}
impl private::Sealed for ActionMarker {}

/// Sealed marker implemented by the built-in Cedar identity kinds.
pub trait QualifiedIdKind: private::Sealed {
    /// Cedar entity basename represented by this marker.
    const CEDAR_TYPE: &'static str;
}

impl QualifiedIdKind for UserMarker {
    const CEDAR_TYPE: &'static str = "User";
}

impl QualifiedIdKind for GroupMarker {
    const CEDAR_TYPE: &'static str = "Group";
}

impl QualifiedIdKind for ActionMarker {
    const CEDAR_TYPE: &'static str = "Action";
}

/// A fully qualified, validated identifier with its parsed Cedar UID cached.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct QualifiedId<T: QualifiedIdKind> {
    id: String,
    namespace: Vec<String>,
    #[serde(skip)]
    _marker: PhantomData<T>,
    #[serde(skip)]
    uid: EntityUid,
}

impl<T: QualifiedIdKind> PartialEq for QualifiedId<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.namespace == other.namespace
    }
}

impl<T: QualifiedIdKind> Eq for QualifiedId<T> {}

impl<T: QualifiedIdKind> Hash for QualifiedId<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.namespace.hash(state);
    }
}

impl<T: QualifiedIdKind> QualifiedId<T> {
    /// Construct a non-empty identifier with a valid Cedar namespace.
    pub fn new(id: impl Into<String>, namespace: Option<Vec<String>>) -> Result<Self, PolicyError> {
        let id = id.into();
        if id.is_empty() {
            return Err(PolicyError::InvalidFormat(
                "entity identifier cannot be empty".to_string(),
            ));
        }
        let namespace = namespace.unwrap_or_default();
        let type_name = Self::validate_namespace_with_type(&namespace)?;
        let uid = EntityUid::from_type_name_and_id(type_name, EntityId::new(&id));
        Ok(Self {
            id,
            namespace,
            _marker: PhantomData,
            uid,
        })
    }

    /// Backward-compatible name for [`Self::new`].
    pub fn try_new(
        id: impl Into<String>,
        namespace: Option<Vec<String>>,
    ) -> Result<Self, PolicyError> {
        Self::new(id, namespace)
    }

    /// Get the raw id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the namespace path.
    pub fn namespace(&self) -> &[String] {
        &self.namespace
    }

    /// Render the canonical Cedar entity UID.
    pub fn fmt_qualified(&self) -> String {
        self.uid.to_string()
    }

    pub(crate) fn cedar_entity_uid(&self) -> &EntityUid {
        &self.uid
    }

    fn validate_namespace_with_type(namespace: &[String]) -> Result<EntityTypeName, PolicyError> {
        let type_name = if namespace.is_empty() {
            T::CEDAR_TYPE.to_string()
        } else {
            format!("{}::{}", namespace.join("::"), T::CEDAR_TYPE)
        };
        type_name.parse().map_err(|e| {
            PolicyError::InvalidFormat(format!("invalid Cedar entity type '{type_name}': {e}"))
        })
    }
}

#[derive(Deserialize)]
struct QualifiedIdRepr {
    id: String,
    #[serde(default)]
    namespace: Vec<String>,
}

impl<'de, T: QualifiedIdKind> Deserialize<'de> for QualifiedId<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = QualifiedIdRepr::deserialize(deserializer)?;
        Self::new(repr.id, Some(repr.namespace)).map_err(D::Error::custom)
    }
}

impl<T: QualifiedIdKind> Display for QualifiedId<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // We don't know `T`'s name here; we'll implement Display on the wrappers.
        write!(f, "{}", self.id)
    }
}

/// A User's fully‐qualified ID.
pub type UserId = QualifiedId<UserMarker>;

/// A Group's fully‐qualified ID.
pub type GroupId = QualifiedId<GroupMarker>;

/// An Action's fully‐qualified ID.
pub type ActionId = QualifiedId<ActionMarker>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_qualified_id_display() {
        let id: UserId = QualifiedId::new("alice", None).unwrap();
        assert_eq!(format!("{}", id), "alice");
    }

    #[test]
    fn test_qualified_id_fmt_qualified() {
        let id: UserId = QualifiedId::new("alice", Some(vec!["Infra".to_string()])).unwrap();
        assert_eq!(id.fmt_qualified(), r#"Infra::User::"alice""#);
    }

    #[test]
    fn test_qualified_id_namespace_accessor() {
        let id: UserId =
            QualifiedId::new("alice", Some(vec!["App".to_string(), "Core".to_string()])).unwrap();
        assert_eq!(id.namespace(), &["App".to_string(), "Core".to_string()]);
    }

    #[test]
    fn test_qualified_id_empty_namespace() {
        let id: UserId = QualifiedId::new("alice", None).unwrap();
        assert_eq!(id.namespace(), &[] as &[String]);
        assert_eq!(id.fmt_qualified(), r#"User::"alice""#);
    }

    #[test]
    fn test_qualified_id_multiple_namespaces() {
        let id: ActionId = QualifiedId::new(
            "delete",
            Some(vec![
                "App".to_string(),
                "Admin".to_string(),
                "Actions".to_string(),
            ]),
        )
        .unwrap();
        assert_eq!(
            id.fmt_qualified(),
            r#"App::Admin::Actions::Action::"delete""#
        );
    }

    #[test]
    fn test_qualified_id_with_special_chars() {
        let id: UserId = QualifiedId::new("alice@example.com", None).unwrap();
        assert_eq!(id.id(), "alice@example.com");
    }

    #[test]
    fn test_qualified_id_types() {
        let user_id: UserId = QualifiedId::new("alice", None).unwrap();
        let group_id: GroupId = QualifiedId::new("admins", None).unwrap();
        let action_id: ActionId = QualifiedId::new("read", None).unwrap();

        assert_eq!(user_id.id(), "alice");
        assert_eq!(group_id.id(), "admins");
        assert_eq!(action_id.id(), "read");
    }

    #[test]
    fn test_qualified_id_clone() {
        let original: UserId = QualifiedId::new("alice", Some(vec!["App".to_string()])).unwrap();
        let cloned = original.clone();
        assert_eq!(original.id(), cloned.id());
        assert_eq!(original.namespace(), cloned.namespace());
    }

    #[test]
    fn test_qualified_id_serialization() {
        let id: UserId = QualifiedId::new("alice", Some(vec!["App".to_string()])).unwrap();
        let serialized = serde_json::to_value(&id).unwrap();
        let deserialized: UserId = serde_json::from_value(serialized).unwrap();
        assert_eq!(id.id(), deserialized.id());
        assert_eq!(id.namespace(), deserialized.namespace());
    }

    #[test]
    fn cached_uid_does_not_change_value_semantics() {
        let cached: UserId = QualifiedId::new("alice", Some(vec!["App".to_string()])).unwrap();
        let uncached = cached.clone();
        cached.cedar_entity_uid();

        assert_eq!(cached, uncached);
        assert_eq!(
            serde_json::to_value(&cached).unwrap(),
            serde_json::to_value(&uncached).unwrap()
        );

        let mut cached_hasher = DefaultHasher::new();
        cached.hash(&mut cached_hasher);
        let mut uncached_hasher = DefaultHasher::new();
        uncached.hash(&mut uncached_hasher);
        assert_eq!(cached_hasher.finish(), uncached_hasher.finish());
    }

    #[test]
    fn cached_uid_initialization_is_thread_safe() {
        let id = Arc::new(
            UserId::new("alice", Some(vec!["App".to_string(), "Core".to_string()])).unwrap(),
        );
        let handles = (0..8)
            .map(|_| {
                let id = Arc::clone(&id);
                thread::spawn(move || id.cedar_entity_uid().clone())
            })
            .collect::<Vec<_>>();

        for handle in handles {
            assert_eq!(
                handle.join().unwrap().to_string(),
                r#"App::Core::User::"alice""#
            );
        }
    }

    #[test]
    fn test_qualified_id_empty_id() {
        let result: Result<UserId, _> = QualifiedId::new("", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_qualified_id_escapes_entity_id() {
        let id: UserId = QualifiedId::try_new("a\"b\\c", None).unwrap();
        assert_eq!(id.fmt_qualified(), r#"User::"a\"b\\c""#);
        assert_eq!(id.cedar_entity_uid().id().unescaped(), "a\"b\\c");
    }

    #[test]
    fn test_qualified_id_try_new_rejects_invalid_namespace() {
        let result: Result<UserId, _> =
            QualifiedId::try_new("alice", Some(vec!["invalid namespace".into()]));
        assert!(result.is_err());
    }

    #[test]
    fn deserialization_cannot_bypass_validation() {
        assert!(serde_json::from_value::<UserId>(serde_json::json!({"id": ""})).is_err());
        assert!(
            serde_json::from_value::<UserId>(serde_json::json!({
                "id": "alice",
                "namespace": ["invalid namespace"]
            }))
            .is_err()
        );
    }

    #[test]
    fn test_qualified_id_from_string() {
        let id: UserId = QualifiedId::new("alice".to_string(), None).unwrap();
        assert_eq!(id.id(), "alice");
    }
}
