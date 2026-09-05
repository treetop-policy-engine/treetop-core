use std::collections::HashMap;

use cedar_policy::{EntityUid, RestrictedExpression};

/// Anything that can become a Cedar‐typed atom, e.g. `User::"alice"`,
/// `Action::"foo"`, `Group::"devs"`.
///
/// Types implementing this trait can produce their Cedar identity (`cedar_id`)
/// and attributes for internal request preparation.
pub(crate) trait CedarAtom {
    /// The Cedar typename (“User”, “Action”, “Group”, etc)
    fn cedar_type() -> &'static str;

    /// Build the attributes for this Cedar atom.
    fn cedar_attr(&self) -> HashMap<String, RestrictedExpression> {
        HashMap::new()
    }

    /// Borrow the already-validated Cedar entity UID.
    fn cedar_entity_uid(&self) -> &EntityUid;

    /// The ID string, fully qualified (e.g. `User::"alice"` or `DNS::Action::"create_host"`).
    #[cfg(test)]
    fn cedar_id(&self) -> String;
}
