use cedar_policy::{
    ContextCreationError, EntityAttrEvaluationError, ParseErrors, RequestValidationError,
    entities_errors::EntitiesError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Policy evaluation and validation errors.
///
/// Variants correspond to Cedar parse/eval errors and library validation
/// errors. Call sites attach human-friendly context where possible.
/// For example, `EntityAttrError` wraps attribute access failures.
#[derive(Debug, Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PolicyError {
    /// Failed to parse Cedar policy text.
    #[error("failed to parse policy: {0}")]
    ParseError(String),

    /// Error during policy evaluation.
    #[error("evaluation error: {0}")]
    EvalError(String),

    /// Request validation failed (invalid principals, resources, or actions).
    #[error("request validation error: {0}")]
    RequestValidationError(String),

    /// Context creation error during request processing.
    #[error("context creation error: {0}")]
    ContextError(String),

    /// Error creating or manipulating Cedar entities.
    #[error("entity error: {0}")]
    EntityError(String),

    /// Invalid format for a Cedar construct (string parsing failure).
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// Entity attribute evaluation or access error.
    #[error("entity attribute error: {0}")]
    EntityAttrError(String),

    /// A policy-store layout or policy assignment is invalid.
    #[error("policy-store configuration error: {0}")]
    PolicyStoreConfigError(String),

    /// A request cannot be routed to exactly one configured policy store.
    #[error("policy-store routing error: {0}")]
    PolicyStoreRoutingError(String),

    /// A resource-labeling configuration violates the trusted-output contract.
    #[error("label configuration error: {0}")]
    LabelConfigError(String),
}

impl From<RequestValidationError> for PolicyError {
    fn from(err: cedar_policy::RequestValidationError) -> Self {
        PolicyError::RequestValidationError(err.to_string())
    }
}

impl From<ParseErrors> for PolicyError {
    fn from(err: ParseErrors) -> Self {
        PolicyError::ParseError(err.to_string())
    }
}

impl From<ContextCreationError> for PolicyError {
    fn from(err: ContextCreationError) -> Self {
        PolicyError::ContextError(err.to_string())
    }
}

impl From<EntityAttrEvaluationError> for PolicyError {
    fn from(err: EntityAttrEvaluationError) -> Self {
        PolicyError::EntityAttrError(err.to_string())
    }
}

impl From<EntitiesError> for PolicyError {
    fn from(err: EntitiesError) -> Self {
        PolicyError::EntityError(err.to_string())
    }
}
