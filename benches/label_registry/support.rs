use std::sync::Arc;
use treetop_core::{AttrValue, LabelRegistry, LabelRegistryBuilder, Labeler, Resource};

struct EmptyLabeler;

impl Labeler for EmptyLabeler {
    fn applies_to(&self, _: &str) -> bool {
        true
    }

    fn output(&self) -> &str {
        "labels"
    }

    fn derive(&self, _: &Resource) -> Option<AttrValue> {
        None
    }
}

pub fn build_registry() -> LabelRegistry {
    LabelRegistryBuilder::new()
        .add_labeler(Arc::new(EmptyLabeler))
        .build()
        .unwrap()
}
