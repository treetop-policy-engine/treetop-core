use std::sync::Arc;
use treetop_core::{
    AttrValue, LabelRegistry, LabelRegistryBuilder, LabelTarget, Labeler, Resource,
};

struct EmptyLabeler(LabelTarget);

impl Labeler for EmptyLabeler {
    fn target(&self) -> &LabelTarget {
        &self.0
    }
    fn derive(&self, _: &Resource) -> Option<AttrValue> {
        None
    }
}

pub fn prepare_labeler() -> Arc<dyn Labeler> {
    Arc::new(EmptyLabeler(LabelTarget::new("Host", "labels").unwrap()))
}

pub fn build_registry(labeler: Arc<dyn Labeler>) -> LabelRegistry {
    LabelRegistryBuilder::new()
        .add_labeler(labeler)
        .build()
        .unwrap()
}
