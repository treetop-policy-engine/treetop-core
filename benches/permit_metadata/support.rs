use treetop_core::{Action, AttrValue, Decision, PolicyEngine, Principal, Request, Resource, User};

/// Stable fixture v1: 64 permits with either one or all policies matching.
pub struct Fixture {
    pub text: String,
    pub request: Request,
}

impl Fixture {
    pub fn new(many_matches: bool) -> Self {
        install_sink();
        let mut text = String::new();
        for index in 0..64 {
            let user = if many_matches || index == 0 {
                "alice".into()
            } else {
                format!("noise-{index}")
            };
            text.push_str(&format!(
                "@id(\"permit-{index}\") permit(principal == User::\"{user}\", action == App::Action::\"read\", resource is App::Document) when {{ resource.visible && resource.tags.contains(\"public\") }};\n"
            ));
        }
        Self {
            text,
            request: Request {
                principal: Principal::User(User::new("alice", None, None).unwrap()),
                action: Action::new("read", Some(vec!["App".into()])).unwrap(),
                resource: Resource::new("App::Document", "document")
                    .unwrap()
                    .with_attr("visible", AttrValue::Bool(true))
                    .with_attr(
                        "tags",
                        AttrValue::Set(vec![AttrValue::String("public".into())]),
                    ),
            },
        }
    }

    pub fn engine(&self) -> PolicyEngine {
        PolicyEngine::new_from_str(&self.text).unwrap()
    }
}

pub struct Prepared {
    pub fixture: Fixture,
    pub engine: PolicyEngine,
}

impl Prepared {
    pub fn new(many_matches: bool) -> Self {
        let fixture = Fixture::new(many_matches);
        let engine = fixture.engine();
        Self { fixture, engine }
    }

    pub fn evaluate(&self) -> Decision {
        self.engine.evaluate(&self.fixture.request).unwrap()
    }
}

pub fn sparse() -> Prepared {
    Prepared::new(false)
}

pub fn sparse_fixture() -> Fixture {
    Fixture::new(false)
}
pub fn dense() -> Prepared {
    Prepared::new(true)
}
pub fn warm_sparse() -> Prepared {
    let scenario = sparse();
    let _ = scenario.evaluate();
    scenario
}
pub fn warm_dense() -> Prepared {
    let scenario = dense();
    let _ = scenario.evaluate();
    scenario
}
pub fn sparse_decision() -> (Prepared, Decision) {
    let scenario = sparse();
    let decision = scenario.evaluate();
    (scenario, decision)
}
pub fn dense_decision() -> (Prepared, Decision) {
    let scenario = dense();
    let decision = scenario.evaluate();
    (scenario, decision)
}

#[cfg(feature = "observability")]
fn install_sink() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use treetop_core::{
        EvaluationObservation, EvaluationStats, MetricsSink, ReloadStats, set_sink,
    };
    struct Sink(AtomicU64);
    impl MetricsSink for Sink {
        fn on_evaluation_observation(&self, _: &EvaluationObservation<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn on_evaluation(&self, _: &EvaluationStats) {}
        fn on_reload(&self, _: &ReloadStats) {}
    }
    set_sink(Arc::new(Sink(AtomicU64::new(0))));
}

#[cfg(not(feature = "observability"))]
fn install_sink() {}
