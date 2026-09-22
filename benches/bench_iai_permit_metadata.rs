#[path = "permit_metadata/support.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use support::{Fixture, Prepared};
use treetop_core::{Decision, PolicyEngine};

// Return owned setup data as well as results, so its destruction happens after
// the measured function. First-evaluation cases have never evaluated the engine.
#[library_benchmark(setup = support::sparse_fixture)]
fn load(fixture: Fixture) -> (Fixture, PolicyEngine) {
    let engine = fixture.engine();
    black_box((fixture, engine))
}

#[library_benchmark]
#[bench::one_match(setup = support::sparse)]
#[bench::many_matches(setup = support::dense)]
fn first_evaluation(scenario: Prepared) -> (Prepared, Decision) {
    let decision = scenario.evaluate();
    black_box((scenario, decision))
}

#[library_benchmark]
#[bench::one_match(setup = support::warm_sparse)]
#[bench::many_matches(setup = support::warm_dense)]
fn repeated_evaluation(scenario: Prepared) -> (Prepared, usize) {
    let mut score = 0;
    for _ in 0..100 {
        score += scenario.evaluate().permit_policies().unwrap().len();
    }
    black_box((scenario, score))
}

#[library_benchmark]
#[bench::one_match(setup = support::sparse_decision)]
#[bench::many_matches(setup = support::dense_decision)]
fn serialize_decision(input: (Prepared, Decision)) -> ((Prepared, Decision), Vec<u8>) {
    let bytes = serde_json::to_vec(&input.1).unwrap();
    black_box((input, bytes))
}

#[library_benchmark]
#[bench::one_match(setup = support::sparse_decision)]
#[bench::many_matches(setup = support::dense_decision)]
fn materialize_decision_value(
    input: (Prepared, Decision),
) -> ((Prepared, Decision), serde_json::Value) {
    let value = serde_json::to_value(&input.1).unwrap();
    black_box((input, value))
}

library_benchmark_group!(name = permit_metadata; benchmarks = load, first_evaluation, repeated_evaluation, serialize_decision, materialize_decision_value);
main!(library_benchmark_groups = permit_metadata);
