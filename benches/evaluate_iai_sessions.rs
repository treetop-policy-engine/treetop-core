#[allow(dead_code)] // Shared fixture also serves the other benchmark binaries.
mod evaluate_common;

use evaluate_common::{Scenario, build_scenario, iai_matrix_specs_baseline};
use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use std::sync::LazyLock;
use treetop_core::{Decision, EvaluationSession, Request};

const IAI_INNER_ITERS: usize = 1_000;

fn score(decision: Decision) -> usize {
    decision
        .permit_policies()
        .map_or(0, |policies| policies.len())
}

fn run_many_live(scenario: &Scenario) -> usize {
    let mut acc = 0usize;
    for _ in 0..IAI_INNER_ITERS {
        let decision = scenario
            .engine
            .evaluate(black_box(&scenario.request))
            .expect("benchmark requests are valid");
        acc = acc.wrapping_add(black_box(score(decision)));
    }
    acc
}

fn run_many_session(session: &EvaluationSession, request: &Request) -> usize {
    let mut acc = 0usize;
    for _ in 0..IAI_INNER_ITERS {
        let decision = session
            .evaluate(black_box(request))
            .expect("benchmark requests are valid");
        acc = acc.wrapping_add(black_box(score(decision)));
    }
    acc
}

static SMALL_ALLOW: LazyLock<Scenario> =
    LazyLock::new(|| build_scenario(iai_matrix_specs_baseline()[0]));
static SMALL_ALLOW_SESSION: LazyLock<EvaluationSession> =
    LazyLock::new(|| SMALL_ALLOW.engine.session());

#[library_benchmark]
fn iai_small_allow_live() -> usize {
    run_many_live(&SMALL_ALLOW)
}

#[library_benchmark]
fn iai_small_allow_session() -> usize {
    run_many_session(&SMALL_ALLOW_SESSION, &SMALL_ALLOW.request)
}

library_benchmark_group!(
    name = evaluate_sessions;
    benchmarks = iai_small_allow_live, iai_small_allow_session
);

main!(library_benchmark_groups = evaluate_sessions);
