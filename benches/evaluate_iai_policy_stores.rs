mod policy_store_common;

use gungraun::{library_benchmark, library_benchmark_group, main};
use policy_store_common::{PolicyStoreScenario, build_policy_store_scenario};
use std::hint::black_box;
use std::sync::LazyLock;

const INNER_ITERS: usize = 100;

static SCENARIO: LazyLock<PolicyStoreScenario> =
    LazyLock::new(|| build_policy_store_scenario(8, 32));

#[library_benchmark]
fn evaluate_selected_policy_store() -> usize {
    let mut allowed = 0usize;
    for _ in 0..INNER_ITERS {
        let decision = SCENARIO
            .scoped
            .evaluate(black_box(&SCENARIO.request))
            .expect("benchmark request must be valid");
        allowed += usize::from(decision.is_allowed());
    }
    black_box(allowed)
}

#[library_benchmark]
fn evaluate_monolithic_policy_set() -> usize {
    let mut allowed = 0usize;
    for _ in 0..INNER_ITERS {
        let decision = SCENARIO
            .monolithic
            .evaluate(black_box(&SCENARIO.request))
            .expect("benchmark request must be valid");
        allowed += usize::from(decision.is_allowed());
    }
    black_box(allowed)
}

library_benchmark_group!(
    name = evaluate_policy_stores;
    benchmarks = evaluate_monolithic_policy_set, evaluate_selected_policy_store
);

main!(library_benchmark_groups = evaluate_policy_stores);
