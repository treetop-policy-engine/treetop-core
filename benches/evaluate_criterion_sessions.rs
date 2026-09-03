#[allow(dead_code)] // Shared fixture also serves the other benchmark binaries.
mod evaluate_common;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use evaluate_common::{build_scenario, wide_matrix_specs_baseline};
use std::hint::black_box;
use treetop_core::Decision;

fn score(decision: Decision) -> usize {
    decision
        .permit_policies()
        .map_or(0, |policies| policies.len())
}

fn benchmark_evaluate_sessions(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate_sessions");
    group.sample_size(40);

    let scenarios: Vec<_> = wide_matrix_specs_baseline()
        .into_iter()
        .map(build_scenario)
        .collect();

    for scenario in &scenarios {
        group.bench_function(BenchmarkId::new("live", scenario.name), |b| {
            b.iter(|| {
                let decision = scenario
                    .engine
                    .evaluate(black_box(&scenario.request))
                    .expect("benchmark requests are valid");
                black_box(score(decision));
            });
        });

        let session = scenario.engine.session();
        group.bench_function(BenchmarkId::new("session", scenario.name), |b| {
            b.iter(|| {
                let decision = session
                    .evaluate(black_box(&scenario.request))
                    .expect("benchmark requests are valid");
                black_box(score(decision));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, benchmark_evaluate_sessions);
criterion_main!(benches);
