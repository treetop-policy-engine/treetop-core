mod policy_store_common;

use criterion::{Criterion, criterion_group, criterion_main};
use policy_store_common::build_policy_store_scenario;
use std::hint::black_box;

fn benchmark_evaluate_policy_stores(c: &mut Criterion) {
    let scenario = build_policy_store_scenario(16, 128);
    let mut group = c.benchmark_group("evaluate_policy_stores_2048_total_128_selected");
    group.sample_size(20);

    group.bench_function("monolithic", |b| {
        b.iter(|| {
            black_box(
                scenario
                    .monolithic
                    .evaluate(black_box(&scenario.request))
                    .expect("benchmark request must be valid"),
            );
        });
    });
    group.bench_function("scoped", |b| {
        b.iter(|| {
            black_box(
                scenario
                    .scoped
                    .evaluate(black_box(&scenario.request))
                    .expect("benchmark request must be valid"),
            );
        });
    });
    group.finish();
}

criterion_group!(benches, benchmark_evaluate_policy_stores);
criterion_main!(benches);
