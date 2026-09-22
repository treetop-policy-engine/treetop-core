#[allow(dead_code)] // Shared setup functions also serve the Gungraun target.
#[path = "permit_metadata/support.rs"]
mod support;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;
use support::Fixture;

fn permit_metadata(c: &mut Criterion) {
    for (name, many_matches) in [("one_match", false), ("64_matches", true)] {
        let fixture = Fixture::new(many_matches);
        let mut group = c.benchmark_group(format!("permit_metadata/{name}"));
        group.sample_size(20);
        group.warm_up_time(Duration::from_secs(1));
        group.measurement_time(Duration::from_secs(2));
        group.bench_function("load", |b| b.iter(|| black_box(fixture.engine())));
        group.bench_function("first_evaluation", |b| {
            b.iter_batched_ref(
                || fixture.engine(),
                |engine| black_box(engine.evaluate(black_box(&fixture.request)).unwrap()),
                // Evaluate immediately after each engine's setup. Batching
                // many unevaluated engines adds unrelated cache pressure.
                BatchSize::PerIteration,
            );
        });
        let engine = fixture.engine();
        let decision = engine.evaluate(&fixture.request).unwrap();
        assert_eq!(
            decision.permit_policies().unwrap().len(),
            if many_matches { 64 } else { 1 }
        );
        group.bench_function("repeated_evaluation", |b| {
            b.iter(|| black_box(engine.evaluate(black_box(&fixture.request)).unwrap()));
        });
        group.bench_function("serialize_decision", |b| {
            b.iter(|| black_box(serde_json::to_vec(black_box(&decision)).unwrap()));
        });
        group.bench_function("materialize_decision_value", |b| {
            b.iter(|| black_box(serde_json::to_value(black_box(&decision)).unwrap()));
        });
        group.finish();
    }
}

criterion_group!(benches, permit_metadata);
criterion_main!(benches);
