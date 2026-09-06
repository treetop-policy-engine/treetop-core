#[path = "label_registry/support.rs"]
mod support;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

fn benchmark_registry(c: &mut Criterion) {
    c.bench_function("label_registry_build", |b| {
        b.iter_batched(
            support::prepare_labeler,
            support::build_registry,
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark_registry);
criterion_main!(benches);
