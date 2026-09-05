#[path = "label_registry/support.rs"]
mod support;

use criterion::{Criterion, criterion_group, criterion_main};

fn benchmark_registry(c: &mut Criterion) {
    c.bench_function("label_registry_build", |b| b.iter(support::build_registry));
}

criterion_group!(benches, benchmark_registry);
criterion_main!(benches);
