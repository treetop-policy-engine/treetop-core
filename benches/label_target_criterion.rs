use criterion::{Criterion, criterion_group, criterion_main};
use treetop_core::LabelTarget;

fn benchmark_target(c: &mut Criterion) {
    c.bench_function("label_target_parse", |b| {
        b.iter(|| LabelTarget::new("App::Host", "labels").unwrap())
    });
}

criterion_group!(benches, benchmark_target);
criterion_main!(benches);
