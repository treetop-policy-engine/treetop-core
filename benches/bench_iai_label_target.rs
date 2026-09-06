use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_core::LabelTarget;

// Keep target parsing cold so initialization of Cedar validation remains visible.
#[library_benchmark]
fn parse_cold_target() -> LabelTarget {
    LabelTarget::new("App::Host", "labels").unwrap()
}

library_benchmark_group!(name = label_target; benchmarks = parse_cold_target);
main!(library_benchmark_groups = label_target);
