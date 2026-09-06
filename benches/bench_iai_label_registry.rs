#[path = "label_registry/support.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use std::sync::Arc;
use treetop_core::{LabelRegistry, Labeler};

// Registration consumes a validated declaration. The separate cold target
// benchmark measures the parsing work required before this boundary.
#[library_benchmark(setup = support::prepare_labeler)]
fn build_cold_registry(labeler: Arc<dyn Labeler>) -> LabelRegistry {
    support::build_registry(labeler)
}

library_benchmark_group!(name = label_registry; benchmarks = build_cold_registry);
main!(library_benchmark_groups = label_registry);
