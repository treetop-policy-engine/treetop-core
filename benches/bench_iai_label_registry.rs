#[path = "label_registry/support.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_core::LabelRegistry;

// Keep this as one cold construction: setup or repeated iterations would hide
// accidental initialization of Cedar's extension machinery inside validation.
#[library_benchmark]
fn build_cold_registry() -> LabelRegistry {
    support::build_registry()
}

library_benchmark_group!(name = label_registry; benchmarks = build_cold_registry);
main!(library_benchmark_groups = label_registry);
