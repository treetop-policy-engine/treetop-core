//! Count Rust allocation payloads separately from allocator-retained RSS.
//! Instrumentation is confined to this executable; never use its wall times as
//! performance results. Each mode must run in a fresh process.

#[allow(dead_code)] // Timing helpers are used by the companion concurrency probe.
#[path = "operational/support.rs"]
mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use support::{memory, mib, positive_env};
use treetop_core::bench_helpers::policy_scale::{
    CORPUS_VERSION, ScaleCorpus, configured_policy_count,
};
use treetop_core::bench_helpers::retain_policy_metadata;
use treetop_core::{PolicyEngine, Schema, compile_policy, compile_policy_with_schema};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
    ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
}

// SAFETY: Every operation forwards the identical pointer and layout to System.
// Accounting uses only atomics, never allocates or dereferences an allocation,
// and records changes only after successful allocation/reallocation.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the valid allocation layout unchanged.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the valid allocation layout unchanged.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: Pointer ownership and original layout are the caller's contract.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: Forward the live allocation and requested size unchanged.
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            allocated(new_size);
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Sample {
    name: &'static str,
    live: usize,
    peak: usize,
    allocations: usize,
    memory: support::Memory,
}

fn sample(name: &'static str) -> Sample {
    // Capture counters before /proc parsing allocates temporary buffers.
    let live = LIVE.load(Ordering::Relaxed);
    let peak = PEAK.load(Ordering::Relaxed);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let memory = memory();
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    Sample {
        name,
        live,
        peak,
        allocations,
        memory,
    }
}

fn main() {
    let count = configured_policy_count();
    let reloads = positive_env("TREETOP_OPERATIONAL_RELOADS", 3);
    let mode = std::env::var("TREETOP_MEMORY_MODE").unwrap_or_else(|_| "metadata".into());
    let mut samples = Vec::with_capacity(2 * reloads + 16);
    samples.push(sample("Process initialized"));
    let corpus = ScaleCorpus::new(count, 0);
    samples.push(sample("Input corpus"));
    match mode.as_str() {
        "parse" => {
            let set = compile_policy(&corpus.policy_text).unwrap();
            samples.push(sample("Compiled Cedar policies"));
            drop(set);
            samples.push(sample("Policies dropped"));
        }
        "validated" | "metadata" | "metadata-parts" => {
            let schema: Schema = corpus.schema_text.parse().unwrap();
            samples.push(sample("Schema"));
            let set = compile_policy_with_schema(&corpus.policy_text, &schema).unwrap();
            samples.push(sample("Validated Cedar policies"));
            if mode.starts_with("metadata") {
                let mut metadata = retain_policy_metadata(&set);
                samples.push(sample("Permit and forbid metadata retained"));
                if mode == "metadata-parts" {
                    metadata.release_json();
                    samples.push(sample("Metadata JSON released"));
                    metadata.release_literals();
                    samples.push(sample("Metadata literals released"));
                    metadata.release_ids();
                    samples.push(sample("Returned IDs and forbid map released"));
                }
                drop(metadata);
                samples.push(sample("Metadata dropped"));
            }
            drop(set);
            drop(schema);
            samples.push(sample("Policies and schema dropped"));
        }
        "engine" | "reload" | "retained" => {
            let engine = PolicyEngine::new_from_str_with_cedarschema(
                &corpus.policy_text,
                &corpus.schema_text,
            )
            .unwrap();
            samples.push(sample("Engine loaded"));
            let mut retained = Vec::with_capacity(reloads);
            if mode != "engine" {
                for generation in 1..=reloads {
                    // Record generation separately so replacement text is not
                    // misattributed to compiled snapshot retention.
                    let replacement = ScaleCorpus::new(count, generation);
                    samples.push(sample("Replacement input generated"));
                    if mode == "retained" {
                        retained.push(engine.session());
                    }
                    engine.reload_from_str(&replacement.policy_text).unwrap();
                    drop(replacement);
                    samples.push(sample("Reload complete; replacement input dropped"));
                }
            }
            drop(retained);
            samples.push(sample("Retained sessions dropped"));
            drop(engine);
            samples.push(sample("Engine dropped"));
        }
        other => panic!("unknown memory mode {other}"),
    }
    drop(corpus);
    samples.push(sample("Input corpus dropped"));
    println!(
        "# Policy allocation probe\n\nCorpus v{CORPUS_VERSION}; policies: {count}; mode: {mode}; reloads: {reloads}.\n\nBuild: {:?}.",
        treetop_core::build_info()
    );
    println!(
        "\n| Phase | Live payload MiB | Interval peak payload MiB | Allocation/reallocation calls | RSS MiB | Process peak RSS MiB |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: |");
    for row in samples {
        println!(
            "| {} | {:.3} | {:.3} | {} | {} | {} |",
            row.name,
            row.live as f64 / 1048576.0,
            row.peak as f64 / 1048576.0,
            row.allocations,
            mib(row.memory.resident_kib),
            mib(row.memory.peak_kib)
        );
    }
    println!(
        "\nPayload counters track successful Rust System allocations, excluding allocator bookkeeping, stacks, and direct mappings. Interval peaks include fixture and retained state already live at interval start; do not sum peaks. RSS minus payload is not a precise allocator-retention measure. Dropped phases reveal live versus retained memory. This instrumented executable does not provide comparable latency measurements."
    );
}
