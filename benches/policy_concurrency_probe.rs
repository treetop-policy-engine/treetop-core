//! Closed-loop capacity probe. Each invocation measures one layout and mode.

#[path = "operational/support.rs"]
mod support;

use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use support::{memory, mib, percentile, positive_env};
use treetop_core::bench_helpers::operational_scale::{
    OPERATIONAL_CORPUS_VERSION, OperationalCorpus,
};
use treetop_core::{EvaluationSession, PolicyVersion, SchemaEnforcing};

#[cfg(feature = "observability")]
mod observation {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use treetop_core::{
        EvaluationObservation, EvaluationStats, MetricsSink, ReloadStats, set_sink,
    };

    #[derive(Default)]
    struct Sink(AtomicU64);
    impl MetricsSink for Sink {
        fn on_evaluation_observation(&self, _: &EvaluationObservation<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn on_evaluation(&self, _: &EvaluationStats) {}
        fn on_reload(&self, _: &ReloadStats) {}
    }
    pub fn install() {
        set_sink(Arc::new(Sink::default()));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Steady,
    Reload,
    Retained,
}

// Let scoped workers terminate even if the control thread unwinds during reload.
struct ReloadCompletion<'a>(&'a AtomicBool);

impl Drop for ReloadCompletion<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn main() {
    let stores = positive_env("TREETOP_OPERATIONAL_STORES", 8);
    let policies = positive_env("TREETOP_OPERATIONAL_POLICIES_PER_STORE", 128);
    let samples = positive_env("TREETOP_OPERATIONAL_SAMPLES", 1000);
    let reloads = positive_env("TREETOP_OPERATIONAL_RELOADS", 3);
    let layout =
        std::env::var("TREETOP_OPERATIONAL_LAYOUT").unwrap_or_else(|_| "partitioned".into());
    let partitioned = match layout.as_str() {
        "monolithic" => false,
        "partitioned" => true,
        _ => panic!("unknown layout {layout}"),
    };
    let mode = match std::env::var("TREETOP_OPERATIONAL_MODE")
        .as_deref()
        .unwrap_or("steady")
    {
        "steady" => Mode::Steady,
        "reload" => Mode::Reload,
        "retained" => Mode::Retained,
        other => panic!("unknown mode {other}"),
    };
    let workers: Vec<usize> = std::env::var("TREETOP_OPERATIONAL_WORKERS")
        .unwrap_or_else(|_| "1,2,4,8,16".into())
        .split(',')
        .map(|value| {
            let count = value.parse().expect("worker counts must be integers");
            assert!(count > 0);
            count
        })
        .collect();
    #[cfg(feature = "observability")]
    observation::install();
    let corpus = OperationalCorpus::new(stores, policies, 0);
    // Generate replacements before any timed requests. Their bytes remain live
    // in every mode, keeping fixture memory comparable.
    let replacements: Vec<_> = (1..=reloads)
        .map(|generation| OperationalCorpus::new(stores, policies, generation).policy_text)
        .collect();
    let requests = corpus.requests();
    println!("# Concurrent policy probe");
    println!(
        "\nCorpus: operational v{OPERATIONAL_CORPUS_VERSION}; stores: {stores}; policies/store: {policies}; total policies: {}; layout: {layout}; mode: {mode:?}; samples/worker: {samples}; reloads: {reloads}; observability: {}.",
        stores * policies + 1,
        cfg!(feature = "observability")
    );
    println!(
        "\nBuild: {:?}; available parallelism: {:?}.",
        treetop_core::build_info(),
        thread::available_parallelism()
    );
    println!(
        "\n| Workers | Requests | Requests/s | p50 ms | p95 ms | p99 ms | Reload ms | Overlap requests | Retained | RSS MiB | Peak MiB | RSS after release MiB |"
    );
    println!(
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    );
    for workers in workers {
        let engine = corpus.engine(partitioned);
        let initial_version = engine.current_version();
        for (request, expected) in &requests {
            assert_eq!(engine.evaluate(request).unwrap().is_allowed(), *expected);
        }
        let mut retained: Vec<EvaluationSession<SchemaEnforcing>> = Vec::with_capacity(reloads);
        let mut versions = vec![initial_version];
        let start = Barrier::new(workers + 1);
        let reload_active = AtomicBool::new(false);
        let reload_done = AtomicBool::new(mode == Mode::Steady);
        let (results, reload_elapsed) = thread::scope(|scope| {
            let completion = ReloadCompletion(&reload_done);
            let handles: Vec<_> = (0..workers)
                .map(|worker| {
                    let (engine, requests, start, active, done) =
                        (&engine, &requests, &start, &reload_active, &reload_done);
                    scope.spawn(move || {
                        let mut latencies = Vec::with_capacity(samples);
                        let mut observed: Vec<(u64, std::sync::Arc<str>)> =
                            Vec::with_capacity(reloads + 1);
                        start.wait();
                        let wall = Instant::now();
                        let mut random = worker as u64 + 1;
                        let mut count = 0;
                        let mut overlap = 0;
                        while count < samples || !done.load(Ordering::Acquire) {
                            let (request, expected) = &requests[(count + worker) % requests.len()];
                            let during_reload = active.load(Ordering::Acquire);
                            let now = Instant::now();
                            let decision = engine.evaluate(request).unwrap();
                            let elapsed = now.elapsed();
                            // Bounded reservoir covers the complete interval,
                            // including long reloads after the first N requests.
                            if latencies.len() < samples {
                                latencies.push(elapsed);
                            } else {
                                random ^= random << 13;
                                random ^= random >> 7;
                                random ^= random << 17;
                                let slot = (random % (count as u64 + 1)) as usize;
                                if slot < samples {
                                    latencies[slot] = elapsed;
                                }
                            }
                            assert_eq!(decision.is_allowed(), *expected);
                            let version = decision.version();
                            if observed
                                .last()
                                .is_none_or(|(generation, _)| *generation != version.generation)
                            {
                                if let Some((previous, _)) = observed.last() {
                                    assert!(version.generation > *previous);
                                }
                                observed.push((version.generation, version.hash.clone()));
                            }
                            overlap += usize::from(during_reload);
                            count += 1;
                        }
                        let wall = wall.elapsed();
                        (latencies, wall, count, overlap, observed)
                    })
                })
                .collect();
            start.wait();
            let now = Instant::now();
            if mode != Mode::Steady {
                for text in &replacements {
                    if mode == Mode::Retained {
                        retained.push(engine.session());
                    }
                    reload_active.store(true, Ordering::Release);
                    engine.reload_from_str(text).unwrap();
                    reload_active.store(false, Ordering::Release);
                    versions.push(engine.current_version());
                }
            }
            let elapsed = now.elapsed();
            drop(completion);
            (
                handles
                    .into_iter()
                    .map(|handle| handle.join().unwrap())
                    .collect::<Vec<_>>(),
                elapsed,
            )
        });
        let published: Vec<PolicyVersion> = versions;
        let wall = results.iter().map(|result| result.1).max().unwrap();
        let total: usize = results.iter().map(|result| result.2).sum();
        let overlap: usize = results.iter().map(|result| result.3).sum();
        let mut latencies = Vec::with_capacity(samples * workers);
        for (sample, _, _, _, observed) in results {
            latencies.extend(sample);
            for (generation, hash) in observed {
                assert!(
                    published
                        .iter()
                        .any(|version| version.generation == generation && version.hash == hash)
                );
            }
        }
        latencies.sort_unstable();
        for session in &retained {
            for (request, expected) in &requests {
                let decision = session.evaluate(request).unwrap();
                assert_eq!(decision.is_allowed(), *expected);
                assert_eq!(decision.version(), &session.version());
            }
        }
        let version = engine.current_version();
        assert!(engine.reload_from_str("permit (").is_err());
        assert_eq!(engine.current_version(), version);
        let held = memory();
        let retained_count = retained.len();
        drop(retained);
        let released = memory();
        let ms = |value: Duration| value.as_secs_f64() * 1000.0;
        println!(
            "| {workers} | {total} | {:.1} | {:.3} | {:.3} | {:.3} | {:.3} | {overlap} | {retained_count} | {} | {} | {} |",
            total as f64 / wall.as_secs_f64(),
            ms(percentile(&latencies, 50)),
            ms(percentile(&latencies, 95)),
            ms(percentile(&latencies, 99)),
            if mode == Mode::Steady {
                0.0
            } else {
                ms(reload_elapsed)
            },
            mib(held.resident_kib),
            mib(held.peak_kib),
            mib(released.resident_kib)
        );
    }
    println!(
        "\nClosed-loop service times exclude queueing; latencies pool equal-size deterministic reservoirs from each worker across the full interval (equal worker weighting). Throughput covers all requests through reload completion and includes assertion/sampling overhead. Zero overlap invalidates a reload-interference comparison. RSS includes input corpora, schema, request fixtures and allocator retention; peak RSS is cumulative across rows. Use one worker count per process for isolated memory comparisons."
    );
}
