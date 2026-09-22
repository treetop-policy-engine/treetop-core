# Concurrent evaluation and memory attribution

The operational probes answer two separate questions: how concurrent requests
behave during reloads, and which allocations remain live afterwards. They keep
instrumented allocation accounting out of latency measurements. These reports
describe exercised workloads; they are not service-level guarantees.

## Concurrent requests

```bash
TREETOP_OPERATIONAL_LAYOUT=partitioned TREETOP_OPERATIONAL_MODE=reload \
  cargo bench --locked --features bench-internal --bench policy_concurrency_probe
```

Run the same command with `--features bench-internal,observability` to install a
fixed-size atomic counting sink using the borrowed callback. This measures an
active sink, including shared-counter contention, not just a compiled feature.
The sink retains no history and exports no user, resource, or policy labels.

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `TREETOP_OPERATIONAL_LAYOUT` | `partitioned` | `monolithic` or `partitioned`, using identical policies |
| `TREETOP_OPERATIONAL_MODE` | `steady` | `steady`, `reload`, or `retained` |
| `TREETOP_OPERATIONAL_STORES` | `8` | Number of independent namespaces |
| `TREETOP_OPERATIONAL_POLICIES_PER_STORE` | `128` | At least four policies per namespace |
| `TREETOP_OPERATIONAL_WORKERS` | `1,2,4,8,16` | Comma-separated positive worker counts |
| `TREETOP_OPERATIONAL_SAMPLES` | `1000` | Minimum requests and reservoir capacity per worker |
| `TREETOP_OPERATIONAL_RELOADS` | `3` | Successful replacements during each reload row |

The separately versioned `OperationalCorpus` extends scale corpus v1 with exact
namespaces and one global forbid. The default contains 1,025 policies. Requests
rotate equally through direct permit, local forbid, group permit, no match, and
global forbid in every store. The global forbid overrides an otherwise matching
group permit. Both layouts use strict schema validation.

Workers start behind a barrier. Reload modes continue evaluating until both the
minimum request count and all reloads finish. Every request checks its expected
decision; observed generation/hash pairs must correspond to a published state
and generations cannot move backwards within a worker. `retained` captures a
session before every swap, then verifies every old session's decisions and
versions after the load interval. Failed reload rollback is also checked.

Each worker keeps a bounded, deterministic reservoir across its whole interval;
p50/p95/p99 pool equally sized reservoirs, giving each worker equal weight.
With different worker request counts, these are not request-weighted population
percentiles. Increase samples and repeat runs before interpreting tail changes.
The probe reports how many requests started while a reload was active; a zero
count provides no evidence about interference. The rows are closed-loop service
times and exclude queueing. They cannot establish an HTTP p99 or saturation SLO.
Throughput includes decision checks and sample bookkeeping, while each latency
sample times only `evaluate`. Startup, compilation, fixture generation, warm-up,
session verification, and reporting are outside the measured request interval.
Throughput divides total requests by the longest worker interval after the start
barrier. Reload time covers the complete control loop, including session capture
and version bookkeeping, and is not added to request latency.

Each row constructs a fresh engine. RSS includes the engine, schemas, request
fixtures, every replacement input string, samples, and allocator retention.
Peak RSS is process-wide and carries across rows. For isolated memory comparisons,
run one worker count per fresh process. Use CPU isolation and matched machine
allocations for regression comparisons; 16 workers on a smaller CI runner is an
oversubscription experiment, not evidence of 16-core capacity.

## Allocation attribution

Run each mode in a fresh process:

```bash
for mode in parse validated metadata metadata-parts engine reload retained; do
  TREETOP_SCALE_POLICY_COUNT=10000 TREETOP_MEMORY_MODE="$mode" \
    cargo bench --locked --features bench-internal --bench policy_memory_probe
done
```

`parse` retains Cedar policies without a schema. `validated` adds strict schema
validation. `metadata` retains the actual loader's permit/forbid metadata above
that compiled set, then drops it independently. `metadata-parts` releases JSON
trees, literals, returned IDs/forbid map, and finally the remaining permit index,
in that order. Empty placeholders are shared; allocation deltas include their
small fixed cost. These destructive releases affect a benchmark-owned copy only.

`engine` measures complete engine construction. `reload` replaces generations
without retaining sessions. `retained` deliberately holds one session per old
generation, then releases them together. Replacement text generation and release
have separate samples, so input bytes are not mistaken for compiled snapshots.
`TREETOP_OPERATIONAL_RELOADS` controls the number of replacements.

The probe delegates to Rust's `System` allocator and counts successful requested
allocation sizes. Live payload excludes allocator bookkeeping, stacks, and
direct mappings. The peak counter resets after each sample; interval peaks
include everything already live and must not be summed. `/proc` readings use
temporary buffers after capturing counters. No reports are printed until the
measured objects have been dropped. Allocator instrumentation changes execution
cost, so this binary is unsuitable for latency comparisons.

RSS minus live payload is not a precise allocator-retention estimate. Compare
drop phases and repeat fresh processes to distinguish live ownership from pages
retained by the allocator. Use Massif or another allocation profiler when parser
subcomponents need attribution; phase counters cannot identify individual call
stacks or internal Cedar CST allocations.

## Automation and reporting

The weekly/manual Policy Scale workflow runs every layout/mode with and without
observability, plus all memory modes at 10,000 policies. Reports and machine
information are retained as artifacts for 30 days. Existing large-scale tiers
and Criterion/Gungraun regression targets retain their original fixtures.

Record both fixture versions, exact commit and dirty status, Rust/Cedar versions,
CPU model and allocation, worker count, policies per store, layout, mode, sample
count, reload count, allocator, and observability sink. Keep Core, REST in-process,
and HTTP results separate; do not subtract unrelated percentiles to infer
overhead. The operational fixture is available downstream through `bench-internal`.

See [the initial findings](OperationalBaseline.md) for measured allocation
attribution, concurrent-load observations, and the selected optimization priority.
