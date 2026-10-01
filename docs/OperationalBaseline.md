# Initial operational measurements

Measured on 2026-09-22 at commit
`2beff78a1314e69e604e9f71f2ea268bc0ecef5c` (clean), using Rust 1.98.0,
Cedar 4.13.0, Linux x86-64, glibc 2.34, and Rust's System allocator on an Intel
Xeon Silver 4216 (16 physical cores, 32 logical CPUs available). This was a shared
host without CPU isolation. Builds completed before the reported probes ran;
probe processes ran sequentially. These are reference observations, not
regression thresholds or service capacity promises. Scheduled CI uses Rust
1.93.1, so compare its results within that environment.

The [measurement protocol](OperationalMeasurements.md) documents the exact
commands, fixture versions, configuration, counters, and limitations. The
historical `Scale.md` results remain unchanged: they used a different Rust and
Cedar version and must not be treated as a matched before/after comparison.

## Live memory at 10,000 policies

Scale corpus v1, three reloads, one fresh process per mode:

| Component or phase | Live allocation payload MiB |
| --- | ---: |
| Input corpus | 1.72 |
| Additional schema and initialization | 0.07 |
| Additional validated Cedar policy state | 29.61 |
| Additional Treetop permit/forbid metadata | 29.58 |
| Complete engine plus input | 60.99 |
| Complete engine plus three retained old generations and input | 238.50 |
| After dropping the three retained sessions | 60.99 |
| After dropping the engine and input | 0.06 |

The metadata release experiment attributes approximately 26.00 MiB to JSON
trees, 1.58 MiB to policy literals, 0.73 MiB to returned IDs and the forbid map,
and 1.27 MiB to the remaining permit index and placeholders. This is roughly
88% JSON within metadata and 44% of the engine's live allocation payload after
subtracting input bytes. Small differences reflect initialization caches and
shared empty placeholders, not a precise object-size accounting identity.

Parsing alone peaked at 101.69 MiB of requested live payload and settled at
31.32 MiB including input. Strict validation peaked at 101.77 MiB and settled at
31.40 MiB including schema and input. Validation performed about 5.28 million
allocation/reallocation calls in that interval, versus about 0.40 million for
parsing alone, even though the retained payload was similar. Transient work and
steady memory are distinct optimization questions.

## Reload retention and RSS

Without retained sessions, every completed reload returned to about 60.99 MiB
live payload. The interval peak was about 162.67 MiB; RSS settled around
185 MiB after repeated reloads. With three retained sessions, each additional
generation added about 59.17 MiB live payload, reaching 238.50 MiB live and
326 MiB RSS. The last reload's interval payload peak was 281.02 MiB.

Dropping retained sessions returned live payload to 60.99 MiB, but RSS remained
about 325 MiB. Dropping the engine and input reduced live payload to about
0.06 MiB while RSS remained about 323 MiB. This demonstrates why RSS alone cannot
diagnose an engine leak or prove that releasing sessions reclaimed resident
pages. Linux RSS/high-water samples are approximate; use payload ownership and
repeated fresh-process runs alongside them.

Keep session lifetimes bounded at the application layer and coalesce reloads on
the control plane. At this corpus size, capacity planning must account for each
retained generation as well as replacement compilation and application data.
The probe intentionally retains three generations; it does not impose a new
engine limit or recommend three as a production maximum.

## Concurrent throughput and tails

Operational corpus v1, eight stores with 128 policies each plus one global forbid,
1,000 samples per worker, and three replacements in reload modes. All 60 rows
(five worker counts, two layouts, three modes, two feature configurations)
completed their decision/version/rollback checks. Typed requests were reused;
these times exclude application deserialization and request construction.

Steady-state observations:

| Observability | Layout | Workers | Requests/s | p95 ms | p99 ms |
| --- | --- | ---: | ---: | ---: | ---: |
| Off | Monolithic | 1 | 731.4 | 1.390 | 1.417 |
| Off | Monolithic | 2 | 1,185.8 | 1.717 | 1.769 |
| Off | Monolithic | 4 | 1,796.1 | 2.272 | 2.626 |
| Off | Monolithic | 8 | 2,095.3 | 3.922 | 3.973 |
| Off | Monolithic | 16 | 2,011.8 | 8.923 | 9.501 |
| Off | Partitioned | 1 | 5,494.0 | 0.190 | 0.193 |
| Off | Partitioned | 2 | 9,142.3 | 0.235 | 0.239 |
| Off | Partitioned | 4 | 14,433.4 | 0.291 | 0.297 |
| Off | Partitioned | 8 | 16,446.0 | 0.507 | 0.520 |
| Off | Partitioned | 16 | 16,127.0 | 1.535 | 1.587 |
| On | Monolithic | 1 | 735.0 | 1.368 | 1.393 |
| On | Monolithic | 2 | 1,153.1 | 1.764 | 1.796 |
| On | Monolithic | 4 | 1,791.2 | 2.280 | 2.315 |
| On | Monolithic | 8 | 2,041.4 | 4.007 | 4.059 |
| On | Monolithic | 16 | 2,068.8 | 8.154 | 9.129 |
| On | Partitioned | 1 | 5,481.4 | 0.192 | 0.196 |
| On | Partitioned | 2 | 8,500.0 | 0.248 | 0.254 |
| On | Partitioned | 4 | 13,879.0 | 0.299 | 0.306 |
| On | Partitioned | 8 | 16,801.3 | 0.493 | 0.501 |
| On | Partitioned | 16 | 15,994.4 | 1.049 | 1.489 |

Partitioning reduces the evaluated policy count from 1,025 to 129 for this
distribution. Throughput flattened between eight and sixteen workers while
tails increased. Additional workers did not imply additional useful capacity.
This shared-host run cannot attribute the plateau to CPU scheduling, cache
pressure, or memory bandwidth. No hardware bandwidth counters were collected.
Use production-shaped, isolated runs to choose the application's worker limit.

Reload observations at eight workers:

| Observability | Layout | Mode | Requests/s | p99 ms | Three reloads ms | Requests starting during reload | Retained sessions |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Off | Monolithic | Reload | 2,099.4 | 4.134 | 1,765.2 | 3,658 | 0 |
| Off | Monolithic | Retained | 2,005.6 | 4.228 | 1,721.1 | 3,556 | 3 |
| Off | Partitioned | Reload | 16,785.5 | 0.564 | 2,126.0 | 35,798 | 0 |
| Off | Partitioned | Retained | 16,292.8 | 0.581 | 2,071.8 | 33,756 | 3 |
| On | Monolithic | Reload | 2,082.9 | 4.044 | 1,793.5 | 3,769 | 0 |
| On | Monolithic | Retained | 2,098.0 | 3.952 | 1,740.2 | 3,647 | 3 |
| On | Partitioned | Reload | 16,253.3 | 0.538 | 2,193.2 | 35,758 | 0 |
| On | Partitioned | Retained | 16,492.4 | 0.522 | 2,068.0 | 34,101 | 3 |

Every reload row across all worker counts recorded overlapping requests. Old
sessions retained their original decisions and versions. Monolithic workers
often continued after reload completion to meet the minimum request count;
partitioned workers usually exceeded it while reloads were still running.
Consequently, these latency distributions include different proportions of
reload-active traffic. They demonstrate exercised overlap, not an isolated
estimate of reload overhead. Some observability-enabled values were faster in
this single run; do not infer negative or negligible sink cost from that noise.
Use repeated matched runs and the focused metrics benchmarks for that question.

## Selected optimization experiment

Prioritize reducing retained permit JSON over literal interning or finer policy
indexing for the next memory experiment. JSON is the largest measured
Treetop-owned component and its cost multiplies with retained generations.
Candidate designs should compare compact/shared representation and one-time
materialization against the existing eager cache. Keep these acceptance gates:

- Preserve returned policy JSON, annotations, diagnostics, and decision semantics.
- Account separately for engine construction, first matching evaluation,
  repeated evaluation, serialization, and reload memory; do not hide a memory
  saving by adding repeated serialization to every allow decision.
- Compare focused Criterion and Gungraun results with and without observability,
  plus the unchanged scale corpus and these allocation phases.
- Retain atomic publication and coherent old sessions. Document any public Rust
  type change explicitly, even if the JSON shape stays the same.

No production representation or authorization behavior changes in this
measurement PR. The data selects an experiment, not a demonstrated improvement.
