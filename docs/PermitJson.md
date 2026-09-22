# Compact permit JSON

Treetop retains Cedar JSON for each permit policy so an allow decision can return
the policies that contributed to it. The evaluator uses compiled Cedar policies;
the JSON is descriptive metadata. Engines, sessions, and returned decisions share
that metadata through `Arc`.

The initial allocation probe attributed about 26 MiB to retained permit JSON in
the versioned 10,000-policy scale corpus, which contains 9,000 permits and 1,000
forbids. That is roughly 3 KiB per permit in this fixture, not a per-request
allocation or a fixed cost for all possible policies. Policy complexity and the
number of simultaneously retained generations affect the total.

`PolicyJson` stores immutable objects and arrays in boxed slices and strings in
boxed string slices. It consumes the temporary `serde_json::Value` during metadata
construction, preserving field order and eliminating spare collection capacity
and per-object map indexes. There is no lazy initialization, parsing, or JSON tree
reconstruction during evaluation or direct Serde serialization. Old sessions and
decisions keep their original shared data through reloads and engine destruction.

## Rust migration

The public `PermitPolicy.json` field changes from `Arc<serde_json::Value>` to
`Arc<PolicyJson>`. The `PermitPolicy::new(literal, value, cedar_id)` signature stays
the same and performs compaction at construction. Code that serializes a policy,
decision, or the JSON field directly needs no change:

```rust
# use treetop_core::PermitPolicy;
# fn example(policy: &PermitPolicy) -> Result<(), serde_json::Error> {
let bytes = serde_json::to_vec(&policy.json)?;
# Ok(())
# }
```

Replace direct indexing, `.get(...)`, or `.as_object(...)` on the JSON field with
an explicit owned copy, then use the normal `serde_json::Value` API:

```rust
# use treetop_core::PermitPolicy;
# fn example(policy: &PermitPolicy) {
let mut value = policy.json.to_value();
let effect = value["effect"].as_str();
value["annotations"]["display"] = "A local description".into();
# }
```

This recursively allocates and copies the retained data, so materialize once per
inspection rather than once per field. Editing the copy does not alter shared
metadata. For struct literals, replace `json: Arc::new(value)` with
`json: Arc::new(value.into())`; to replace a DTO's JSON after editing it, assign
`policy.json = Arc::new(value.into())`. `PolicyJson::from(value)` is also available
at the crate root. `PolicyJson` has private storage and supports Serde round trips.

Serialized JSON values, object field order, annotations, and the OpenAPI JSON
shape remain unchanged. Object equality and hashing ignore field order, matching
`serde_json::Value`; hashing sorts temporary borrowed entries, and equality
searches object entries. These explicit caller operations are outside evaluation.
As before, constructing or deserializing metadata does not validate Cedar or grant
authorization. Use `PolicyEngine::evaluate*` for authorization decisions.

## Measurements

The matched comparison uses the unchanged scale corpus v1 and the focused
permit-metadata fixture v1. The baseline is commit
`2d6aa56a30c2fdd0aa943c0bb23a23f1c4f153aa`, with only the new benchmark harness
copied into its checkout. The implementation is measured with the identical
harness and toolchain; the benchmark declarations and CI matrix are kept together.

Measured on 2026-09-22 with Rust 1.98.0, Cedar 4.13.0, Gungraun 0.19.4, Linux
x86-64, glibc 2.34, and the System allocator on an Intel Xeon Silver 4216. The
host is shared and CPUs are not isolated. Benchmark processes run sequentially;
results describe this fixture and environment, not a service capacity guarantee.

### Retained memory and reloads

Each mode uses a fresh process and 10,000 policies. Figures include the input
corpus except the isolated JSON component:

| Live allocation payload | Original MiB | Compact MiB |
| --- | ---: | ---: |
| Retained permit JSON | 25.998 | 8.922 |
| Complete engine plus input | 60.988 | 43.913 |
| Engine plus three retained old generations and input | 238.503 | 170.202 |
| After dropping the three retained sessions | 60.989 | 43.913 |
| After dropping engine and input | 0.057 | 0.057 |
| Initial compilation interval peak | 101.768 | 101.768 |
| Reload interval peak without retained sessions | 162.673 | 145.598 |
| Third reload interval peak with retained sessions | 281.016 | 229.790 |

JSON payload falls by 65.7%, saving 17.1 MiB per generation in this corpus.
Complete engine-plus-input payload falls by 28.0%. Compilation's initial peak
does not improve: it occurs before Treetop compacts the returned metadata. During
metadata construction, allocation/reallocation calls increase from 1,802,121 to
1,953,852 (8.4%); over complete engine construction they increase by about 2.1%.
Compaction trades some construction work for lower retained memory.

RSS after initial load remains about 109 MiB in both versions. With three retained
generations, RSS reaches about 327 MiB originally and 275 MiB with compact JSON,
and stays high after sessions are dropped. These RSS observations include
allocator retention and cannot be interpreted as the live size of policy JSON.

See [the performance guide](Perf.md) for the CPU benchmark protocol and
[the allocation protocol](OperationalMeasurements.md) for fresh-process memory
commands and the difference between live allocation payload and RSS. Memory probe
timings include allocator instrumentation and are not used as latency evidence.
