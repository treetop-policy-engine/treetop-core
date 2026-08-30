# Policy-Store Design and Format

Policy stores partition one trusted Cedar policy source into independent
namespace-owned `PolicySet` values. A request is routed to one store before Cedar
authorization, reducing evaluation work without creating multiple conceptual
policy engines.

Policy stores are an optimization boundary, not a change to Cedar authorization
semantics. Permit and forbid evaluation, group membership, context, labels,
schema validation, diagnostics, and policy versions retain their existing
meaning.

## Activation Model

Store support is compiled into Treetop Core and enabled explicitly when an
engine is constructed. It is not a Cargo feature or a mutable per-request
toggle.

- `PolicyEngine::new_from_str` and the existing schema constructors remain
  monolithic.
- `PolicyEngine::new_from_str_with_policy_stores` enables stores without a
  schema.
- `PolicyEngine::new_from_str_with_schema_and_policy_stores` and
  `PolicyEngine::new_from_str_with_cedarschema_and_policy_stores` enable stores
  with schema validation.
- Every `reload_from_str*` method retains the engine's original monolithic or
  partitioned layout.

Applications should expose an explicit loading mode such as `monolithic` or
`bundle-modules`, with `monolithic` as the backward-compatible default. Core
does not define a serialized JSON or TOML configuration format for stores. The
application constructs a trusted `PolicyStoreLayout`, or a trusted bundle
loader derives one from authenticated module metadata.

## Layout

Each `PolicyStoreConfig` contains an application-defined ID and a Cedar
namespace root:

```rust
use treetop_core::{PolicyStoreConfig, PolicyStoreLayout};

let layout = PolicyStoreLayout::new([
    PolicyStoreConfig::new("dns", "ExampleCo::DNS")?,
    PolicyStoreConfig::new("www", "ExampleCo::WWW")?,
])?
.with_global_policy_ids(["organization.suspended"])?;
# Ok::<(), treetop_core::PolicyError>(())
```

Store IDs must be non-empty and unique. `*` is reserved for the global policy
annotation. Namespace roots must be valid Cedar names, unique, and
non-overlapping. A store owns its root and every namespace below it, so
`ExampleCo` and `ExampleCo::DNS` cannot be separate stores in one layout.

The layout is application configuration rather than policy-controlled data.
Policy annotations can select only an already declared store; they cannot create
one or change its namespace.

## Policy Assignment

During snapshot construction, Core parses and optionally schema-validates the
complete policy source once. It then inspects every policy's principal, action,
resource, `when`, and `unless` references and applies these rules:

| Policy form | Assignment |
| --- | --- |
| References exactly one configured namespace root | That store |
| References no configured root | Rejected unless explicitly assigned or global |
| References more than one configured root | Rejected unless global |
| `@treetop_store("store-id")` | Named store, if inferred references do not conflict |
| `@treetop_store("*")` | Every store |
| `@id` registered by `with_global_policy_ids` | Every store |

An explicit local assignment is primarily for policies whose scope is otherwise
unconstrained:

```cedar
@id("dns.emergency-lock")
@treetop_store("dns")
forbid (principal, action, resource)
when { context.emergencyLockdown };
```

An annotation can also declare a policy global:

```cedar
@id("organization.suspended")
@treetop_store("*")
forbid (
    principal in Organization::Group::"suspended",
    action,
    resource
);
```

Registering global `@id` values in the layout lets a trusted bundle manifest
own the global designation instead of policy text. Every registered ID must
exist in the loaded source, which makes stale or misspelled assignments a load
failure. A registered global policy cannot also carry a local store annotation.

Namespaces outside every configured store are shared. For example, a
server-controlled `Organization::User` or `Organization::Group` namespace can
be referenced from DNS and WWW policies without selecting either store. Group
resolution, including future LDAP-backed resolution, remains trusted request
preparation and does not affect routing.

## Request Routing

Routing uses only the request action namespace and resource type. Principal
identity, group membership, resource attributes, and context never choose the
store.

| Action namespace | Resource type | Result |
| --- | --- | --- |
| Same configured store | Same configured store | Route to that store |
| Configured store | Outside every store | Route to the action store |
| Outside every store | Configured store | Route to the resource store |
| Different configured stores | Different configured stores | Fail closed |
| Outside every store | Outside every store | Fail closed |

The namespace router is precomputed with the snapshot. Lookup follows namespace
depth rather than scanning all stores. Applications must construct action and
resource identities from authenticated, application-controlled data; a client
must not be able to select a more permissive store by asserting a namespace.

`PolicyStoreRoutingError` reports requests that cannot resolve to exactly one
store. `PolicyStoreConfigError` reports invalid layouts or policy assignments.
Neither error falls back to monolithic authorization.

## Snapshots, Reloads, and Administrative APIs

One evaluation retains one immutable snapshot from routing through the returned
decision. Reloads build and validate every replacement store before the atomic
swap. A failed reload leaves the last-known-good snapshot and store layout
active.

The policy version hash remains based on the complete source text. Whole-engine
policy inventory and listing APIs inspect all stores and deduplicate global
copies. Those APIs remain structural and non-authoritative; only `evaluate*`
can make an authorization decision.

## Bundle and Service Integration

A bundle format with trusted module metadata can map each ordinary module name
and namespace to one store and register every global module's policy IDs as
global. This does not require the bundle archive format to serialize Core's
internal layout directly.

Modules used as stores must actually be independent. Imports or policy
expressions that cross ordinary module namespaces cause preparation to fail.
Organization-wide policies must be marked global so forbid precedence is
preserved in every store.

Raw Cedar uploads do not carry trusted module boundaries and should remain
monolithic unless the service receives a separate trusted layout. Services
should validate a new bundle and its derived layout completely before replacing
live state, retain the previous engine after failure, and expose the active
loading mode operationally.

## Performance and Memory

Authorization work becomes proportional to the selected store's policies plus
global policies rather than the full organization policy count. This benefit is
largest when stores are balanced and global policies remain small.

Partitioning does not reduce total policy text, organization-wide parsing and
schema validation, whole-engine administrative scans, or reload coordination.
Every global policy is compiled into every store, and multiple `PolicySet`
values add metadata overhead. Capacity planning must measure request latency,
steady-state memory, and atomic-reload peak memory using the production policy
distribution.

See [Operating at Large Policy-Set Scale](Scale.md) for the current benchmark
and operational guidance.
