# Declared label targets: breaking migration

Treetop's early releases prioritize correctness and one explicit contract over
backward compatibility. The 0.1.0 contract removes legacy behavior rather than
retaining deprecated adapters. Upgrade the coordinated Core, Bundle, REST, SDK,
CLI, frontend, and Bundle Action changes together.

## Ownership and application

A labeler owns a tuple: `(fully qualified Cedar resource type, attribute)`.
`App::Host` and `Other::Host` are distinct types; a root-namespace `Host` is also
an exact type. Entity IDs, namespace wildcards, and arbitrary Rust applicability
predicates are not scopes.

Construct `LabelTarget::new("App::Host", "labels")` once, handle its validation
error, and return the target from `Labeler::target`. Implement read-only `derive`
logic. Use `labeler.apply(&mut resource)` for controlled direct application; it
checks the resource type and leaves other types untouched.

The registry captures each declaration when built and rejects duplicate tuples
before installation. It indexes validated Cedar types without reparsing them on
requests. For a matching resource it clears all owned attributes before running
any derivation, then applies labelers in registration order. A derivation returning
`None` leaves its target absent. Equal attribute names on different types have
independent owners. Reloads publish the complete immutable registry as part of
one engine generation, and captured sessions retain their original generation.

## Authorization impact

Only attributes owned on the actual resource type are server-derived labels.
Other attributes remain trusted application inputs. Registering `App::Host.labels`
does not remove or validate `Other::Host.labels`. Policies that rely on derived
labels must constrain the resource type and install the corresponding owner.
Review policies that previously relied on a global attribute-name reservation.

A labeler cannot echo its own incoming output. An earlier labeler cannot consume
a forged value owned by a later labeler on the same type, because the registry
clears every owned output first. Canonical `id` is reserved on all types.

## Configuration

Bundle and REST label rules use an explicit target object:

```json
{
  "target": { "resource_type": "App::Host", "attribute": "labels" },
  "field": "name",
  "patterns": [{ "name": "prod", "regex": "^prod" }]
}
```

Replace the old rule-level `kind` and `output` fields with `target.resource_type`
and `target.attribute`. Old keys, unknown fields, missing target components,
invalid Cedar resource types, empty attribute names, and reserved outputs are
errors. Shared names on disjoint types require separate rules, not a dispatcher.
Set bundle and module manifests to `format_version = 2`, then rebuild and re-sign
bundles after migrating their configuration. Old archives and signatures are rejected.

## Rust and wire consumers

- Replace custom `applies_to` and `output` methods with `target` returning a
  validated `LabelTarget`. Create one labeler per exact target.
- Pass the validated target to `RegexLabeler::new(target, field, rules)`.
- Replace `UserPolicies` with `PolicyCandidates`; replace its deprecated action
  aliases with `candidate_actions` and `candidate_actions_by_name`. Candidate
  listings do not evaluate Cedar conditions and never authorize operations.
- Supply every policy-version field: `hash`, `loaded_at`, `label_set`, and
  `generation`. Use explicit null when no label-set identifier exists. Generation
  is an unsigned 64-bit value local to one engine instance. Omission is an error.

Old-server defaults, wildcard scopes, and deprecated label APIs are removed from
the coordinated new contract. Candidate revisions are pinned for integration
before publication.
