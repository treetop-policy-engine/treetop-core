#![cfg(feature = "bench-internal")]

use treetop_core::bench_helpers::operational_scale::OperationalCorpus;

#[test]
fn operational_corpus_preserves_decisions_and_retained_generations() {
    let initial = OperationalCorpus::new(3, 16, 0);
    let replacement = OperationalCorpus::new(3, 16, 1);
    assert_ne!(initial.policy_text, replacement.policy_text);
    for partitioned in [false, true] {
        let engine = initial.engine(partitioned);
        assert_eq!(engine.policies().len(), 49);
        let session = engine.session();
        let original = session.version();
        engine.reload_from_str(&replacement.policy_text).unwrap();
        let current = engine.current_version();
        assert_eq!(current.generation, original.generation + 1);
        assert_ne!(current.hash, original.hash);
        assert!(engine.reload_from_str("permit (").is_err());
        assert_eq!(engine.current_version(), current);
        for (request, expected) in initial.requests() {
            let old = session.evaluate(&request).unwrap();
            assert_eq!(old.is_allowed(), expected);
            assert_eq!(old.version(), &original);
            let live = engine.evaluate(&request).unwrap();
            assert_eq!(live.is_allowed(), expected);
            assert_eq!(live.version(), &current);
        }
        // This principal has the group permit, so the global forbid must be
        // present in every store to produce the expected denial.
        for (request, _) in initial.requests().into_iter().skip(4).step_by(5) {
            let diagnostics = engine.evaluate_with_diagnostics(&request).unwrap();
            assert_eq!(
                diagnostics.matched_forbid_policy_ids(),
                ["organization.blocked"]
            );
        }
    }
}
