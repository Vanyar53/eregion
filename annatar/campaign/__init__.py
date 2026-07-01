"""Annatar generative campaigns — planner, synthesizer, manifest, scope guard.

A *campaign* is a coherent ATT&CK kill-chain that Annatar plans (LLM picks +
orders techniques from ``technique_catalog.yaml``), synthesizes (materializes
schema-valid scenario YAMLs referencing only existing ``scripts/vm/`` scripts)
and later executes sequentially within a ratified budget/scope.

Invariants (see collab/design_generative_purple_loop.md):
  - every LLM product is a PROPOSITION (scenarios live campaign-scoped, not in
    the curated corpus);
  - the budget/scope allowlist is the load-bearing guardrail (Celebrimbor only);
  - zero autonomous destructive action on real data (testdata-only, safe_target).
"""
