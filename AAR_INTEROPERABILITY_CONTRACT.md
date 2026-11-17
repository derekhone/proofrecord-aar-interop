# AAR interoperability contract (ProofRecord ↔ AAR)

Status: demonstration contract, version `executionproof.proofrecord.v1` citation, release candidate v0.1.0-rc.5. Not endorsed by AAR. Not formal AAR conformance.

AAR pinned: `oneshot2001/aar` @ `aab2feca93986f92f29f7672dff3464e05163cb5` (bundle wire v0.2), `spec/aar-core.cddl`.

## Citation (no AAR schema change)

An AAR **authorization** receipt's `decision.evaluated_inputs` (an existing list of `{name, value_digest: digest32}`) carries:

```
{ name: "executionproof.proofrecord.v1", value_digest: SHA-256(exact ProofRecord file bytes) }
```

The entry is inside the decision record, so it is covered by AAR's `decision_commitment` and by the AAR issuer's COSE_Sign1 signature. **AAR treats it as an opaque input and does not interpret it.** The semantic agreement check is done by `epverify/aar_xcheck.py`. This is an *existing extension point*, not an AAR-endorsed profile. AAR maintainers may prefer a different mechanism.

## Comparison (cross-record level)

| ProofRecord (signed) | AAR (signed by AAR issuer keys) | Rule |
|---|---|---|
| SHA-256(file) | authorization `evaluated_inputs[name=executionproof.proofrecord.v1].value_digest` | exactly one authorization cites it, else `NO_CITATION`/`REF_NOT_CITED` (5) or `AMBIGUOUS_CITATION` (1) |
| `actor.aar_subject_credential_id` | authorization `delegation.subject_credential_id` | equal, else `ACTOR` |
| `decision` | authorization `decision.decision` | ALLOW needs permit/permit_with_approval. HOLD/DENY with any dispatch gives `DISPATCH_WITHOUT_ALLOW`; without one gives `NOT_AUTHORIZED` |
| `action.action_name` | each eligible attempt `action.action_name`, `command.action_name`, `canonical_command.operation` | equal, else `ACTION_NAME` / `CANONICAL_COMMAND` |
| `action.target_id` (16-byte hex) | `action.target_id`, `command.target_id`, `canonical_command.target` | equal, else `TARGET` / `CANONICAL_COMMAND` |
| `action.parameters_digest` = SHA-256(detCBOR(parameters)) | `action.parameters_digest`, `canonical_command.parameters_digest` | byte-equal, else `PARAMETERS_DIGEST` |
| `action.parameters` | decoded `action.parameters_cbor` | type-strict equality (3 ≠ "3" ≠ true), else `PARAMETERS_VALUE` |
| `use: single` | dispatches bound to eligible attempts of that authorization | exactly one, else `NO_DISPATCH` (5) / `REPLAY` (1); any dispatch bound to a non-eligible attempt of that authorization, naming an attempt absent from the bundle, or whose `attempted_as` edge disagrees with its `attempt_id` → `DISPATCH_NOT_ELIGIBLE` / `UNBOUND_DISPATCH` / `DISPATCH_EDGE_CONFLICT` (1) |
| — | dispatch `command_id` vs attempt `command.command_id` | equal, else `COMMAND_ID` |
| `[not_before, expires_at)` | dispatch `dispatched_at` | inside, else `DISPATCH_BEFORE_VALIDITY` / `EXPIRED_AT_DISPATCH` |
| — | `outcome_observation` for that dispatch | reported. With `--require-outcome`: absent gives `OUTCOME_ABSENT` (5), non-consistent gives `OUTCOME_NOT_CONSISTENT` (1) |

## What each level establishes

| Level | Established by | Not established |
|---|---|---|
| ProofRecord-only | Ed25519 under pinned key, schema, digest, time coherence | anything about dispatch |
| Cross-record | the AAR bundle as read agrees with the ProofRecord | AAR signatures, credentials, Merkle, epochs |
| Full AAR conformance | AAR's own pyref, run unchanged (`--aar-pyref`) | ProofRecord semantics (pyref does not interpret the citation) |
| Independent outcome | **not established**: the AAR observer is an AAR test key from the same fixture generator | — |

## Fixture generation

The AAR bundles were produced by AAR's TypeScript harness (`harness/fixtures.ts`) with a small test-only option hook (not included in this package). With no options, the hook reproduces upstream `kats/positive/bundle-valid-subset.cbor` byte-identically (sha256 `9571233e…5b75`, verified). The bundles use AAR's published test keys. `MUT_*` bundles are post-hoc byte mutations whose AAR signatures are deliberately broken (cross-check-only negatives), with one exception: `MUT_OUTCOME_REMOVED`, which pyref still reports as conformant (`valid_subset` coverage).

## AAR reference-verifier conformance vs RF cross-receipt consistency

These are two different checks. **Neither implies the other.**

| | AAR reference-verifier conformance | RF cross-receipt consistency |
|---|---|---|
| Tool | AAR `pyref`, run unchanged from the pinned AAR commit (`--aar-pyref`) | `epverify/aar_xcheck.py` (this package) |
| Question answered | Is the AAR bundle well-formed and correctly signed under AAR's own rules? | Does the AAR bundle cite exactly this ProofRecord and record exactly the authorized action, once, in time, by the named credential? |
| Reads the ProofRecord? | No. `evaluated_inputs` is opaque to AAR | Yes |
| Report field | `levels.aar_conformance` | `levels.cross_record`; MATCH without pyref carries `_CROSS_CHECK_ONLY` |

### Observation: conformant AAR bundles that disagree with the ProofRecord

In this fixture set, **16 of 21** harness-generated `AAR_*` bundles are reported conformant by AAR pyref while the RF cross-check reports a non-MATCH result (no citation, unknown or ambiguous citation, or a disagreement in parameters, timing, decision, actor, action or target). Reproduce with:

```bash
AAR_DIR=./aar python3 -B tests/conformant_disagreement_observation.py
```

The recorded run is `evidence/CONFORMANT_DISAGREEMENT_OBSERVATION.json`. This is a **same-author observation, not an independently confirmed defect and not an AAR vulnerability claim**: AAR does not interpret `evaluated_inputs`, so a conformant bundle can disagree with a record AAR never reads. It shows only that a pyref "conformant" result says nothing about ProofRecord agreement.
