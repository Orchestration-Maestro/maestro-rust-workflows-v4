# Provisioned-host ownership

This is an ownership transfer, not an exclusion or manufactured LLVM hit.
The early planner and required Ubuntu executor form one capability. R3 and R4
release together. Consumers enable ownership only after their provisioner
implements the schema-1 protocol below. Missing execution still fails closed.

## Tested-head policy

The optional `[ci.mutation-provisioned-host]` table in `maestro-quality.toml`
is always read from the tested checkout, including called workflows. Its bytes,
owned sources and provisioner must match tracked HEAD blobs. There is no caller
input to override ownership. The table takes exactly these fields:

| Field | Value |
| --- | --- |
| `files` | Nonempty unique exact tracked Rust paths inside the project |
| `features` | Nonempty unique declared workspace `package/feature` strings |
| `provisioner` | One exact tracked regular script path, never command text |

Paths with symlink components, escapes, globs or control characters refuse.
Host files cannot disable mutation or coverage. Windows and engine owners
cannot overlap. Mutation testing must stay enabled. A removed entry transfers
the still-existing file back to full ordinary or new-owner mutation discovery,
even if the source did not change. A deleted source has no remaining obligation.

Host discovery always lists full files with pinned cargo-mutants 27.1.0,
`--list --json --no-shuffle --no-config --cargo-arg=--locked`, selected owning
packages and qualified features. It never inherits exclusions, changed-line
filters or prior iteration evidence. Ordinary mutation excludes only the exact
transferred host files. The early planner runs independently of coverage.

## Schema 1 plans and pending coverage

`mutation-host-plan.json` contains `schema`, `identity`, `mutants`, `files`,
`features`, `packages`, `source_sha256`, `policy_sha256`, `provisioner`,
`provisioner_sha256` and `workflow_revision`. `identity` is the existing
mutation manifest: SHA, first parent, directory, compiler, cargo-mutants version,
run ID, attempt, configuration/diff digests and ordinary counts. `mutants`
retains the complete listing, including patches and enclosing-function spans.
`source_sha256` maps each owned path to the tested bytes' SHA-256. Every owned
file requires nonempty discovery. Raw discovery and diagnostics remain in
`mutation-host-list.json` and `mutation-host-plan.log`.

`changed-coverage-pending.json` contains `schema`, `state: pending-host`, `sha`,
`run_id`, `attempt`, `plan_sha256`, `policy_sha256`, `target`, `coverable`,
`ordinary`, `host`, `ordinary_uncovered`, `ordinary_allowed` and `full_allowed`.
Each line record is `{file, line, hits}` with real LCOV counters. The full set
is the disjoint union of ordinary and exact host identities. The ordinary
subset independently keeps the existing title target, rounding and minimum-one
allowance. Host lines cannot increase that allowance. Every owned file must
have LCOV line records. Pushes have empty changed identities but still require
complete host mutation evidence. Raw global LLVM coverage stays unchanged.

All versioned envelopes, manifest identities, receipt records, outcome records
and line records require their exact key sets before identity and behaviour
validation. Unknown fields, missing fields and unknown schema versions refuse.
Native cargo-mutants listing fields retain the upstream contract.

## Schema 1 outcomes

The executor produces `host-outcomes.json`, never cargo-mutants' native outcomes.
Its fields are `schema`, `sha`, `run_id`, `attempt`, `plan_sha256`,
`policy_sha256`, `provisioner_sha256`, `source_sha256`, `baseline_before`,
`baseline_after` and `outcomes`. Both baselines and every mutant receipt retain:

| Field | Meaning |
| --- | --- |
| `build`, `provision`, `test`, `cleanup` | Separate `passed`, `failed` or `not-run` phase statuses |
| `selected_tests`, `passed`, `failed`, `ignored` | Named positive test selection and exact integral counts |
| `phases` | `normal`, `abandon`, `preparing`, `recover_abandon`, `recover_preparing` assertion statuses |
| `test_sha256`, `bootstrap_sha256` | Current built test and bootstrap byte digests |
| `logs` | Nonempty map of artifact-relative raw phase log paths to SHA-256 digests |
| `test_failure` | Mutant receipts only: unique exact selected test or failed phase names |

Each `outcomes` entry contains the complete planned `mutant` identity,
`outcome`, `patched_source_sha256` and `receipt`. Exact planned and executed
sets must match without duplicates. Every outcome must be `caught`. Both
baselines require successful tests and every phase passed. Mutants run every
phase, with only passed or failed statuses. Every failed phase must be named in
`test_failure`; a phase-only failure or multiple named phase failures can prove
a kill after successful build, provision and cleanup. A Rust test failure must
name exactly as many unique selected tests as the failed count. Ignored or zero tests,
unviable, timeout, partial, missing, stale and mismatched evidence refuse.
Raw logs must be nonempty regular files inside a checked safe artifact tree.

## Final join

Aggregation runs for host-only, ordinary-inline, ordinary-empty and sharded
plans, with or without Windows and engine owners. It rechecks the plan digest,
SHA/run/attempt, exact outcome population, phase receipts and raw log digests.
Every host changed line must have an enclosing function in that complete caught
population. Unmapped lines or functions refuse; one unrelated caught mutant
does not credit an entire file.

The final `changed-coverage-final.json` retains the pending document and changes
its state to `passed`, with `host_verified`. `changed-coverage.txt` reports the
unchanged full denominator, ordinary misses/allowance, host-verified count, raw
host hits and exact mutant totals. `HOST_BEHAVIOUR_VERIFIED` is distinct from
`LLVM_EXECUTED`; neither LCOV nor Codecov gains invented hits.

The scorecard keeps pending changed coverage and mutation `not-run`. Only the
same-attempt successful host job, aggregation and coverage join can satisfy
Required Rust CI. The `mutation-host` job depends only on the early plan, not
checks or coverage. Its internal-PR guard cannot be replaced by a manual
qualification artifact. The executor runs every mandatory phase in fresh units.
Raw global LLVM coverage and existing ordinary gates remain unchanged.

## Serial execution and scoped cleanup

`rust-gate mutants-host` revalidates the tested SHA, first parent, run, attempt,
compiler, workflow, policy, source and script hashes. It copies the provisioner,
prepares one disposable Git checkout and writes a digest-bound `prepared.json`.
The consumer checkout is never mutated. Pinned discovery refuses a tool whose
reported version differs from cargo-mutants 27.1.0.

The supervisor command runs `timeout --kill-after=1m 30m` around its own internal
`mutants-host-execute` command. The internal entry refuses absent or changed
prepared state. It runs a clean baseline, each complete listed patch serially,
and a restored baseline. Cargo-mutants labels the new patch side with its
mutation description; only these two headers are normalized for Git. The exact
listed patch body remains unchanged. Git compares and restores tracked bytes against the bound plan SHA, with new mtimes.
A provisioner moving HEAD or changing tracked source invalidates its result. Mutants that reuse
both baseline executable digests are stale, not caught. A parent-only mutation
may legitimately leave the bootstrap digest unchanged.

The script must obtain the test and bootstrap paths from Cargo JSON and copy the
current built executables into the scenario scratch before reporting digests.
It may keep build outputs only as a cache. It must install those bootstrap bytes
at the manifest's root-owned installation location, under their digest, with the
existing root:root 0755 directory and 0555 executable posture. A mutant's failed
probe cannot select a weaker provisioning route than the clean baseline.

Each viable scenario runs `normal`, `abandon`, `preparing`, `recover_abandon` and
`recover_preparing`, including the remaining phases after a behavioural failure.
Each phase uses its own fresh non-root delegated unit from the scope manifest.
Reuse the existing 120-second provisioning/collection ceiling and a 120-second
unit watchdog. Build, setup, ignored/zero selection, incomplete phases, timeout,
outer signal/OOM and cleanup failures never count as kills. If the first baseline
fails, no mutant is provisioned; the final baseline is retried and the complete
unproven population remains red.

The gate-written scope manifest has exact fields `schema`, `prefix`, `units`,
`profile`, `installation`, `scratch` and `resources`. Units have unique names
for each scenario and phase. For run 123, attempt 1, the profile is
`/etc/apparmor.d/maestro-n17-parser-123-1`, installation is
`/opt/maestro/n17/123-1`, and scratch is inside the gate's runner-temp scope.
`resources` is the exact flattened set of unit names and those three paths.
R5 must refuse escapes, symlinks, unreserved prefixes and roots it did not create.
No global AppArmor, systemd or installation cleanup is authorized.

The parent attempts teardown and source restoration even after child failure.
The job also has an independent `if: always()` cleanup step, so killing the
executor cannot suppress collection. Cleanup is idempotent and never earns
mutation credit. A missing, failed or out-of-scope cleanup receipt fails the job.
Requests, results, raw logs, `host-progress.json` and `host-interruption.json`
remain artifacts on failure. The interruption record names the complete planned
population, completed outcomes and exact identities still lacking complete proof.
It never fabricates cargo-mutants outcomes.

## Schema 1 script protocol

The script retains its no-argument entry and adds exactly:

```text
bash <tracked-provisioner> --gate-host-v1 <request-json> <result-json>
```

Request and result files are gate-controlled regular files. Request replacement
refuses existing symlinks and nonregular files, then creates the new file exclusively. Unknown or missing
fields, unsupported versions, escaping/symlink paths and mismatched features
refuse. The script must emit failure receipts too. The gate binds result bytes
to the request digest calculated before execution, not a rewritten request.

| Request field | Meaning |
| --- | --- |
| `schema` | Exactly 1 |
| `scenario` | `baseline-before`, `mutant`, `baseline-after` or `cleanup` |
| `scenario_id` | Unique label: baseline name, `mutant-0`, `mutant-1`, or `cleanup` |
| `features` | Exact planned qualified package/feature array |
| `identity` | Complete default manifest identity from the host plan |
| `policy_sha256`, `provisioner_sha256` | Exact tested policy and script digests |
| `source_sha256` | Baseline owned-source digest map |
| `mutant` | Complete discovered mutant object, or null for baselines/cleanup |
| `patched_source_sha256` | Gate-computed patched bytes, or empty for baselines/cleanup |
| `scratch`, `reports` | Exclusive scenario locations inside the gate-controlled trees |
| `baseline_posture` | Null before baseline/cleanup; otherwise `{installed, apparmor}` booleans |
| `scope_manifest`, `scope_sha256` | Exact gate-owned scope file and its digest |

These examples show the scenario-dependent fields only. The gate supplies every
common field in the table; these fragments are not standalone input files.

```json
{"scenario":"baseline-before","scenario_id":"baseline-before","mutant":null,"patched_source_sha256":"","baseline_posture":null}
```

```json
{"scenario":"mutant","scenario_id":"mutant-0","baseline_posture":{"installed":true,"apparmor":true}}
```

The mutant request also carries its complete listing object and nonempty patched
source digest, not an invented or abbreviated mutation identity.

```json
{"scenario":"baseline-after","scenario_id":"baseline-after","mutant":null,"patched_source_sha256":"","baseline_posture":{"installed":true,"apparmor":true}}
```

```json
{"scenario":"cleanup","scenario_id":"cleanup","mutant":null,"patched_source_sha256":"","baseline_posture":null}
```

A scenario result has exactly `schema`, `request_sha256`, `posture`, `artifacts`,
`cargo_json`, `installed_bootstrap` and `receipt`. `posture` has exactly the `installed` and `apparmor` booleans.
`artifacts` has exactly `test` and `bootstrap`, the current built executable
paths inside that scenario's scratch. `cargo_json` has exactly `test` and
`bootstrap`, artifact-relative Cargo JSON paths which must also appear in
`receipt.logs`. Each log must end in a successful `build-finished` record and
identify exactly one current executable of its role inside the executor root.
The gate hashes these current build outputs as well as their scenario copies,
so a changed parent test cannot legitimize baseline bootstrap bytes.

`installed=false` requires `installed_bootstrap:null`. `installed=true` requires
an exact regular file under the manifest installation's current bootstrap digest
directory. The gate uses lstat throughout, refuses symlink components and checks
uid 0, gid 0, mode 0555 and bytes matching the current Cargo-built bootstrap.
Installation directories must be root:root 0755. These production identities
are fixed. Private unit fixtures pass their actual owner through a mandatory
private parameter; there is no production environment override. Wrong owner,
mode, root, digest or null/path relationship refuses with a named reason.
The gate recomputes every nonempty raw-log digest. `receipt` is the exact R3 receipt defined
above: baselines omit `test_failure`, while mutant receipts require it, including
an empty array on a survivor. Statuses are `passed`, `failed` or `not-run`;
counters are nonnegative integers and selection is unique. Only a complete
named failure after successful build, provisioning and cleanup becomes `caught`.
Every failed phase is named, and the number of named Rust failures equals
`failed`. Timeout/signal process status overrides receipt and artifact classifications.
Receipt and artifact problems remain diagnostics for an interrupted process.

A cleanup result has exactly `schema`, `request_sha256`, `cleanup`, `removed`
and `absent`. Cleanup must be `passed`, and the disjoint union of the unique
`removed` and `absent` arrays must equal the exact manifest resource set. A
second cleanup returns no removed resources. Receipts outside that set refuse.

## Budgets and qualification

The required Ubuntu job is 60 minutes, the executor step 35, and the inner
command 30 with a one-minute kill-after: `30 + 1 < 35 < 60`. The independent
cleanup step is five minutes around its reused 120-second command and one-minute
kill-after. Seven-day artifact retention and the ten-minute aggregate job are
unchanged. Pi's installed subagent documentation uses a 30-minute run backstop
and a 300000 ms HTTP idle timeout. The latter is not a kernel watchdog. Live Pi
settings do not override these defaults; Pi has no host-provisioning or artifact
retention equivalent. Serial execution is required by scoped profile and
installation lifecycle, not Pi's default four-agent concurrency.

[The synthetic qualification workflow](../.github/workflows/host-executor-fixture.yml)
runs actual pinned discovery, Cargo JSON builds and executable assertions on
Ubuntu. It observes one caught and one surviving mutation, asserts that the
partition returned failure and retains logs and successful cleanup receipts.
Its outer test passes only when that expected red partition is observed. The
synthetic provisioner uses ordinary processes and, on GitHub, a scoped root-owned
bootstrap installation with marker-bound always-run cleanup. It additionally
refuses baseline installed bootstrap bytes under a changed parent test binary.
It claims no AppArmor, delegated-cgroup or parser-containment qualification. R5's real host
assertions and mutated-bootstrap sentinel remain mandatory before adoption.
