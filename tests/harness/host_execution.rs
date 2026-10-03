//! A real Cargo consumer exercising the same host executor protocol on local and hosted runs.

use super::engine_workspace::fixture_git;
use super::fixture::Fixture;
use super::host_fixture::host_fixture;
use std::{env, fs, path::PathBuf};

/// Real discovery, Cargo JSON builds and executable assertions; no Cargo stand-in.
pub(crate) fn execution_fixture(survivor: bool) -> Fixture {
    let mut fixture = host_fixture();
    fs::remove_file(fixture.root.join("bin/cargo")).unwrap();
    fixture.set(
        "CARGO_HOME",
        &fixture.root.join("cargo-home").display().to_string(),
    );
    let project = fixture.root.join("project");
    fs::write(
        project.join("src/host.rs"),
        "pub fn caught() -> bool { true }\npub fn survivor() -> bool { true }\n",
    )
    .unwrap();
    fs::write(
        project.join("src/lib.rs"),
        format!(
            concat!(
                "pub mod host;\n#[cfg(test)] mod tests {{\n",
                "#[test] fn required_assertion_selects_host() {{ ",
                "assert!(super::host::caught()); {} }}\n}}\n"
            ),
            if survivor {
                ""
            } else {
                "assert!(super::host::survivor());"
            }
        ),
    )
    .unwrap();
    fs::write(
        project.join("src/main.rs"),
        "fn main() { println!(\"{} {}\", fixture::host::caught(), fixture::host::survivor()); }\n",
    )
    .unwrap();
    fs::write(
        project.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(project.join(".github/scripts/host.sh"), SCRIPT).unwrap();
    fixture_git(&project, &["add", "."]);
    fixture_git(
        &project,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "protocol",
        ],
    );
    fixture_git(
        &project,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "head",
        ],
    );
    fixture.set("GITHUB_SHA", &fixture_git(&project, &["rev-parse", "HEAD"]));
    fixture.set(
        "WORKFLOW_REVISION",
        &env::var("WORKFLOW_REVISION").unwrap_or_default(),
    );
    for name in ["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"] {
        if let Ok(value) = env::var(name) {
            fixture.set(name, &value);
        }
    }
    fixture.set(
        "MUTATION_HOST_PLAN",
        &fixture
            .root
            .join("reports/mutation-host-plan.json")
            .display()
            .to_string(),
    );
    retain_qualification_scope(&mut fixture, survivor);
    fixture
}

/// Preserve only the synthetic workflow's scope and cleanup inputs before administrative work.
fn retain_qualification_scope(fixture: &mut Fixture, survivor: bool) {
    if let Ok(output) = env::var("HOST_QUALIFICATION_REPORTS") {
        let case = if survivor {
            "caught-survivor"
        } else {
            "install-sentinel"
        };
        fixture.set("HOST_FIXTURE_CASE", case);
        let output = PathBuf::from(output).join(case);
        fs::create_dir_all(&output).unwrap();
        fixture.set(
            "HOST_FIXTURE_INSTALL",
            if env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
                "true"
            } else {
                "false"
            },
        );
        fs::write(
            output.join("cleanup-env.json"),
            serde_json::to_vec(&fixture.env).unwrap(),
        )
        .unwrap();
    }
}

/// Synthetic resources are ordinary files, never claims of kernel containment qualification.
const SCRIPT: &str = r#"#!/bin/bash
set -euo pipefail
[[ "$1" == --gate-host-v1 && $# == 3 ]]
request=$2
result=$3
jaq -e 'keys ==
["baseline_posture","features","identity","mutant","patched_source_sha256",
 "policy_sha256","provisioner_sha256","reports","scenario","scenario_id","schema",
 "scope_manifest","scope_sha256","scratch","source_sha256"]
and .schema == 1 and .features == ["fixture/host-tests"]' "$request" >/dev/null
get() { jaq -r "$1" "$request"; }
scenario=$(get '.scenario_id')
scratch=$(get '.scratch')
reports=$(get '.reports')
scope=$(get '.scope_manifest')
[[ $(sha256sum "$scope" | cut -d' ' -f1) == "$(get '.scope_sha256')" ]]
request_hash=$(sha256sum "$request" | cut -d' ' -f1)
installation=$(jaq -r '.installation' "$scope")
[[ "$installation" == "/opt/maestro/n17/$(get '.identity.run_id')-$(get '.identity.attempt')" ]]
scope_hash=$(get '.scope_sha256')
if [[ "$scenario" == cleanup ]]; then
  removed='[]'
  absent=$(jaq -c '.resources' "$scope")
  for owned in "$(jaq -r '.scratch' "$scope")" "$installation"; do
    if [[ -e "$owned" || -L "$owned" ]]; then
      [[ ! -L "$owned" && -d "$owned" ]]
      if [[ "$owned" == "$installation" ]]; then
        [[ "${HOST_FIXTURE_INSTALL:-false}" == true ]]
        [[ $(sudo stat -c '%u:%g' "$installation") == 0:0 ]]
        [[ ! -L "$installation/.gate-host-scope" ]]
        [[ $(sudo cat "$installation/.gate-host-scope") == "$scope_hash" ]]
        sudo rm -r -- "$installation"
      else
        [[ "$owned" == "${RUNNER_TEMP%/}/host-executor/scratch" ]]
        [[ $(stat -c %u "$owned") == "$(id -u)" ]]
        [[ ! -L "$owned/.gate-host-scope" && -f "$owned/.gate-host-scope" ]]
        [[ $(cat "$owned/.gate-host-scope") == "$scope_hash" ]]
        rm -r -- "$owned"
      fi
      removed=$(jaq -cn --argjson r "$removed" --arg p "$owned" '$r+[$p]')
      absent=$(jaq -cn --argjson a "$absent" --arg p "$owned" '$a|map(select(. != $p))')
    fi
  done
  if [[ "${HOST_FIXTURE_MODE:-ordinary}" == cleanup-outside ]]; then
    removed=$(jaq -cn --argjson r "$removed" '$r+["outside-scope.service"]')
  fi
  if [[ "${HOST_FIXTURE_MODE:-ordinary}" == cleanup-fail ]]; then exit 1; fi
  mode=${HOST_FIXTURE_MODE:-ordinary}
  tree="${scope%/*}/checkout"
  if [[ "$mode" == cleanup-commit || "$mode" == cleanup-source ]]; then
    printf '\n// cleanup committed change\n' >> "$tree/src/lib.rs"
    git -C "$tree" add src/lib.rs
  fi
  if [[ "$mode" == cleanup-commit || "$mode" == cleanup-empty ]]; then
    git -C "$tree" -c user.name=Fixture -c user.email=fixture@example.invalid \
      -c commit.gpgsign=false commit --allow-empty -qm 'cleanup source change'
  fi
  if [[ "$mode" == cleanup-reset ]]; then
    git -C "$tree" reset --hard "$(get '.identity.sha')"
  fi
  jaq -n --arg hash "$request_hash" --argjson removed "$removed" --argjson absent "$absent" \
    '{schema:1,request_sha256:$hash,cleanup:"passed",removed:$removed,absent:$absent}' > "$result"
  case "${HOST_FIXTURE_MODE:-ordinary}" in
    cleanup-schema) change='.schema=2' ;;
    cleanup-binding) change='.request_sha256="wrong"' ;;
    cleanup-unknown) change='.unknown=true' ;;
    *) exit 0 ;;
  esac
  jaq "$change" "$result" > "$result.tmp"
  mv "$result.tmp" "$result"
  exit 0
fi
printf '%s\n' "$scope_hash" > "$(dirname "$scratch")/.gate-host-scope"
mode=${HOST_FIXTURE_MODE:-ordinary}
if [[ "$mode" == source-* && "$scenario" == baseline-before ]]; then
  if [[ "$mode" == source-commit ]]; then printf '\n// committed source change\n' >> src/lib.rs; fi
  git add src/lib.rs
  git -c user.name=Fixture -c user.email=fixture@example.invalid \
    -c commit.gpgsign=false commit --allow-empty -qm 'changed source'
fi
if [[ "$mode" == hang ]]; then
  touch "$scratch/active"
  sleep 60
fi
cache=$(dirname "$scratch")/build-cache
if [[ "${HOST_FIXTURE_WARM_CACHE:-false}" == true ]]; then
  cache="${RUNNER_TEMP%/}/host-executor/build-cache"
fi
cargo test --locked --offline --features fixture/host-tests --no-run --lib --message-format=json \
  --target-dir "$cache" > "$reports/cargo-test.json" 2> "$reports/build.log"
cargo build --locked --offline --features fixture/host-tests --message-format=json \
  --target-dir "$cache" > "$reports/cargo-bootstrap.json" 2>> "$reports/build.log"
test=$(jaq -r 'select(.reason == "compiler-artifact"
 and .profile.test == true and .executable != null)|.executable' "$reports/cargo-test.json")
bootstrap=$(jaq -r 'select(.reason == "compiler-artifact"
 and .target.kind == ["bin"] and .executable != null)|.executable' "$reports/cargo-bootstrap.json")
cp -- "$test" "$scratch/test"
cp -- "$bootstrap" "$scratch/bootstrap"
test="$scratch/test"
bootstrap="$scratch/bootstrap"
installed=false
installed_path=''
if [[ "${HOST_FIXTURE_INSTALL:-false}" == true ]]; then
  if [[ -e "$installation" ]]; then
    [[ $(sudo cat "$installation/.gate-host-scope") == "$scope_hash" ]]
  else
    sudo install -d -o root -g root -m0755 "$installation"
    printf '%s\n' "$scope_hash" > "$scratch/marker"
    sudo install -o root -g root -m0644 "$scratch/marker" "$installation/.gate-host-scope"
  fi
  digest=$(sha256sum "$bootstrap" | cut -d' ' -f1)
  installed_path="$installation/$digest/bootstrap"
  sudo install -d -o root -g root -m0755 "$installation/$digest"
  bytes="$bootstrap"
  if [[ "$mode" == install-stale && "$scenario" == mutant-* ]]; then
    bytes=$(jaq -r '.artifacts.bootstrap' "$(dirname "$reports")/baseline-before/result.json")
  fi
  sudo install -o root -g root -m0555 "$bytes" "$installed_path"
  installed=true
  "$installed_path" > "$reports/installed-bootstrap.log"
fi
selected=$("$test" --list | sed -n 's/: test$//p')
total=1
if [[ "$mode" == zero && "$scenario" == mutant-* ]]; then selected=""; total=0; fi
# Five independent processes, just as real provisioners must use five fresh delegated units.
phases='{}'
failures='[]'
failed=0
for phase in normal abandon preparing recover_abandon recover_preparing; do
  status=passed
  if ! "$test" --exact "$selected" > "$reports/$phase.log" 2>&1; then
    status=failed
    failures=$(jaq -cn --argjson f "$failures" --arg p "$phase" '$f+[$p]')
    failed=1
  fi
  phases=$(jaq -cn --argjson p "$phases" --arg phase "$phase" \
    --arg status "$status" '$p+{($phase):$status}')
done
status=passed
if (( failed != 0 )); then
  status=failed
  failures=$(jaq -cn --argjson f "$failures" --arg p "$selected" '$f+[$p]')
fi
test_hash=$(sha256sum "$test" | cut -d' ' -f1)
bootstrap_hash=$(sha256sum "$bootstrap" | cut -d' ' -f1)
logs='{}'
for phase in build normal abandon preparing recover_abandon recover_preparing; do
  name="$scenario/$phase.log"
  hash=$(sha256sum "$reports/$phase.log" | cut -d' ' -f1)
  logs=$(jaq -cn --argjson logs "$logs" --arg name "$name" \
    --arg hash "$hash" '$logs+{($name):$hash}')
done
for json in cargo-test.json cargo-bootstrap.json; do
  name="$scenario/$json"
  hash=$(sha256sum "$reports/$json" | cut -d' ' -f1)
  logs=$(jaq -cn --argjson logs "$logs" --arg name "$name" \
    --arg hash "$hash" '$logs+{($name):$hash}')
done
jaq -n --arg request "$request_hash" --arg test "$test" --arg bootstrap "$bootstrap" \
  --arg th "$test_hash" --arg bh "$bootstrap_hash" --arg selected "$selected" \
  --argjson installed "$installed" --arg ip "$installed_path" \
  --arg status "$status" --arg scenario "$scenario" --argjson total "$total" \
  --argjson failed "$failed" --argjson phases "$phases" \
  --argjson failures "$failures" --argjson logs "$logs" \
  '{schema:1,request_sha256:$request,posture:{installed:$installed,apparmor:false},
installed_bootstrap:(if $installed then $ip else null end),
cargo_json:{test:($scenario+"/cargo-test.json"),
bootstrap:($scenario+"/cargo-bootstrap.json")},artifacts:{test:$test,
bootstrap:$bootstrap},receipt:{build:"passed",provision:"passed",test:$status,
cleanup:"passed",selected_tests:(if $total == 0 then [] else [$selected] end),
passed:($total-$failed),failed:$failed,ignored:0,phases:$phases,test_sha256:$th,
bootstrap_sha256:$bh,test_failure:$failures,logs:$logs}}' > "$result"
if [[ "$scenario" != mutant-* ]]; then
  jaq 'del(.receipt.test_failure)' "$result" > "$result.tmp"
  mv "$result.tmp" "$result"
fi
if [[ "$mode" == baseline && "$scenario" == baseline-before ]] \
  || [[ "$mode" == after && "$scenario" == baseline-after ]]; then
  jaq '.receipt.provision="failed"' "$result" > "$result.tmp"
  mv "$result.tmp" "$result"
fi
if [[ "$scenario" == mutant-* ]]; then
  case "$mode" in
    build|provision|cleanup)
      jaq --arg field "$mode" '.receipt[$field]="failed"' "$result" > "$result.tmp"
      mv "$result.tmp" "$result" ;;
    unknown) jaq '.unknown=true' "$result" > "$result.tmp"; mv "$result.tmp" "$result" ;;
    source) printf '\n// changed source\n' >> src/lib.rs ;;
    artifact) printf 'stale executable\n' > "$test" ;;
    baseline-bootstrap)
      parent=$(dirname "$reports")
      previous=$(jaq -r '.artifacts.bootstrap' "$parent/baseline-before/result.json")
      cp -- "$previous" "$bootstrap"
      jaq --slurpfile b "$parent/baseline-before/result.json" \
        '.receipt.bootstrap_sha256=$b[0].receipt.bootstrap_sha256' "$result" > "$result.tmp"
      mv "$result.tmp" "$result" ;;
    binding) jaq '.request_sha256="wrong"' "$result" > "$result.tmp"; mv "$result.tmp" "$result" ;;
    incomplete)
      jaq '.receipt.phases.recover_preparing="not-run"' "$result" > "$result.tmp"
      mv "$result.tmp" "$result" ;;
    timeout-invalid|oom-invalid)
      printf '{}' > "$result"
      if [[ "$mode" == oom-invalid ]]; then kill -KILL $$; fi
      exit 124 ;;
    timeout-artifact)
      printf 'stale executable\n' > "$test"
      exit 124 ;;
    timeout-stale)
      jaq --slurpfile b "$(dirname "$reports")/baseline-before/result.json" \
        '.receipt.test_sha256=$b[0].receipt.test_sha256|
.receipt.bootstrap_sha256=$b[0].receipt.bootstrap_sha256' "$result" > "$result.tmp"
      mv "$result.tmp" "$result"
      exit 124 ;;
    timeout) timeout 0.05s sleep 60 ;;
    oom) kill -KILL $$ ;;
    stale)
      jaq --slurpfile b "$(dirname "$reports")/baseline-before/result.json" \
        '.artifacts=$b[0].artifacts|.receipt.test_sha256=$b[0].receipt.test_sha256|
.receipt.bootstrap_sha256=$b[0].receipt.bootstrap_sha256' \
        "$result" > "$result.tmp"
      mv "$result.tmp" "$result" ;;
  esac
fi
"#;
