#!/usr/bin/env bash

# Evaluate the PostgreSQL N-1 check for one exact pull-request head. This file
# is checked out from main by a pull_request_target/workflow_run workflow; no
# candidate-owned gate code is executed.

set -euo pipefail

POSTGRESQL_N1_CHECK="verify-postgresql-n1"
POSTGRESQL_N1_WORKFLOW="SaaS N-1 compatibility image"
POSTGRESQL_N1_WORKFLOW_PATH=".github/workflows/saas-n1-compat-image.yml"
POSTGRESQL_N1_WORKFLOW_SHA256="8bca805eb58a4739a73478105233801409454d4defb4f2c9e082eb61b9673f52"

# Candidate inputs that can change pytest collection, dependency resolution,
# fixtures, or the selected assertions are pinned by the trusted main policy.
POSTGRESQL_N1_TRUSTED_INPUTS=(
  "pyproject.toml|c4b9baa229972c36302ff2b358102db9968319fac9e0ca062515c939fcddd941"
  "uv.lock|0b4f16e857a865d5483432d440205667c62bc7a9fe109bf46532ecb538d78586"
  "tests/__init__.py|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  "tests/_model_pools.py|d25fda757b12bffbaa6a42e468f625f715cc3ee37df7f9b5af4b8d70af781362"
  "tests/_token_usage.py|25dbfbc0caea11edd4be3bb3eb530e2a784e9c98e6e2f652beeddae7b7071fa8"
  "tests/conftest.py|366d658c3cc67dca4c02f32e36c2424c57377f534c9ea03efcca21f294ff4104"
  "tests/saas/__init__.py|7c14e27fe713806e1e8fe6d3034333e8fb9442289484cf8778ec88c754c7181d"
  "tests/saas/conftest.py|5e1c588076fd6f7976e81cdc58047d5d21830b393af496b158907af0dfc7339c"
  "tests/saas/test_n1_compat_patch.py|31bc0247e238e36fa3c8af0f0061f35c27a8432327377d6f8edb3ffe568ac7db"
  "tests/saas/test_n1_outbox_admission.py|852466d5c52d01a8832afabd1a135b715d27a23162efec95d4ce924fdf0ebfa1"
  "tests/saas/test_control_plane_migration.py|e1a3cdbe178d6a758cd813ada732cb0ab3320f7e40f20eb77de80c0b0798cee0"
)

POSTGRESQL_N1_PATHS=(
  ".github/actions/compat-smoke-saas-n1-gate/**"
  ".github/workflows/saas-n1-merge-gate.yml"
  ".github/workflows/saas-n1-compat-image.yml"
  ".python-version"
  ".uv/**"
  ".venv/**"
  "conftest.py"
  "deploy/docker/Dockerfile"
  "pyproject.toml"
  "pytest.ini"
  "setup.cfg"
  "setup.py"
  "tox.ini"
  "uv.toml"
  "uv.lock"
  "saas/**"
  "tests/conftest.py"
  "tests/saas/**"
)

POSTGRESQL_N1_POLICY_PATHS=(
  ".github/actions/compat-smoke-saas-n1-gate/**"
  ".github/workflows/saas-n1-merge-gate.yml"
)

POSTGRESQL_N1_FORBIDDEN_PATHS=(
  ".uv/**"
  ".venv/**"
)

PRIVILEGED_AUTOMATION_PATHS=(
  ".github/actions/**"
  ".github/workflows/**"
)

fail() {
  echo "::error::$*"
  exit 1
}

matches_any() {
  local path=$1
  shift
  local pattern
  for pattern in "$@"; do
    if [[ "$path" == $pattern ]]; then
      return 0
    fi
  done
  return 1
}

requires_postgresql_n1() {
  local path
  while IFS= read -r path; do
    matches_any "$path" "${POSTGRESQL_N1_PATHS[@]}" && return 0
  done
  return 1
}

changes_postgresql_n1_policy() {
  local path
  while IFS= read -r path; do
    matches_any "$path" "${POSTGRESQL_N1_POLICY_PATHS[@]}" && return 0
  done
  return 1
}

changes_forbidden_environment() {
  local path
  while IFS= read -r path; do
    matches_any "$path" "${POSTGRESQL_N1_FORBIDDEN_PATHS[@]}" && return 0
  done
  return 1
}

changes_untrusted_automation() {
  local path
  while IFS= read -r path; do
    # The candidate workflow is the one automation change allowed through this
    # gate, and only at the byte-exact digest pinned below. Any other workflow
    # or action could mint a same-app status and therefore needs an explicit
    # administrator merge.
    [[ "$path" == "$POSTGRESQL_N1_WORKFLOW_PATH" ]] && continue
    matches_any "$path" "${PRIVILEGED_AUTOMATION_PATHS[@]}" && return 0
  done
  return 1
}

if ! [[ "${PR:-}" =~ ^[0-9]+$ ]] || ! [[ "${SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  fail "PR and full head SHA are required"
fi

PR_METADATA=$(gh api "repos/$REPO/pulls/$PR" \
  --jq '[.state, .head.sha, .base.ref, .base.sha, (.changed_files | tostring)] | @tsv')
IFS=$'\t' read -r PR_STATE PR_HEAD_SHA PR_BASE_REF PR_BASE_SHA \
  PR_CHANGED_FILES <<<"$PR_METADATA"
if [[ "$PR_STATE" != "open" ]] || [[ "$PR_BASE_REF" != "main" ]] || \
   [[ "$PR_HEAD_SHA" != "$SHA" ]] || ! [[ "$PR_BASE_SHA" =~ ^[0-9a-f]{40}$ ]] || \
   ! [[ "$PR_CHANGED_FILES" =~ ^[0-9]+$ ]]; then
  fail "PR is not an open main-targeting PR at exact head SHA $SHA"
fi

PR_FILE_ROWS=$(gh api "repos/$REPO/pulls/$PR/files" --paginate \
  --jq '.[] | [.filename, (.previous_filename // "")] | @tsv')
PR_FILE_COUNT=$(printf '%s\n' "$PR_FILE_ROWS" | awk 'NF {count++} END {print count + 0}')
[[ "$PR_FILE_COUNT" -eq "$PR_CHANGED_FILES" ]] || fail "PR file pagination is incomplete"
PR_FILES=$(printf '%s\n' "$PR_FILE_ROWS" | awk -F'\t' \
  '{print $1; if ($2 != "") print $2}')

if changes_forbidden_environment <<<"$PR_FILES"; then
  fail "Committed .uv/.venv state requires an explicit administrator merge"
fi
if changes_postgresql_n1_policy <<<"$PR_FILES"; then
  fail "PostgreSQL N-1 gate policy changes require an explicit administrator merge"
fi
if changes_untrusted_automation <<<"$PR_FILES"; then
  fail "GitHub Actions policy changes require an explicit administrator merge"
fi
if ! requires_postgresql_n1 <<<"$PR_FILES"; then
  echo "SaaS PostgreSQL N-1 gate is not required for this PR."
  exit 0
fi

[[ "$POSTGRESQL_N1_WORKFLOW_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
  fail "trusted PostgreSQL N-1 workflow digest is not configured"
OBSERVED_WORKFLOW_SHA256=$(gh api \
  -H 'Accept: application/vnd.github.raw+json' \
  "repos/$REPO/contents/$POSTGRESQL_N1_WORKFLOW_PATH?ref=$SHA" \
  | shasum -a 256 | awk '{print $1}')
[[ "$OBSERVED_WORKFLOW_SHA256" == "$POSTGRESQL_N1_WORKFLOW_SHA256" ]] || \
  fail "PostgreSQL N-1 workflow bytes do not match trusted main policy"

for trusted_input in "${POSTGRESQL_N1_TRUSTED_INPUTS[@]}"; do
  trusted_path="${trusted_input%%|*}"
  trusted_sha256="${trusted_input#*|}"
  observed_sha256=$(gh api \
    -H 'Accept: application/vnd.github.raw+json' \
    "repos/$REPO/contents/$trusted_path?ref=$SHA" \
    | shasum -a 256 | awk '{print $1}')
  [[ "$observed_sha256" == "$trusted_sha256" ]] || \
    fail "PostgreSQL N-1 trusted input drift: $trusted_path"
done

# The latest exact workflow run is authoritative, including its rerun attempt.
# This prevents an older successful check-run from surviving while a newer
# attempt is queued, in progress, or failed.
N1_RUN_ROWS=$(gh api \
  "repos/$REPO/actions/workflows/saas-n1-compat-image.yml/runs?event=pull_request&head_sha=$SHA&per_page=100" \
  --paginate \
  --jq '.workflow_runs[] | [(.id | tostring), (.run_attempt | tostring), .status, (.conclusion // "null"), .name, .display_title, .path, .event, .head_sha] | @tsv')
LATEST_N1_RUN=$(printf '%s\n' "$N1_RUN_ROWS" \
  | awk -F'\t' -v name="$POSTGRESQL_N1_WORKFLOW" \
      -v path="$POSTGRESQL_N1_WORKFLOW_PATH" -v sha="$SHA" \
      '$5 == name && $7 == path && $8 == "pull_request" && $9 == sha' \
  | sort -t$'\t' -k1,1nr -k2,2nr | head -n1)
[[ -n "$LATEST_N1_RUN" ]] || fail "exact PostgreSQL N-1 workflow run is missing"
IFS=$'\t' read -r AUTHORITATIVE_RUN_ID AUTHORITATIVE_RUN_ATTEMPT \
  AUTHORITATIVE_RUN_STATUS AUTHORITATIVE_RUN_CONCLUSION _ \
  AUTHORITATIVE_RUN_TITLE _ _ _ <<<"$LATEST_N1_RUN"
EXPECTED_RUN_TITLE="SaaS N-1 pull_request pr=$PR base=$PR_BASE_SHA head=$SHA"
[[ "$AUTHORITATIVE_RUN_TITLE" == "$EXPECTED_RUN_TITLE" ]] || \
  fail "latest PostgreSQL N-1 workflow run title does not bind this PR/base/head"
if [[ "$AUTHORITATIVE_RUN_STATUS" != "completed" ]] || \
   [[ "$AUTHORITATIVE_RUN_CONCLUSION" != "success" ]]; then
  fail "latest PostgreSQL N-1 workflow run $AUTHORITATIVE_RUN_ID attempt $AUTHORITATIVE_RUN_ATTEMPT is not successful"
fi

N1_CANDIDATES=$(gh api "repos/$REPO/commits/$SHA/check-runs" --paginate \
  --jq '.check_runs[] | select(.name == "verify-postgresql-n1") | [.id, .status, (.conclusion // "null"), .details_url, .app.slug] | @tsv')
TRUSTED_RUNS=""
while IFS=$'\t' read -r check_id check_status check_conclusion details_url app_slug; do
  [[ -z "$check_id" ]] && continue
  [[ "$app_slug" == "github-actions" ]] || continue
  if ! [[ "$details_url" =~ ^https://github.com/$REPO/actions/runs/([0-9]+)/job/([0-9]+)$ ]]; then
    continue
  fi
  run_id="${BASH_REMATCH[1]}"
  job_id="${BASH_REMATCH[2]}"
  [[ "$job_id" == "$check_id" ]] || continue
  [[ "$run_id" == "$AUTHORITATIVE_RUN_ID" ]] || continue

  run_metadata=$(gh api "repos/$REPO/actions/runs/$run_id" \
    --jq '[.name, .display_title, .path, .event, .status, (.conclusion // "null"), .head_sha, (.id | tostring), (.run_attempt | tostring)] | @tsv') || continue
  IFS=$'\t' read -r run_name run_display_title run_path run_event run_status \
    run_conclusion run_head_sha observed_run_id observed_run_attempt <<<"$run_metadata"
  if [[ "$run_name" != "$POSTGRESQL_N1_WORKFLOW" ]] || \
     [[ "$run_display_title" != "$EXPECTED_RUN_TITLE" ]] || \
     [[ "$run_path" != "$POSTGRESQL_N1_WORKFLOW_PATH" ]] || \
     [[ "$run_event" != "pull_request" ]] || \
     [[ "$run_head_sha" != "$SHA" ]] || \
     [[ "$observed_run_id" != "$run_id" ]] || \
     [[ "$observed_run_attempt" != "$AUTHORITATIVE_RUN_ATTEMPT" ]] || \
     [[ "$run_status" != "$check_status" ]] || \
     [[ "$run_conclusion" != "$check_conclusion" ]]; then
    continue
  fi

  job_metadata=$(gh api "repos/$REPO/actions/jobs/$job_id" \
    --jq '[.name, .status, (.conclusion // "null"), .head_sha, (.run_id | tostring), (.run_attempt | tostring), .workflow_name] | @tsv') || continue
  IFS=$'\t' read -r job_name job_status job_conclusion job_head_sha \
    observed_job_run_id observed_job_run_attempt job_workflow_name <<<"$job_metadata"
  if [[ "$job_name" != "$POSTGRESQL_N1_CHECK" ]] || \
     [[ "$job_status" != "$check_status" ]] || \
     [[ "$job_conclusion" != "$check_conclusion" ]] || \
     [[ "$job_head_sha" != "$SHA" ]] || \
     [[ "$observed_job_run_id" != "$run_id" ]] || \
     [[ "$observed_job_run_attempt" != "$AUTHORITATIVE_RUN_ATTEMPT" ]] || \
     [[ "$job_workflow_name" != "$POSTGRESQL_N1_WORKFLOW" ]]; then
    continue
  fi
  TRUSTED_RUNS+="$run_id"$'\t'"$check_status"$'\t'"$check_conclusion"$'\n'
done <<<"$N1_CANDIDATES"

LATEST_TRUSTED=$(printf '%s' "$TRUSTED_RUNS" | sort -t$'\t' -k1,1nr | head -n1)
[[ -n "$LATEST_TRUSTED" ]] || fail "trusted verify-postgresql-n1 check is missing"
IFS=$'\t' read -r latest_run_id latest_status latest_conclusion <<<"$LATEST_TRUSTED"
if [[ "$latest_status" != "completed" ]] || [[ "$latest_conclusion" != "success" ]]; then
  fail "latest trusted verify-postgresql-n1 run $latest_run_id is not successful"
fi

echo "Trusted PostgreSQL N-1 check accepted for PR #$PR at $SHA (run $latest_run_id)."
