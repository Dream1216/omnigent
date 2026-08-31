#!/usr/bin/env bash

# Evaluate the PostgreSQL N-1 check for one exact pull-request head. This file
# is checked out from main by a pull_request_target/workflow_run workflow; no
# candidate-owned gate code is executed.

set -euo pipefail

POSTGRESQL_N1_CHECK="verify-postgresql-n1"
POSTGRESQL_N1_WORKFLOW_NAME="SaaS N-1 compatibility image"
POSTGRESQL_N1_WORKFLOW_ID="342012814"
POSTGRESQL_N1_WORKFLOW_PATH=".github/workflows/saas-n1-compat-image.yml"
POSTGRESQL_N1_WORKFLOW_SHA256="a913b18b3216fd2a77b9297f13ec0e5a50e1ca6d9c5af12d0dc33c218554f4d9"
POSTGRESQL_N1_ACTIONS_APP_ID="15368"

# Candidate inputs that can change pytest collection, dependency resolution,
# fixtures, or the selected assertions are pinned by the trusted main policy.
POSTGRESQL_N1_TRUSTED_INPUTS=(
  "pyproject.toml|dd8a302d7f87dd7e5d4b6fa7220820ba0751c885e4628db33e423dbafed444e0"
  "uv.lock|5f4577d6500fc70e02ad8efe4608f5071318d6a82893ecea52cd77bf4b3c9505"
  "tests/__init__.py|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  "tests/_model_pools.py|d25fda757b12bffbaa6a42e468f625f715cc3ee37df7f9b5af4b8d70af781362"
  "tests/_token_usage.py|25dbfbc0caea11edd4be3bb3eb530e2a784e9c98e6e2f652beeddae7b7071fa8"
  "tests/conftest.py|a7a137d49f0ac6664381d89a2e21ef56db2cb6918907460ed253045f9605a4d8"
  "tests/saas/__init__.py|7c14e27fe713806e1e8fe6d3034333e8fb9442289484cf8778ec88c754c7181d"
  "tests/saas/conftest.py|5e1c588076fd6f7976e81cdc58047d5d21830b393af496b158907af0dfc7339c"
  "tests/saas/test_n1_compat_patch.py|5b37577efadb67db9b6eeb60e1c4f6f442cf9360765766e5f4bb7dab02329425"
  "tests/saas/test_image_supply_chain.py|2861e8d2aac57f377dc358295ebcb97ed045ff1189d4ca1079f4decf40a2fc7f"
  "saas/scripts/build_n1_compat.py|a500e888307c0a1fbddf674789c975bd24aeeb16b9db0bb21a3724505157488b"
  "saas/scripts/compare_oci_rebuilds.py|050e397b74632d407fb8d7f115de4b75f4e3b7e19e99d8fe394fe9595fd515bc"
  "saas/n1_compat/manifest.json|d1ac950f3578d1a053900d394ae42375970df3fb9774a4f27f512476538d0099"
  "saas/n1_compat/Dockerfile|1c5c9b91a566fe334f90b6b14e62d378139f56214081157e591bce94f3930567"
  "saas/n1_compat/Dockerfile.dockerignore|72aa85a2e1e88d468d3843d18199b1d0959a7ba4b3227c4354c722c4461f3275"
  "saas/n1_compat/build-requirements.txt|f258dfd1257091c9942501adc5106bee29806def12abd16d48feecabceb3ca29"
  "tests/saas/test_n1_merge_gate_candidate.py|9152d911ec1ccf11399c304961e57964c1a937e49584262c5ebcb7610189c967"
  "tests/saas/test_n1_merge_gate.py|d37d3dfc19d280579e6c9ec23781fba84a74a19d00ff9c2615f5d0a80a112a04"
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
WORKFLOW_METADATA=$(gh api \
  "repos/$REPO/actions/workflows/$POSTGRESQL_N1_WORKFLOW_ID" \
  --jq '[(.id | tostring), .name, .path, .state] | @tsv')
IFS=$'\t' read -r OBSERVED_WORKFLOW_ID OBSERVED_WORKFLOW_NAME \
  OBSERVED_WORKFLOW_PATH OBSERVED_WORKFLOW_STATE <<<"$WORKFLOW_METADATA"
[[ "$OBSERVED_WORKFLOW_ID" == "$POSTGRESQL_N1_WORKFLOW_ID" ]] && \
  [[ "$OBSERVED_WORKFLOW_NAME" == "$POSTGRESQL_N1_WORKFLOW_NAME" ]] && \
  [[ "$OBSERVED_WORKFLOW_PATH" == "$POSTGRESQL_N1_WORKFLOW_PATH" ]] && \
  [[ "$OBSERVED_WORKFLOW_STATE" == "active" ]] || \
  fail "PostgreSQL N-1 workflow registry identity drifted"

N1_RUN_ROWS=$(gh api \
  "repos/$REPO/actions/workflows/$POSTGRESQL_N1_WORKFLOW_ID/runs?event=pull_request&head_sha=$SHA&per_page=100" \
  --paginate \
  --jq '.workflow_runs[] | [(.id | tostring), (.run_attempt | tostring), .status, (.conclusion // "null"), (.workflow_id | tostring), .display_title, .path, .event, .head_sha] | @tsv')
LATEST_N1_RUN=$(printf '%s\n' "$N1_RUN_ROWS" \
  | awk -F'\t' -v workflow_id="$POSTGRESQL_N1_WORKFLOW_ID" \
      -v path="$POSTGRESQL_N1_WORKFLOW_PATH" -v sha="$SHA" \
      '$5 == workflow_id && $7 == path && $8 == "pull_request" && $9 == sha' \
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

AUTHORITATIVE_RUN_METADATA=$(gh api \
  "repos/$REPO/actions/runs/$AUTHORITATIVE_RUN_ID" \
  --jq '[(.workflow_id | tostring), .display_title, .path, .event, .status, (.conclusion // "null"), .head_sha, (.id | tostring), (.run_attempt | tostring), (.check_suite_id | tostring)] | @tsv')
IFS=$'\t' read -r RUN_WORKFLOW_ID RUN_DISPLAY_TITLE RUN_PATH RUN_EVENT \
  RUN_STATUS RUN_CONCLUSION RUN_HEAD_SHA RUN_ID RUN_ATTEMPT \
  AUTHORITATIVE_CHECK_SUITE_ID <<<"$AUTHORITATIVE_RUN_METADATA"
[[ "$RUN_WORKFLOW_ID" == "$POSTGRESQL_N1_WORKFLOW_ID" ]] && \
  [[ "$RUN_DISPLAY_TITLE" == "$EXPECTED_RUN_TITLE" ]] && \
  [[ "$RUN_PATH" == "$POSTGRESQL_N1_WORKFLOW_PATH" ]] && \
  [[ "$RUN_EVENT" == "pull_request" ]] && \
  [[ "$RUN_STATUS" == "$AUTHORITATIVE_RUN_STATUS" ]] && \
  [[ "$RUN_CONCLUSION" == "$AUTHORITATIVE_RUN_CONCLUSION" ]] && \
  [[ "$RUN_HEAD_SHA" == "$SHA" ]] && \
  [[ "$RUN_ID" == "$AUTHORITATIVE_RUN_ID" ]] && \
  [[ "$RUN_ATTEMPT" == "$AUTHORITATIVE_RUN_ATTEMPT" ]] && \
  [[ "$AUTHORITATIVE_CHECK_SUITE_ID" =~ ^[0-9]+$ ]] || \
  fail "authoritative PostgreSQL N-1 workflow metadata drifted"

N1_CANDIDATES=$(gh api "repos/$REPO/commits/$SHA/check-runs" --paginate \
  --jq '.check_runs[] | select(.name == "verify-postgresql-n1") | [.id, .status, (.conclusion // "null"), .details_url, (.app.id | tostring), .app.slug, (.check_suite.id | tostring)] | @tsv')
TRUSTED_RUNS=""
while IFS=$'\t' read -r check_id check_status check_conclusion details_url \
  app_id app_slug check_suite_id; do
  [[ -z "$check_id" ]] && continue
  [[ "$app_id" == "$POSTGRESQL_N1_ACTIONS_APP_ID" ]] || continue
  [[ "$app_slug" == "github-actions" ]] || continue
  [[ "$check_suite_id" == "$AUTHORITATIVE_CHECK_SUITE_ID" ]] || continue
  if ! [[ "$details_url" =~ ^https://github.com/$REPO/actions/runs/([0-9]+)/job/([0-9]+)$ ]]; then
    continue
  fi
  run_id="${BASH_REMATCH[1]}"
  job_id="${BASH_REMATCH[2]}"
  [[ "$job_id" == "$check_id" ]] || continue
  [[ "$run_id" == "$AUTHORITATIVE_RUN_ID" ]] || continue

  if [[ "$run_id" != "$RUN_ID" ]] || \
     [[ "$check_status" != "$RUN_STATUS" ]] || \
     [[ "$check_conclusion" != "$RUN_CONCLUSION" ]]; then
    continue
  fi

  job_metadata=$(gh api "repos/$REPO/actions/jobs/$job_id" \
    --jq '[(.id | tostring), .name, .status, (.conclusion // "null"), .head_sha, (.run_id | tostring), (.run_attempt | tostring)] | @tsv') || continue
  IFS=$'\t' read -r observed_job_id job_name job_status job_conclusion \
    job_head_sha observed_job_run_id observed_job_run_attempt <<<"$job_metadata"
  if [[ "$observed_job_id" != "$check_id" ]] || \
     [[ "$job_name" != "$POSTGRESQL_N1_CHECK" ]] || \
     [[ "$job_status" != "$check_status" ]] || \
     [[ "$job_conclusion" != "$check_conclusion" ]] || \
     [[ "$job_head_sha" != "$SHA" ]] || \
     [[ "$observed_job_run_id" != "$run_id" ]] || \
     [[ "$observed_job_run_attempt" != "$AUTHORITATIVE_RUN_ATTEMPT" ]]; then
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
