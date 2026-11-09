#!/usr/bin/env bash

# Evaluate the PostgreSQL N-1 check for one exact pull-request head. This file
# is checked out from main by a pull_request_target/workflow_run workflow; no
# candidate-owned gate code is executed.

set -euo pipefail

POSTGRESQL_N1_CHECK="verify-postgresql-n1"
POSTGRESQL_N1_WORKFLOW_NAME="SaaS N-1 compatibility image"
POSTGRESQL_N1_WORKFLOW_ID="342012814"
POSTGRESQL_N1_WORKFLOW_PATH=".github/workflows/saas-n1-compat-image.yml"
POSTGRESQL_N1_WORKFLOW_SHA256="5aaf4474b8ff073b1ec5b72e51ee56c98b81bfcd0acd000481afbb8ba166b667"
POSTGRESQL_N1_ACTIONS_APP_ID="15368"

# Candidate inputs that can change pytest collection, dependency resolution,
# fixtures, or the selected assertions are pinned by the trusted main policy.
POSTGRESQL_N1_TRUSTED_INPUTS=(
  "pyproject.toml|2d50173296c09198dcafb573bdd0fc18abce0e1f6afbf702d077b54f3db770f9,3df60bf721d1df8558df6e569ff26a34d628c6590df7ac306a07f890cd9b1411"
  "uv.lock|8c4aef4e0da8a83415effabc4f9b4e946756145729a88ee43c466f994a35730f,a307dcaca4909b33b5fcce4846d03b2beebbda62a42d1c7148f708042bc70866"
  "tests/__init__.py|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  "tests/_model_pools.py|d25fda757b12bffbaa6a42e468f625f715cc3ee37df7f9b5af4b8d70af781362"
  "tests/_token_usage.py|25dbfbc0caea11edd4be3bb3eb530e2a784e9c98e6e2f652beeddae7b7071fa8"
  "tests/conftest.py|8dc962866d33ba30ebac092b47e6afd0318bac2e2c861fd78b8bbe6d15792b8f,54a9017176a2a4d423f377122e3d6cd7e9dcc024af3eed15ea6237f1c45e8828"
  "tests/saas/__init__.py|7c14e27fe713806e1e8fe6d3034333e8fb9442289484cf8778ec88c754c7181d"
  "tests/saas/conftest.py|5e1c588076fd6f7976e81cdc58047d5d21830b393af496b158907af0dfc7339c"
  "tests/saas/test_n1_compat_patch.py|ef658549e497e6a64c6f686a699926ef9f6ffc79790e745d9d8ad4308ccd1475,094c8b99bd8ec31fc27002fa4c1bc6fdb01e018a9ed9acc98120aed44f4fe07c"
  "tests/saas/test_image_supply_chain.py|0b554b2e7bbfc71789bb6278765e469976bdcf2014ec09f4c8ff8f8da50d0392,ce051c02f6232658fad652ef89af3a6ae7ad4cf3ac63a4ae3c7bf4f7b8150f76"
  "saas/scripts/build_n1_compat.py|566557b74dfdbcfeaad30f88b172820b88d9e86cc7f7af70b8e92f910f45303d"
  "saas/scripts/compare_oci_rebuilds.py|74b7f38a031bc64e0490dc31c19a746487182dc1a2e62cadc6a60ab6fd8b159b"
  "saas/n1_compat/manifest.json|eb74bc6f938da18792a190ade70f3604f247f50f6c1b25f70bb96ac68d56d99f"
  "saas/n1_compat/Dockerfile|df011b0e3c2a3f9ecf69b71307eeca282c2cf1377d26a20053df4d12a0d2aaed"
  "saas/n1_compat/Dockerfile.dockerignore|72aa85a2e1e88d468d3843d18199b1d0959a7ba4b3227c4354c722c4461f3275"
  "saas/n1_compat/build-requirements.txt|f258dfd1257091c9942501adc5106bee29806def12abd16d48feecabceb3ca29"
  "tests/saas/test_n1_merge_gate_candidate.py|ef2abbae9c50169ac76327227b76fd0fc89768e4bcf0fe7ee3562a92ed2b7365,0a09d3731cce4d6611c85de07e76f7238295a5add9ecc82a2cf92e0bb524c7d4"
  "tests/saas/test_n1_merge_gate.py|14ac6f69efaf5dcb165e082857bcbbe11764dab043a8cf1ff3b738d3c9b4d262,3b752c50ea3808e5172ecd6579237a8611f51ea3b5059a025a808ecb7dc47840"
  "tests/saas/test_n1_outbox_admission.py|d5db6f7cc3feb7a8a9de64da88bab036ba7b6e57be4043e36c29736d462811c1,2570537024bd3ba5d1501ad58d0e76d65a0b49c66ad471869f7c5cb757440b30"
  "tests/saas/test_control_plane_migration.py|deedcbfcf9cabb1ac4e71cfeb0f0803eb5b62a659bac00720ee99f9befd4d0ef,c533432965dcdc87fb9201459d96e44ce086ccb264007af7f2ba0330a31305eb"
  "tests/saas/test_production_runner_postgresql.py|0004ce57cb1ec4dafad3ea80729c8fedd95d0308098df8e073382e1cd66c0400,c62e642dabe8f0870a67583e6cb8fe64e58a558938678e30f716df51b88774e0"
)

# Controller tooling is separate from the frozen legacy product PG source inputs.
POSTGRESQL_N1_ACTION_INPUTS=(
  "saas/actions/setup-pinned-crane/action.yml|383728141dbd88956fe9ddcb8fe29ec0e621ab5d2a51943b9e88d8f68d54bcfd"
)

# Separately reviewed Aliyun input bytes; preserve generic and old018 hashes.
POSTGRESQL_N1_ALIYUN_TRUSTED_INPUTS=(
  "pyproject.toml|f2dc2794af15424de2e97422d2bf4dd59eccc6f413fbbb3e6b4453ca302b3f27"
  "uv.lock|a362e493d57d743d8d7d8674ca6e05371d51af29fc73e54a2f1a426de9ba97f4"
  "tests/saas/test_image_supply_chain.py|507837a9b6cafe037e2d199c3ba87e225dec11ce3762c66dadcce6f572c99bbc"
  "saas/scripts/compare_oci_rebuilds.py|fdabfecb538d04c52ee4a036da4ffb2db2ee00cb0a49d0e5e1b11ca66de9c732"
)

# Preserve exact previously reviewed Main and Aliyun variants.
POSTGRESQL_N1_ALIYUN_PREVIOUS_INPUTS=(
  "tests/saas/test_image_supply_chain.py|3fcebd0ee00134ba2889c094c961351dd8482850b901827ba45d5b9ad16ec4c2"
  "tests/saas/test_image_supply_chain.py|07c305d43955deffe843de9e7f45a6ff38e59b95b07491231f64d19f8b2a1dd0"
  "uv.lock|d5f1d133221f33dca75e9e0a4e7c49b2bded0da5cfcabc2ae212f7e615681ce2"
  "pyproject.toml|77ffd5d339656adfec3e7b15660599226ff29a527e05f75cdbbb386ad280550f"
  "pyproject.toml|7b7bfc95d45ac928bb91cf6b383c94c48792474adf967e34fcfddca15d0c58a6"
  "tests/saas/test_image_supply_chain.py|109ac4d727d73b271613089acbb693944047f9705f10c33c4e676075fe52d4f7"
  "uv.lock|51412e72b0d0119f388ad9349025fb40f1f5458e55695b736f9e79ab99395b5b"
)

# Retain the previous 0.21 input beside the newly reviewed resource-only packaging hash.
POSTGRESQL_N1_PREVIEW_PREVIOUS_PYPROJECT_SHA256="24fe2762769bbd06e8da179caf64140a5869e3c33ee875c83bb3a51f266ba322"
POSTGRESQL_N1_PREVIEW_PREVIOUS_MERGE_TEST_SHA256="2621c5890478d5cc4d4d7a5e8fef6a1d69bd25b85943b64ec8a2e62f06db83d2"

is_reviewed_preview_authority_input() {
  [[ "$1" == "pyproject.toml" && "$2" == "$POSTGRESQL_N1_PREVIEW_PREVIOUS_PYPROJECT_SHA256" ]] ||
    [[ "$1" == "tests/saas/test_n1_merge_gate.py" && "$2" == "$POSTGRESQL_N1_PREVIEW_PREVIOUS_MERGE_TEST_SHA256" ]]
}

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

is_reviewed_aliyun_input() {
  local path=$1 digest=$2 entry
  case "$path" in
    pyproject.toml|uv.lock|tests/saas/test_image_supply_chain.py|saas/scripts/compare_oci_rebuilds.py) ;;
    *) return 1 ;;
  esac
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  for entry in "${POSTGRESQL_N1_ALIYUN_TRUSTED_INPUTS[@]}" "${POSTGRESQL_N1_ALIYUN_PREVIOUS_INPUTS[@]}"; do
    [[ "$entry" == "$path|$digest" ]] && return 0
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

for trusted_input in "${POSTGRESQL_N1_TRUSTED_INPUTS[@]}" "${POSTGRESQL_N1_ACTION_INPUTS[@]}"; do
  trusted_path="${trusted_input%%|*}"
  trusted_sha256s="${trusted_input#*|}"
  [[ "$trusted_sha256s" =~ ^[0-9a-f]{64}(,[0-9a-f]{64})?$ ]] || \
    fail "PostgreSQL N-1 trusted input policy is malformed: $trusted_path"
  observed_sha256=$(gh api \
    -H 'Accept: application/vnd.github.raw+json' \
    "repos/$REPO/contents/$trusted_path?ref=$SHA" \
    | shasum -a 256 | awk '{print $1}')
  if [[ ",$trusted_sha256s," != *",$observed_sha256,"* ]] && \
    ! is_reviewed_aliyun_input "$trusted_path" "$observed_sha256" && \
    ! is_reviewed_preview_authority_input "$trusted_path" "$observed_sha256"; then
    fail "PostgreSQL N-1 trusted input drift: $trusted_path"
  fi
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
