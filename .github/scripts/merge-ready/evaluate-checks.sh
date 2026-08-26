#!/usr/bin/env bash
# Iterates `REQUIRED` (defined in required.sh) against the actual
# check-runs on the PR head SHA. When GitHub has multiple check-runs
# with the same name on the same SHA (for example after re-running PR
# Template on an edited description), the newest run wins.
# Each check counts as green when:
#   - conclusion=success, OR
#   - conclusion=skipped AND name is in ALLOW_SKIP, OR
#   - the check is missing AND name is in ALLOW_SKIP AND its owning
#     workflow either never ran for this SHA (path-ignored), or its
#     newest run succeeded (the absent check was conditionally excluded
#     from that run's job matrix), or its newest run was skipped (the
#     whole workflow was gated off, e.g. a fork/draft PR) — see
#     workflow_run_outcome.
#
# A missing ALLOW_SKIP check is NOT green only while its workflow's
# newest run is still in flight / cancelled / failed: the check could
# still be pending or was lost, so the gate must wait. Inferring "skip"
# from mere absence let PR #2218 merge while an E2E shard was cancelled
# and re-running. Trusting a *succeeded* run keeps path-filtered jobs
# (e.g. CI's dynamically-selected Pytest shards on a docs/deploy-only
# PR) from blocking the gate; trusting a *skipped* run keeps fork/draft
# PRs — whose entire e2e workflow is gated off — from wedging it.
#
# Env in: GH_TOKEN, REPO, PR, SHA
# Out:    failed=<markdown bullet list of failed names> on $GITHUB_OUTPUT
# Exit:   0 if all green, 1 if any red.

set -euo pipefail

HERE=$(dirname "$0")
# shellcheck disable=SC1091
source "$HERE/required.sh"
# shellcheck disable=SC1091
source "$HERE/saas-required.sh"

# Contextual checks are selected from the authoritative current PR. Never mix a
# file list from one PR with checks from another SHA: workflow_dispatch and a
# stale workflow_run must not be able to paint an unrelated commit green.
if ! [[ "${PR:-}" =~ ^[0-9]+$ ]] || ! [[ "${SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::PR and full head SHA are required"
  exit 1
fi
PR_METADATA=$(gh api "repos/$REPO/pulls/$PR" \
  --jq '[.state, .head.sha, .base.ref, .base.sha, (.changed_files | tostring)] | @tsv')
IFS=$'\t' read -r PR_STATE PR_HEAD_SHA PR_BASE_REF PR_BASE_SHA \
  PR_CHANGED_FILES <<<"$PR_METADATA"
if [[ "$PR_STATE" != "open" ]] || [[ "$PR_BASE_REF" != "main" ]] || \
   [[ "$PR_HEAD_SHA" != "$SHA" ]] || ! [[ "$PR_BASE_SHA" =~ ^[0-9a-f]{40}$ ]] || \
   ! [[ "$PR_CHANGED_FILES" =~ ^[0-9]+$ ]]; then
  echo "::error::PR is not an open main-targeting PR at exact head SHA $SHA"
  exit 1
fi
PR_FILE_ROWS=$(gh api "repos/$REPO/pulls/$PR/files" --paginate \
  --jq '.[] | [.filename, (.previous_filename // "")] | @tsv')
PR_FILE_COUNT=$(printf '%s\n' "$PR_FILE_ROWS" | awk 'NF {count++} END {print count + 0}')
if [[ "$PR_FILE_COUNT" -ne "$PR_CHANGED_FILES" ]]; then
  echo "::error::PR file pagination is incomplete"
  exit 1
fi
PR_FILES=$(printf '%s\n' "$PR_FILE_ROWS" | awk -F'\t' \
  '{print $1; if ($2 != "") print $2}')
if changes_postgresql_n1_forbidden_environment <<<"$PR_FILES"; then
  echo "::error::Committed .uv/.venv state requires an explicit admin merge"
  exit 1
fi
if changes_postgresql_n1_policy <<<"$PR_FILES"; then
  echo "::error::PostgreSQL N-1 gate policy changes require an explicit admin merge"
  exit 1
fi
if requires_postgresql_n1 <<<"$PR_FILES"; then
  REQUIRED+=("$POSTGRESQL_N1_CHECK")
  if ! [[ "$POSTGRESQL_N1_WORKFLOW_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::trusted PostgreSQL N-1 workflow digest is not configured"
    exit 1
  fi
  OBSERVED_N1_WORKFLOW_SHA256=$(gh api \
    -H 'Accept: application/vnd.github.raw+json' \
    "repos/$REPO/contents/$POSTGRESQL_N1_WORKFLOW_PATH?ref=$SHA" \
    | shasum -a 256 | awk '{print $1}')
  if [[ "$OBSERVED_N1_WORKFLOW_SHA256" != "$POSTGRESQL_N1_WORKFLOW_SHA256" ]]; then
    echo "::error::PostgreSQL N-1 workflow bytes do not match trusted main policy"
    exit 1
  fi
  for trusted_input in "${POSTGRESQL_N1_TRUSTED_INPUTS[@]}"; do
    trusted_path="${trusted_input%%|*}"
    trusted_sha256="${trusted_input#*|}"
    observed_sha256=$(gh api \
      -H 'Accept: application/vnd.github.raw+json' \
      "repos/$REPO/contents/$trusted_path?ref=$SHA" \
      | shasum -a 256 | awk '{print $1}')
    if [[ "$observed_sha256" != "$trusted_sha256" ]]; then
      echo "::error::PostgreSQL N-1 trusted input drift: $trusted_path"
      exit 1
    fi
  done
fi

CHECKS=$(gh api "repos/$REPO/commits/$SHA/check-runs" --paginate \
  --jq '.check_runs[] | "\(.name)\t\(.status)\t\(.conclusion // "null")\t\(.completed_at // .started_at // "")"')

# A PR can add another job with the same display name. For the contextual N-1
# check, retain only rows whose check-run resolves to the pinned workflow path,
# PR event, exact head SHA, exact PR, and exact job identity. The workflow bytes
# were pinned above, so a PR cannot replace the PG16 commands and self-attest.
if requires_postgresql_n1 <<<"$PR_FILES"; then
  N1_CANDIDATES=$(gh api "repos/$REPO/commits/$SHA/check-runs" --paginate \
    --jq '.check_runs[] | select(.name == "verify-postgresql-n1") | [.id, .name, .status, (.conclusion // "null"), (.completed_at // .started_at // ""), .details_url, .app.slug] | @tsv')
  TRUSTED_N1_ROWS=""
  while IFS=$'\t' read -r check_id check_name check_status check_conclusion \
    check_time details_url app_slug; do
    [[ -z "$check_id" ]] && continue
    [[ "$app_slug" != "github-actions" ]] && continue
    if ! [[ "$details_url" =~ ^https://github.com/$REPO/actions/runs/([0-9]+)/job/([0-9]+)$ ]]; then
      continue
    fi
    run_id="${BASH_REMATCH[1]}"
    job_id="${BASH_REMATCH[2]}"
    [[ "$job_id" != "$check_id" ]] && continue
    if ! run_metadata=$(gh api "repos/$REPO/actions/runs/$run_id" \
      --jq '[.name, .display_title, .path, .event, .status, (.conclusion // "null"), .head_sha, (.id | tostring)] | @tsv'); then
      continue
    fi
    IFS=$'\t' read -r run_name run_display_title run_path run_event run_status \
      run_conclusion run_head_sha observed_run_id <<<"$run_metadata"
    expected_run_title="SaaS N-1 pull_request pr=$PR base=$PR_BASE_SHA head=$SHA"
    if [[ "$run_name" != "$POSTGRESQL_N1_WORKFLOW" ]] || \
       [[ "$run_display_title" != "$expected_run_title" ]] || \
       [[ "$run_path" != "$POSTGRESQL_N1_WORKFLOW_PATH" ]] || \
       [[ "$run_event" != "pull_request" ]] || \
       [[ "$run_head_sha" != "$SHA" ]] || \
       [[ "$observed_run_id" != "$run_id" ]] || \
       [[ "$run_status" != "$check_status" ]] || \
       [[ "$run_conclusion" != "$check_conclusion" ]]; then
      continue
    fi
    if ! job_metadata=$(gh api "repos/$REPO/actions/jobs/$job_id" \
      --jq '[.name, .status, (.conclusion // "null"), .head_sha, (.run_id | tostring), .workflow_name] | @tsv'); then
      continue
    fi
    IFS=$'\t' read -r job_name job_status job_conclusion job_head_sha \
      observed_job_run_id job_workflow_name <<<"$job_metadata"
    if [[ "$job_name" != "$POSTGRESQL_N1_CHECK" ]] || \
       [[ "$job_status" != "$check_status" ]] || \
       [[ "$job_conclusion" != "$check_conclusion" ]] || \
       [[ "$job_head_sha" != "$SHA" ]] || \
       [[ "$observed_job_run_id" != "$run_id" ]] || \
       [[ "$job_workflow_name" != "$POSTGRESQL_N1_WORKFLOW" ]]; then
      continue
    fi
    TRUSTED_N1_ROWS+="$check_name"$'\t'"$check_status"$'\t'\
"$check_conclusion"$'\t'"$check_time"$'\n'
  done <<<"$N1_CANDIDATES"
  CHECKS=$(printf '%s\n' "$CHECKS" | awk -F'\t' \
    -v n="$POSTGRESQL_N1_CHECK" '$1 != n')
  CHECKS+=$'\n'"$TRUSTED_N1_ROWS"
fi

# Per-workflow run state for this SHA (one row per run:
# name<TAB>status<TAB>conclusion<TAB>created_at). Used to classify a
# *missing* required check via workflow_run_outcome below.
WORKFLOW_RUNS=$(gh api "repos/$REPO/actions/runs?head_sha=$SHA&per_page=100" --paginate \
  --jq '.workflow_runs[] | [.name, .status, (.conclusion // "null"), (.created_at // "")] | @tsv')

# Classify the newest run of a workflow for this SHA:
#   "none"    — no run at all. The workflow was gated out by
#               on.pull_request.paths-ignore, so its checks are
#               legitimately absent.
#   "success" — newest run completed successfully. A check that is still
#               absent was conditionally excluded from that run's job
#               matrix (e.g. CI dynamically path-filters its Pytest
#               shards); the green workflow vouches the job wasn't needed.
#   "skipped" — newest run completed with conclusion=skipped: every job's
#               `if:` was false, so the run did no work (e2e fork guard on
#               a fork PR, e2e-ui `!draft` on a draft PR). A definitive
#               skip, not a transient, so absent ALLOW_SKIP checks pass.
#   "other"   — in progress, queued, cancelled, or failed. An absent
#               check may still be pending or was lost, so the gate must
#               wait rather than treat the gap as a skip (the #2218 race,
#               where an E2E shard was cancelled and re-running at the
#               moment the gate evaluated).
workflow_run_outcome() {
  local wf="$1" row status concl
  row=$(printf '%s\n' "$WORKFLOW_RUNS" | awk -F'\t' -v w="$wf" '$1 == w' \
    | sort -t $'\t' -k4,4 | tail -n 1)
  if [[ -z "$row" ]]; then
    echo "none"
    return
  fi
  status=$(printf '%s' "$row" | cut -f2)
  concl=$(printf '%s' "$row" | cut -f3)
  if [[ "$status" == "completed" && "$concl" == "success" ]]; then
    echo "success"
  elif [[ "$status" == "completed" && "$concl" == "skipped" ]]; then
    echo "skipped"
  else
    echo "other"
  fi
}

FAIL=0
FAILED_LINES=""
for n in "${REQUIRED[@]}"; do
  ROW=$(echo "$CHECKS" | awk -F'\t' -v n="$n" '$1 == n {print}' | sort -t $'\t' -k4,4 | tail -n 1)
  if [[ -z "$ROW" ]]; then
    if is_allow_skip "$n"; then
      wf=$(workflow_for "$n")
      outcome="none"
      [[ -n "$wf" ]] && outcome=$(workflow_run_outcome "$wf")
      if [[ "$outcome" == "other" ]]; then
        echo "NOT GREEN: $n  (workflow '$wf' has not succeeded and the check is missing -- pending/cancelled, not a skip)"
        FAILED_LINES+="- \`$n\` (workflow ran but has not succeeded and the check is missing -- still pending or cancelled)"$'\n'
        FAIL=1
        continue
      fi
      # outcome is "none" (workflow path-skipped), "success" (job
      # conditionally excluded from a green run), or "skipped" (whole
      # workflow gated off, e.g. fork/draft PR) — all legitimate.
      echo "OK      : $n  (skipped: path-ignored, conditionally-excluded, or fork/draft-gated)"
      continue
    fi
    echo "MISSING : $n"
    FAILED_LINES+="- \`$n\` (not yet started or not configured on this commit)"$'\n'
    FAIL=1
    continue
  fi
  STATUS=$(echo "$ROW" | cut -f2)
  CONCL=$(echo "$ROW" | cut -f3)
  if [[ "$STATUS" != "completed" ]]; then
    echo "NOT GREEN: $n  (status=$STATUS, conclusion=$CONCL)"
    FAILED_LINES+="- \`$n\` (still running, status=$STATUS)"$'\n'
    FAIL=1
  elif [[ "$CONCL" == "skipped" ]] && is_allow_skip "$n"; then
    echo "OK      : $n  (skipped via path filter)"
  elif [[ "$CONCL" != "success" ]]; then
    echo "NOT GREEN: $n  (status=$STATUS, conclusion=$CONCL)"
    FAILED_LINES+="- \`$n\` (conclusion=$CONCL)"$'\n'
    FAIL=1
  else
    echo "OK      : $n"
  fi
done

{
  echo "failed<<_FAILED_EOF_"
  printf '%s' "$FAILED_LINES"
  echo "_FAILED_EOF_"
} >> "$GITHUB_OUTPUT"

if [[ $FAIL -eq 1 ]]; then
  echo ""
  echo "Required checks are not all green on $SHA."
  exit 1
fi

echo "All required checks green on $SHA."
