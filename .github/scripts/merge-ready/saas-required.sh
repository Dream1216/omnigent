#!/usr/bin/env bash

# SaaS checks are kept outside required.sh because that file is replaced by
# upstream syncs. Only PRs that can change the pinned N-1 contract enter here.

POSTGRESQL_N1_CHECK="verify-postgresql-n1"
POSTGRESQL_N1_WORKFLOW="SaaS N-1 compatibility image"
POSTGRESQL_N1_WORKFLOW_PATH=".github/workflows/saas-n1-compat-image.yml"
# Updated only by a governance bootstrap PR. The Merge Ready evaluator runs
# from main and rejects a same-named check produced by any other workflow bytes.
POSTGRESQL_N1_WORKFLOW_SHA256="992b5d94c6b96ace05a0d443b04f3e947c1ef3279b32aaa369ef8de84ca12f20"

# The PG16 lane executes candidate implementation bytes against a governance-
# pinned test/config harness. Without these pins, a PR could keep the workflow
# name intact while changing pytest collection, fixtures, or the selected tests
# to manufacture a green check.
POSTGRESQL_N1_TRUSTED_INPUTS=(
  "pyproject.toml|c4b9baa229972c36302ff2b358102db9968319fac9e0ca062515c939fcddd941"
  "uv.lock|0b4f16e857a865d5483432d440205667c62bc7a9fe109bf46532ecb538d78586"
  "tests/__init__.py|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  "tests/_model_pools.py|d25fda757b12bffbaa6a42e468f625f715cc3ee37df7f9b5af4b8d70af781362"
  "tests/_token_usage.py|25dbfbc0caea11edd4be3bb3eb530e2a784e9c98e6e2f652beeddae7b7071fa8"
  "tests/conftest.py|366d658c3cc67dca4c02f32e36c2424c57377f534c9ea03efcca21f294ff4104"
  "tests/saas/__init__.py|7c14e27fe713806e1e8fe6d3034333e8fb9442289484cf8778ec88c754c7181d"
  "tests/saas/conftest.py|5e1c588076fd6f7976e81cdc58047d5d21830b393af496b158907af0dfc7339c"
  "tests/saas/test_n1_compat_patch.py|d66ce236a29b70b59287b349846e597cae04932c279c0132c3d8118020163bc5"
  "tests/saas/test_n1_outbox_admission.py|852466d5c52d01a8832afabd1a135b715d27a23162efec95d4ce924fdf0ebfa1"
  "tests/saas/test_control_plane_migration.py|e1a3cdbe178d6a758cd813ada732cb0ab3320f7e40f20eb77de80c0b0798cee0"
)

POSTGRESQL_N1_PATHS=(
  ".github/scripts/merge-ready/**"
  ".github/workflows/merge-ready.yml"
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

# Committed environment state can bypass a fresh isolated interpreter and has
# no valid source-review use. A forced add requires an explicit admin decision.
POSTGRESQL_N1_FORBIDDEN_PATHS=(
  ".uv/**"
  ".venv/**"
)

# These files define the trusted evaluator itself. Once this bootstrap lands,
# an ordinary source PR may not rewrite them and use the old main-side gate to
# approve its successor. An administrator must land policy changes explicitly;
# the pinned candidate workflow is the sole exception because its exact bytes
# are checked above.
POSTGRESQL_N1_POLICY_PATHS=(
  ".github/scripts/merge-ready/**"
  ".github/workflows/merge-ready.yml"
)

requires_postgresql_n1() {
  local path pattern
  while IFS= read -r path; do
    for pattern in "${POSTGRESQL_N1_PATHS[@]}"; do
      if [[ "$path" == $pattern ]]; then
        return 0
      fi
    done
  done
  return 1
}

changes_postgresql_n1_policy() {
  local path pattern
  while IFS= read -r path; do
    for pattern in "${POSTGRESQL_N1_POLICY_PATHS[@]}"; do
      if [[ "$path" == $pattern ]]; then
        return 0
      fi
    done
  done
  return 1
}

changes_postgresql_n1_forbidden_environment() {
  local path pattern
  while IFS= read -r path; do
    for pattern in "${POSTGRESQL_N1_FORBIDDEN_PATHS[@]}"; do
      if [[ "$path" == $pattern ]]; then
        return 0
      fi
    done
  done
  return 1
}
