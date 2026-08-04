# Upstream patch queue

Every `.patch` must have a ledger entry recording its owner, affected upstream
paths, tests, upstream issue or pull request, first/last replayed revisions, and
removal condition. Runtime monkey patches and whole-file overrides are not
accepted.

| Patch | Owner | Upstream path | Verification | Upstream status | Replay baseline | Removal condition |
|---|---|---|---|---|---|---|
| `0001-import-spawn-archive-stop.patch` | SaaS Platform | `omnigent/server/routes/sessions/routes_core.py`; `omnigent/server/routes/sessions/__init__.py` | Pyrefly; `tests/server/integration/test_sessions_archive.py` | Regression introduced by upstream `2ce9c60`; report pending | `2ce9c60` | Remove when upstream imports and facade-exports the archive-stop helper/state |
| `0002-managed-session-initializer.patch` | SaaS Platform | `omnigent/db/utils.py` | Store adapter contract; real PostgreSQL Runtime RLS | Generic extension proposal pending | `2ce9c60` | Remove when upstream exposes a per-transaction Store session initializer or equivalent hook |
