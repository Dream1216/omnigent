# Upstream patch queue

Every `.patch` must have a ledger entry recording its owner, affected upstream
paths, tests, upstream issue or pull request, first/last replayed revisions, and
removal condition. Runtime monkey patches and whole-file overrides are not
accepted.

| Patch | Owner | Upstream path | Verification | Upstream status | Replay baseline | Removal condition |
|---|---|---|---|---|---|---|
| `0001-import-spawn-archive-stop.patch` | SaaS Platform | `omnigent/server/routes/sessions/__init__.py` | Pyrefly; `tests/server/integration/test_sessions_archive.py` | Upstream `ab4bcaa` absorbed the `routes_core.py` import; facade export remains downstream | `b8fd1952` | Remove when upstream facade-exports the archive-stop helper/state |
| `0002-managed-session-initializer.patch` | SaaS Platform | `omnigent/db/utils.py` | Store adapter contract; real PostgreSQL Runtime RLS | Generic extension proposal pending | `b8fd1952` | Remove when upstream exposes a per-transaction Store session initializer or equivalent hook |
