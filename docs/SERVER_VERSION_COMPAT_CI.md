# Server compatibility support and CI policy

Omnigent is pre-1.0. The supported rolling-upgrade window is deliberately one
stable release wide: **main ↔ latest final release**. The workflow resolves the
latest non-prerelease tag at run time; as of this policy's introduction that tag
is `v0.12.0`.

## Blocking support matrix

| Boundary | New side | Older side | Blocking evidence |
| --- | --- | --- | --- |
| Config 1 | server on main | runner/host on latest final | PR compatibility smoke |
| Config 2 | runner/host on main | server on latest final | PR compatibility smoke |
| UI Config A | SPA on main | server on latest final | PR browser smoke |
| UI Config B | server on main | SPA on latest final | PR browser smoke |

All four jobs run on contract-surface pull requests and on scheduled/manual
workflow runs. A failure in this matrix is a release blocker. Runner and host are
one compatibility axis because they are released and deployed together.

Compatibility with tags older than the latest final release is not a supported
upgrade guarantee. Operators must upgrade one stable release at a time; skipping
stable releases requires a separately recorded manual acceptance run.

## Historical telemetry

The broader pairwise matrix is retained to expose drift and guide migrations:

- Core server/runner history starts at `v0.2.0` and exercises E2E and integration
  tests in both directions.
- Browser history starts at `v0.9.0` and exercises both SPA/server directions.
- The `(main, main)` cell is omitted because normal CI owns that evidence.

A **Scheduled full-history sweep** is advisory: failing historical cells remain
visible as job annotations and artifacts, but do not make the workflow red. This
prevents unsupported pre-1.0 combinations from masquerading as a mainline
release regression.

A **Manual full-history dispatch** is strict. It is the reproducible mechanism
for expanding the support promise, accepting a skipped-release upgrade, or
investigating a historical regression. Every selected cell must pass.

## Release evidence

The compatibility gate records the exact checked-out commit, resolved stable
tag, matrix coordinates, and uploaded test artifacts. It proves only the
server/runner/SPA protocol boundary. SaaS PostgreSQL schema N-1 admission,
container digest/signature verification, live deployment, rollback, and
production approval are separate gates and cannot be inferred from this job.
