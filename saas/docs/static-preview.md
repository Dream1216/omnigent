# Static session previews

A SaaS session can open an isolated snapshot of a completed run. The snapshot
serves the completed checkpoint's `dist` publication, and readiness requires a
readable, nonempty entry document. SPA navigation and refresh use that entry;
missing scripts and other assets keep their error status.

## Sub-features

- `publication-readiness`: empty or unsafe entry documents cannot become ready.
- `spa-navigation`: directly open a route, navigate, and refresh without a 404.
- `asset-errors`: missing assets stay missing rather than returning HTML.
- `authorization-lifecycle`: only the owner can start or stop the scoped preview.

## How to get to it (user POV)

- In a SaaS session with a completed delivery run, open **会话预览**, start the
  static preview, and choose **打开预览**.
- In the opened preview, follow an internal page link or refresh a deep URL.
- Return to the session preview control to stop the preview.

## Driving it with the repro environment

Preconditions: the generic repro instance does not provide SaaS delivery or a
production preview gateway. Full session-control journeys require an isolated,
authenticated SaaS environment and an admitted completed run; do not use a
public production session or report the generic instance as covering this path.

- `publication-readiness`, `spa-navigation`, `asset-errors`: own environment,
  `tests/saas/test_static_web_preview_browser.py` starts the actual static runtime
  on a private listener and drives Chromium. Run with `--video=on --screenshot=on`.
  This proves runtime navigation, not the authenticated session handoff.
- `authorization-lifecycle`: `tests/saas/test_production_preview_control.py`
  exercises the owner and tenant HTTP boundaries. For full browser acceptance,
  open the SaaS session, start and open its preview, follow a page link, refresh,
  stop from the session, and verify the original link is denied.

## Gotchas

- A TCP listener alone is not readiness; a valid publication entry must exist.
- A missing JavaScript asset returning the entry HTML hides a broken build.
- The static preview is a completed checkpoint, not a live development server.
- Ignored build outputs must be included in the admitted publication checkpoint;
  a local `dist` directory alone does not prove the restored snapshot has it.
- Browser runtime proof and authenticated deployment proof are separate evidence.
