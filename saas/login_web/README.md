# Omnigent login UI

Blue/white login surface for `/saas/login`, using Next.js **Pages Router**,
React **18.3.1**, Tailwind CSS **4**, and locally owned shadcn/ui primitives
using Radix Label/Slot. React stays on the same version as the main application.

This is an isolated npm package with a committed lockfile. It does not modify
the main Vite app or the root pnpm workspace. It exports static assets into
`saas/login_ui/static/`; FastAPI serves them at `/saas/login-assets/`.
There is no additional production Node process, database change, or new auth API.

## Build and preview

Use Node 22.13+ and the existing Python development environment. From this directory:

```sh
npm ci
npm run build
npm run typecheck
npm run format:check
```

From the repository root, start a local, UI-only preview:

```sh
uv run uvicorn preview:app --app-dir saas/login_web/scripts --host 127.0.0.1 --port 18765
```

Open `http://127.0.0.1:18765/saas/login?return_to=%2Fsettings%2Faccount`.
The preview deliberately returns an explanatory error on sign-in; it never
connects to production or authenticates an account. Use dummy credentials only.
Reload after a new build. `npm run dev` supports styling hot reload on port
18764, but does not proxy production APIs or validate the production CSP.

## Acceptance

```sh
uv run pytest tests/saas/test_onboarding_ui_browser.py tests/saas/test_login_ui.py tests/saas/test_onboarding_http.py tests/saas/test_wheel_contents.py
```

Build first: these tests require the actual Next export, not a mocked page.
Browser tests intercept only API responses and use the packaged HTML/CSS/JS.
They verify desktop and mobile layout, field labels and keyboard validation,
password visibility, pending/duplicate requests, retry, safe same-origin return
targets, tab-scoped CSRF storage, no-JavaScript behavior, and the existing signup
journey. HTTP tests check script hashes, static asset coverage, and traversal.

Manual checks:

1. Check the two-column composition at 1440px and the single-column form at 390px/320px.
2. Tab through the email field, password, visibility toggle, and submit button.
3. Enter `founder@example.test` and a dummy password; toggle visibility twice.
4. Submit in the preview: observe a readable error and an enabled retry button.
5. After a separately authorized deployment, use a test account to confirm that
   the real login reaches `/settings/account` and signup still works.

## Authentication and delivery boundaries

- Sends the unchanged `{email, password}` contract to same-origin `/saas/auth/login`.
- Keeps HttpOnly session cookies server-owned; stores only the existing CSRF
  token under `omnigent.saas.csrf`. Passwords are not persisted.
- Validates `return_to` against the current origin. External and backslash
  redirects fall back to `/`.
- No fake SSO, password-reset, or remember-me controls are introduced.
- Forms stay disabled until hydration; a no-JavaScript message explains why.
- Fonts are bundled locally. No external font/image/analytics requests.
- The server retains its strict CSP. Only build-derived hashes are allowed
  for the Next bootstrap; neither `unsafe-inline` nor `unsafe-eval` is enabled.
- The Docker server builder creates/copies the export before packaging Python.
  For manual wheel builds, run `npm run build` here **before** `uv build --wheel`.
  Backend-only installations without the export keep the original functional
  onboarding login; they do not receive the new UI.
- CI compatibility/image-candidate tests build the export before browser tests.
  Local tests are not proof of CI success, image publication, or live deployment.

Framework references: [Pages Router](https://nextjs.org/docs/pages/getting-started/installation),
[static exports](https://nextjs.org/docs/pages/guides/static-exports),
[Tailwind v4](https://tailwindcss.com/docs/installation/framework-guides/nextjs),
[shadcn/ui](https://ui.shadcn.com/docs/installation/next).
