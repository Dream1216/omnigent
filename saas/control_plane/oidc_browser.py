"""Same-origin OIDC completion documents; no provider tokens reach the browser."""

from __future__ import annotations

import json
from html import escape

from fastapi.responses import HTMLResponse, Response

OIDC_COMPLETE_SCRIPT = r"""(() => {
  'use strict';
  const data = JSON.parse(document.getElementById('oidc-result').textContent);
  if (!data.csrf_token) return;
  try {
    window.OmnigentSaasSession.write(data.csrf_token);
  } catch (_) {
    document.getElementById('status').textContent = data.storage_error;
    return;
  }
  window.location.replace(data.return_to);
})();
"""

SECURITY_HEADERS = {
    "Cache-Control": "private, no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


def completion_script() -> Response:
    return Response(
        OIDC_COMPLETE_SCRIPT, media_type="application/javascript", headers=SECURITY_HEADERS
    )


def completion_document(
    *,
    csrf_token: str | None = None,
    return_to: str = "/",
    ui_locale: str = "zh-CN",
    error_code: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    chinese = ui_locale == "zh-CN"
    title = "胜天半子 · 登录" if chinese else "Shengtian Banzi · Sign in"
    if error_code == "identity_confirmation_required":
        message = (
            "此邮箱已有账号。请先使用原方式登录，再在账号设置中明确关联身份。"
            if chinese
            else "An account already uses this email. Sign in with your existing method, "
            "then explicitly link the identity in account settings."
        )
    elif error_code:
        message = (
            "登录未完成，请重试。" if chinese else "Sign in could not complete. Please try again."
        )
    else:
        message = "正在完成登录…" if chinese else "Completing sign in…"
    storage_error = (
        "浏览器存储不可用。请启用本站存储后重试登录。"
        if chinese
        else "Browser storage is unavailable. Enable storage for this site "
        "and try signing in again."
    )
    payload = (
        json.dumps(
            {"csrf_token": csrf_token, "return_to": return_to, "storage_error": storage_error},
            ensure_ascii=True,
        )
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    retry = "重新登录" if chinese else "Try signing in again"
    return HTMLResponse(
        f'<!doctype html><html lang="{escape(ui_locale)}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title></head><body><main><h1>{escape(title)}</h1>"
        f'<p id="status" role="status">{escape(message)}</p>'
        f'<a href="/saas/login">{escape(retry)}</a>'
        f'<script id="oidc-result" type="application/json">{payload}</script>'
        '<script src="/saas/auth/assets/session.js" defer></script>'
        '<script src="/saas/auth/assets/oidc-complete.js" defer></script>'
        "</main></body></html>",
        status_code=status_code,
        headers=SECURITY_HEADERS,
    )
