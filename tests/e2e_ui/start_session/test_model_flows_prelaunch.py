"""E2E (hermetic): pre-launch model picker rows per model-flows-design.md §10.1.

Row 6's hermetic half: with a host catalog whose rows carry ``isDefault``, the
new-chat model select must read "Default (X)" for BOTH harnesses — X being the
default row's display name. Codex already renders this; the claude branch of
the landing screen historically discarded ``isDefault``, so its select read a
bare "Default" no matter what the host said. This test encodes the design's
target behavior and is red until landing-order step 7.

The driving surface is the real SPA in a browser; only the server edges the
landing screen consults (hosts, agents, model-options) are faked, exactly like
the sibling tests in ``test_start_session.py``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from playwright.async_api import Route, async_playwright, expect

from tests.e2e_ui.start_session.test_start_session import (
    _HOST_ID,
    _close_entry_models,
    _codex_native_agents_body,
    _open_entry_models,
    _register_common_routes,
    _run_in_fresh_loop,
    _wait_until,
)

_CLAUDE_HOST_ROWS = [
    {
        "id": "sonnet",
        "model": "claude-sonnet-5",
        "displayName": "Sonnet 5",
        "isDefault": False,
    },
    {
        "id": "opus[1m]",
        "model": "claude-opus-4-8[1m]",
        "displayName": "Opus 4.8 (1M context)",
        "isDefault": True,
    },
    {
        "id": "haiku",
        "model": "claude-haiku-4-5-20251001",
        "displayName": "Haiku 4.5",
        "isDefault": False,
    },
]


def test_claude_default_entry_names_the_true_default(
    seeded_session: tuple[str, str],
) -> None:
    """Row 6: the claude model select reads "Opus 4.8 (1M context)".

    :param seeded_session: ``(base_url, session_id)`` from the spawned server.
    """
    base_url, session_id = seeded_session
    _run_in_fresh_loop(_drive_claude_default_label(base_url, session_id))


async def _drive_claude_default_label(base_url: str, session_id: str) -> None:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page()
        try:
            create_bodies: list[dict[str, Any]] = []
            await _register_common_routes(
                page, created_session_id=session_id, create_bodies=create_bodies
            )

            async def handle_agent_scan(route: Route) -> None:
                await route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=json.dumps({"data": []}),
                )

            async def handle_model_options(route: Route) -> None:
                await route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=json.dumps({"models": _CLAUDE_HOST_ROWS}),
                )

            import re as _re

            await page.route(
                _re.compile(r"/v1/sessions\?(?!.*pinned=).*visibility=mine"), handle_agent_scan
            )
            await page.route(
                f"**/v1/hosts/{_HOST_ID}/harnesses/claude-native/model-options",
                handle_model_options,
            )
            await page.add_init_script(
                f"""window.localStorage.setItem(
                    "omnigent:recent-workspaces",
                    JSON.stringify({{ {_HOST_ID}: ["/work/repo"] }})
                );"""
            )

            await page.goto(f"{base_url}/")
            await page.get_by_test_id("new-chat-landing-input").wait_for(
                state="visible", timeout=30_000
            )
            await _open_entry_models(page, "ag_claude_e2e")
            model = page.get_by_test_id("new-chat-landing-agent-models")
            # The design's row 6: the untouched select names the model a
            # Default launch truly runs, for claude exactly as for codex.
            await expect(model).to_contain_text("Opus 4.8 (1M context)")
        finally:
            await browser.close()


def test_codex_probe_failure_shows_host_error(seeded_session: tuple[str, str]) -> None:
    """A failed host probe shows its structured error instead of the HTTP status line."""
    base_url, session_id = seeded_session
    _run_in_fresh_loop(_drive_codex_probe_failure(base_url, session_id))


async def _drive_codex_probe_failure(base_url: str, session_id: str) -> None:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page()
        try:
            create_bodies: list[dict[str, Any]] = []
            await _register_common_routes(
                page,
                created_session_id=session_id,
                create_bodies=create_bodies,
                agents_body=_codex_native_agents_body(),
            )

            async def handle_agent_scan(route: Route) -> None:
                await route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=json.dumps({"data": []}),
                )

            async def handle_model_options(route: Route) -> None:
                await route.fulfill(
                    status=502,
                    content_type="application/json",
                    body=json.dumps({"detail": "the codex model probe failed — see the host log"}),
                )

            import re as _re

            await page.route(
                _re.compile(r"/v1/sessions\?(?!.*pinned=).*visibility=mine"), handle_agent_scan
            )
            await page.route(
                f"**/v1/hosts/{_HOST_ID}/harnesses/codex-native/model-options",
                handle_model_options,
            )
            await page.add_init_script(
                f"""window.localStorage.setItem(
                    "omnigent:recent-workspaces",
                    JSON.stringify({{ {_HOST_ID}: ["/work/repo"] }})
                );"""
            )

            await page.goto(f"{base_url}/")
            await page.get_by_test_id("new-chat-landing-input").wait_for(
                state="visible", timeout=30_000
            )
            await _open_entry_models(page, "ag_codex_e2e")

            await expect(
                page.get_by_text("the codex model probe failed — see the host log", exact=True)
            ).to_be_visible(timeout=30_000)
        finally:
            await browser.close()


def test_hosted_codex_only_submits_advertised_deepseek_model(
    seeded_session: tuple[str, str],
) -> None:
    """A gateway-bound Host must not offer or submit account-wide GPT models."""
    base_url, session_id = seeded_session
    _run_in_fresh_loop(_drive_hosted_codex_allowlist(base_url, session_id))


def test_hosted_codex_discards_stale_remembered_gpt_model(
    seeded_session: tuple[str, str],
) -> None:
    """A saved GPT pick cannot leak into a gateway-bound new-session create."""
    base_url, session_id = seeded_session
    _run_in_fresh_loop(_drive_hosted_codex_allowlist(base_url, session_id, stale_model=True))


async def _drive_hosted_codex_allowlist(
    base_url: str, session_id: str, *, stale_model: bool = False
) -> None:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page()
        try:
            create_bodies: list[dict[str, Any]] = []
            await _register_common_routes(
                page,
                created_session_id=session_id,
                create_bodies=create_bodies,
                agents_body=_codex_native_agents_body(),
            )

            async def handle_agent_scan(route: Route) -> None:
                await route.fulfill(json={"data": []})

            async def handle_model_options(route: Route) -> None:
                await route.fulfill(
                    json={
                        "models": [
                            {
                                "id": "deepseek-v4-pro",
                                "model": "deepseek-v4-pro",
                                "displayName": "deepseek-v4-pro",
                                "isDefault": True,
                            },
                            {
                                "id": "deepseek-flash",
                                "model": "deepseek-flash",
                                "displayName": "deepseek-flash",
                            },
                        ]
                    }
                )

            await page.route(
                re.compile(r"/v1/sessions\?(?!.*pinned=).*visibility=mine"), handle_agent_scan
            )
            await page.route(
                f"**/v1/hosts/{_HOST_ID}/harnesses/codex-native/model-options",
                handle_model_options,
            )
            await page.add_init_script(
                f"""window.localStorage.setItem(
                    "omnigent:recent-workspaces",
                    JSON.stringify({{ {_HOST_ID}: ["/work/repo"] }})
                );"""
            )
            if stale_model:
                await page.add_init_script(
                    """window.localStorage.setItem(
                        "omnigent:last-mode-by-harness",
                        JSON.stringify({"codex-native": {"model": "gpt-5.6-sol"}})
                    );"""
                )

            await page.goto(f"{base_url}/")
            await page.get_by_test_id("new-chat-landing-input").wait_for(
                state="visible", timeout=30_000
            )
            await _open_entry_models(page, "ag_codex_e2e")
            await expect(
                page.get_by_role("menuitemcheckbox", name="deepseek-flash", exact=True)
            ).to_be_visible()
            assert await page.get_by_role("menuitemcheckbox", name=re.compile("GPT")).count() == 0
            if not stale_model:
                await page.get_by_role(
                    "menuitemcheckbox", name="deepseek-flash", exact=True
                ).click()
            await _close_entry_models(page)

            await page.get_by_test_id("new-chat-landing-input").fill("Say hello")
            await page.get_by_test_id("new-chat-landing-submit").click()
            await _wait_until(lambda: len(create_bodies) == 1)
            assert create_bodies[0].get("model_override") == (
                None if stale_model else "deepseek-flash"
            )
        finally:
            await browser.close()
