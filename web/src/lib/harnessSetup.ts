/**
 * Requirements checklist for getting a harness ready to run on a host.
 *
 * The New Chat "Set up" dialog renders the steps this returns. The step
 * descriptors are authored by the server (``/v1/harnesses`` → ``setup_steps``)
 * so the UI can't drift from the real install/login commands; this module just
 * marks each step done/todo from the host's readiness map. Later milestones
 * (API key, gateway) add step kinds server-side and appear here for free.
 */

import { isAutoHarness, type SetupStepWire } from "@/lib/agentLabels";
import type { Host } from "@/hooks/useHosts";
import { isFeatureEnabled, type ServerInfo } from "@/lib/capabilities";

/** Whether a step is satisfied, still needed, or not locally determinable. */
export type SetupStepStatus = "done" | "todo" | "unknown";

/**
 * A server setup step resolved against a host's readiness.
 *
 * Carries the server's descriptor (title/detail/action/command) plus a
 * ``status`` derived from the host's ``configured_harnesses`` value:
 * ``done`` / ``todo`` for steps the host can assess (``status_key`` set), or
 * ``unknown`` for steps it can't (rendered as an informational instruction,
 * not a tracked ✓/○ — e.g. Pi's API-key step).
 */
export interface ResolvedSetupStep {
  kind: string;
  title: string;
  detail: string;
  /** ``"install"`` (one-click), ``"command"`` (run on host), ``"setup"`` (omni setup). */
  action: string;
  command: string | null;
  status: SetupStepStatus;
  /** The harness id to POST for a one-click install (``action === "install"``). */
  harness: string;
}

/** In-process SDK harness spellings whose ``needs-auth`` state is advisory.
 * The host cannot see agent-level ``executor.auth``, so these rows must stay
 * selectable and visible even when the host has no ambient credential. */
const SDK_HARNESSES = new Set([
  "claude-sdk",
  "claude_sdk",
  "claude",
  "openai-agents",
  "openai-agents-sdk",
  "agents_sdk",
  "antigravity",
  "agy",
  "google-antigravity",
]);

export function isSdkHarness(harness: string): boolean {
  return SDK_HARNESSES.has(harness);
}

/** Whether *harness* is a Codex spelling (bare or native). Codex is the only
 *  family whose flag-off warning copy is harness-specific ("run codex login"),
 *  so the message helper gates on this. */
export function isCodexHarness(harness: string): boolean {
  return harness === "codex" || harness === "codex-native" || harness === "native-codex";
}

export function isNativeCursorHarness(harness: string): boolean {
  return harness === "cursor-native" || harness === "native-cursor";
}

/** Build the readiness profile for a newly provisioned managed sandbox.
 *
 * Managed hosts are not user-selectable machines, but their connect handshake
 * is the authoritative probe of the image, credentials, and provider config a
 * new sandbox will inherit. Prefer live instances for the selected provider;
 * when an idle-reclaiming provider has none, fall back to its last reports.
 * Conflicting reports fail closed per harness so a mixed rollout never claims
 * an agent is ready until every sampled runtime agrees.
 */
export function managedSandboxReadinessHost(
  hosts: readonly Host[],
  provider: string | null | undefined,
  label: string,
): Host | null {
  if (!provider) return null;
  const matching = hosts.filter(
    (host) =>
      host.sandbox_provider === provider &&
      host.configured_harnesses != null &&
      Object.keys(host.configured_harnesses).length > 0,
  );
  const online = matching.filter((host) => host.status === "online");
  const samples = online.length > 0 ? online : matching;
  if (samples.length === 0) return null;

  const keys = new Set(samples.flatMap((host) => Object.keys(host.configured_harnesses ?? {})));
  const configuredHarnesses: Record<string, boolean | string> = {};
  for (const key of keys) {
    const values = samples.map((host) => host.configured_harnesses?.[key]);
    if (values.every((value) => value === true)) {
      configuredHarnesses[key] = true;
      continue;
    }
    configuredHarnesses[key] =
      values.find((value) => value === "needs-auth") ??
      values.find((value) => value === "version-too-low") ??
      values.find((value) => value === "binary-missing") ??
      values.find((value): value is string => typeof value === "string") ??
      false;
  }

  const gatewayReports = samples
    .map((host) => host.gateway_inference)
    .filter((report): report is Record<string, boolean> => report != null);
  const gatewayKeys = new Set(gatewayReports.flatMap((report) => Object.keys(report)));
  const gatewayInference: Record<string, boolean> = {};
  for (const key of gatewayKeys) {
    gatewayInference[key] = gatewayReports.every((report) => report[key] === true);
  }

  return {
    host_id: `sandbox-provider:${provider}`,
    name: label,
    owner: "managed-sandbox",
    status: "online",
    sandbox_provider: provider,
    configured_harnesses: configuredHarnesses,
    gateway_inference: gatewayReports.length > 0 ? gatewayInference : null,
  };
}

/**
 * Why *harness* can't run on *host* right now, including an unresolved
 * Agent harness even when no host is selected. Otherwise null means ready or
 * unknown readiness. Drives the picker "needs setup"
 * badge and the composer notice; the setup dialog uses the fuller
 * {@link resolveSetupSteps}.
 */
export function harnessUnavailableReasonOnHost(
  harness: string | null | undefined,
  host: Host | undefined | null,
): string | null {
  if (!harness) return "agent-unavailable";
  if (!host?.configured_harnesses) return null;
  const availability = host.configured_harnesses[harness];
  if (availability === false) {
    if (isCodexHarness(harness)) return "binary-missing";
    return "unconfigured";
  }
  // Auth-aware CLI harnesses (codex, claude, opencode) report a structured
  // string when installed-but-not-ready. "version-too-low" can surface for
  // any CLI-backed harness whose binary is present but too old.
  if (
    availability === "binary-missing" ||
    availability === "needs-auth" ||
    availability === "version-too-low"
  ) {
    return availability;
  }
  // Any other string from a newer/older server still means "not ready";
  // show a generic warning rather than silently treating it as available.
  if (typeof availability === "string") {
    return "unconfigured";
  }
  // Missing key on a host that DOES report readiness (a non-empty map): the host
  // can't launch this harness — its runner has no catalog row for it, e.g. a host
  // predating a newly-added harness (jcode on a pre-jcode host, which reports
  // devin/grok but omits jcode). Treat it as unconfigured so "hide unconfigured"
  // hides it, instead of failing open and offering a harness the host can't run.
  // Excludes the client-only Smart Routing "auto" sentinels: the daemon never
  // reports a readiness key for those, so they must stay selectable and unbadged.
  // An absent/empty map still fails open (the guard above, plus the size check),
  // so a host that reports no readiness at all is never emptied out.
  if (
    availability === undefined &&
    !isAutoHarness(harness) &&
    Object.keys(host.configured_harnesses).length > 0
  ) {
    return "unconfigured";
  }
  return null;
}

/** A catalog Agent with no harness has an unreadable bundle; a session-discovered
 * Agent may simply be waiting for its spec to load from that session. */
export function agentHarnessUnavailableReasonOnHost(
  agent: { harness: string | null; sessionId?: string } | null | undefined,
  host: Host | undefined | null,
): string | null {
  if (!agent || (agent.harness === null && agent.sessionId)) return null;
  return harnessUnavailableReasonOnHost(agent.harness, host);
}

/**
 * Whether *harness* is reported not-ready on *host*. Gates the "needs setup"
 * badge in the picker rows and the composer notice.
 */
export function harnessUnconfiguredOnHost(
  harness: string | null | undefined,
  host: Host | undefined | null,
): boolean {
  return harnessUnavailableReasonOnHost(harness, host) !== null;
}

/** Whether the opt-in "hide unconfigured" filter should remove a harness.
 * SDK ``needs-auth`` is a warning, not proof the agent cannot authenticate. */
export function harnessHiddenAsUnconfiguredOnHost(
  harness: string | null | undefined,
  host: Host | undefined | null,
): boolean {
  const reason = harnessUnavailableReasonOnHost(harness, host);
  return reason !== null && !(reason === "needs-auth" && !!harness && isSdkHarness(harness));
}

/**
 * Amber-badge text for a not-ready harness in the picker rows.
 *
 * When the setup feature is OFF this is the label — per-reason, matching the
 * pre-feature UI. When the feature is ON the picker shows a single "needs
 * setup" label instead (the specific reason + fix live in the setup dialog),
 * so callers pass ``collapsed`` to get that. Keeping both here means the
 * flag-off path renders byte-for-byte the original text.
 */
export function harnessWarningBadgeText(reason: string | null, collapsed = false): string {
  if (reason === "agent-unavailable") return "agent unavailable";
  if (collapsed) return "needs setup";
  if (reason === "binary-missing") return "binary missing";
  if (reason === "needs-auth") return "needs auth";
  if (reason === "version-too-low") return "outdated";
  return "needs setup";
}

/**
 * Whether the server will install *harness* onto a host from the UI.
 *
 * True only when the feature is on, the host is online, and the server lists
 * this harness id (bare or native spelling) in ``installable_harnesses`` —
 * matching the install route's allowlist, so the UI never offers an install the
 * server would reject.
 */
export function harnessInstallableOnHost(
  info: ServerInfo | "loading",
  harness: string | null | undefined,
  host: Host | undefined | null,
): boolean {
  return (
    info !== "loading" &&
    isFeatureEnabled(info, "harness_install") &&
    !!harness &&
    info.installable_harnesses.includes(harness) &&
    host?.status === "online"
  );
}

/**
 * The provider family a UI-authable *harness* configures, or ``null`` when the
 * harness isn't one the UI authenticates. Mirrors the backend's harness→family
 * resolution: Claude → anthropic, Codex → openai, Pi → anthropic (its preferred
 * fallback family). The single source of truth for "which harnesses the UI can
 * authenticate" — {@link harnessAuthableOnHost} keys off a non-null result, and
 * the credential form scopes host-wide detected credentials to this family so
 * the adopt affordance can't offer (and persist) a cross-family key — e.g. an
 * Anthropic key for Codex.
 */
export function harnessCredentialFamily(harness: string | null | undefined): string | null {
  if (!harness) return null;
  if (["claude", "claude-native", "native-claude"].includes(harness)) return "anthropic";
  if (["codex", "codex-native", "native-codex"].includes(harness)) return "openai";
  if (["pi", "pi-native", "native-pi"].includes(harness)) return "anthropic";
  return null;
}

/**
 * The provider families whose detected credentials a harness can *adopt*.
 *
 * Usually the harness's own family (Claude → anthropic, Codex → openai). Pi is
 * the exception: it consumes BOTH anthropic and openai (it has no CLI login and
 * routes through either), and the daemon adopts a detected credential under its
 * OWN detected family — so a host with only ``$OPENAI_API_KEY`` can still back
 * Pi. Scoping the adopt filter to this set (not the single write-default family)
 * surfaces that affordance while still keeping a cross-family key off a harness
 * that can't use it (e.g. an Anthropic key for Codex). Empty when the harness
 * isn't UI-authable.
 */
export function harnessCredentialAdoptFamilies(harness: string | null | undefined): string[] {
  const family = harnessCredentialFamily(harness);
  if (family === null) return [];
  if (["pi", "pi-native", "native-pi"].includes(harness as string)) return ["anthropic", "openai"];
  return [family];
}

/**
 * Whether the UI can write a credential for *harness* on *host* (the M3 auth
 * form vs. a copy-command signpost). True only when the feature is on, the host
 * is online, and the harness is one whose credential omnigent owns (Claude /
 * Codex / Pi). Mirrors the server's UI-auth allowlist so the form never posts a
 * credential the route would reject.
 */
export function harnessAuthableOnHost(
  info: ServerInfo | "loading",
  harness: string | null | undefined,
  host: Host | undefined | null,
): boolean {
  return (
    info !== "loading" &&
    isFeatureEnabled(info, "harness_install") &&
    harnessCredentialFamily(harness) !== null &&
    host?.status === "online"
  );
}

/**
 * Resolve a server step's done/todo status from the host's readiness value.
 *
 * The host reports one availability per harness — ``true`` (ready),
 * ``"needs-auth"`` (installed, not signed in), ``"binary-missing"`` / ``false``
 * (not installed). Each step's ``status_key`` says which sub-state it tracks:
 * ``"installed"`` is done once the binary is present (anything but not-installed);
 * ``"authed"`` is done only when fully ready. A ``null`` key isn't locally
 * determinable → ``"unknown"`` (informational).
 */
function stepStatus(
  statusKey: string | null,
  availability: boolean | string | undefined,
): SetupStepStatus {
  if (statusKey === null || availability === undefined) return "unknown";
  const notInstalled =
    availability === false ||
    availability === "binary-missing" ||
    availability === "version-too-low";
  if (statusKey === "installed") return notInstalled ? "todo" : "done";
  if (statusKey === "authed") return availability === true ? "done" : "todo";
  return "unknown";
}

/**
 * Combine the server's ordered setup steps for *harness* with the host's
 * readiness into a resolved checklist for the setup dialog.
 *
 * @param serverSteps The ``setup_steps`` the server published for this harness.
 * @param harness The harness id the session declares, e.g. ``"codex-native"``.
 * @param host The selected host (its ``configured_harnesses`` supplies status).
 * @returns Ordered resolved steps; ``[]`` when the harness has no descriptor.
 */
export function resolveSetupSteps(
  serverSteps: SetupStepWire[] | undefined,
  harness: string | null | undefined,
  host: Host | undefined | null,
): ResolvedSetupStep[] {
  if (!serverSteps || !harness) return [];
  const availability = host?.configured_harnesses?.[harness];
  const resolved = serverSteps.map((step) => ({
    kind: step.kind,
    title: step.title,
    detail: step.detail,
    action: step.action,
    command: step.command,
    status: stepStatus(step.status_key, availability),
    harness,
  }));
  // Drop steps whose status the host can't determine (status_key: null, e.g.
  // Pi/Qwen's credential step) WHEN there's a trackable step to anchor on.
  // Showing an untrackable step pre-install and then having it vanish once the
  // binary lands (the harness reports "ready") is more confusing than never
  // showing it. But never drop the *only* step — a non-installable harness's
  // sole "run omni setup" step must still render.
  const trackable = resolved.filter((s) => s.status !== "unknown");
  return trackable.length > 0 ? trackable : resolved;
}
