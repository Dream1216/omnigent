(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const state = {
    csrf: sessionStorage.getItem("omnigent.platform.csrf") || "",
    context: null,
    permissions: new Set(),
    catalog: [],
    users: [],
    tenants: [],
    conflicts: [],
    support: [],
    audit: [],
    operations: [],
    cursors: { users: null, tenants: null, support: null, audit: null, operations: null },
    loaded: new Set(),
    view: "overview",
    dialogResolver: null,
  };

  function node(tag, className = "", text = "") {
    const value = document.createElement(tag);
    if (className) value.className = className;
    if (text !== "") value.textContent = String(text);
    return value;
  }

  function shortId(value) {
    return value ? String(value).slice(0, 8) : "—";
  }

  function formatDate(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
  }

  function localDateTime(value) {
    const date = new Date(value);
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 16);
  }

  function splitValues(value) {
    return value.split(",").map((item) => item.trim()).filter(Boolean);
  }

  function can(permission) {
    return state.permissions.has(permission);
  }

  function mutationReady(permission) {
    return can(permission) && Boolean(state.csrf);
  }

  function toast(message, tone = "info") {
    const item = node("div", "toast", message);
    item.dataset.tone = tone;
    $("#toast-stack").prepend(item);
    window.setTimeout(() => item.remove(), 6500);
  }

  function requestError(payload, status) {
    const detail = payload?.error || payload?.detail || payload;
    const code = detail?.code || `http_${status}`;
    const message = detail?.message || "Request failed";
    const error = new Error(`${code}: ${message}`);
    error.code = code;
    return error;
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    let body = options.body;
    if (body && typeof body !== "string") {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(body);
    }
    const method = (options.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      if (!state.csrf) throw new Error("platform_csrf_unbound: reauthenticate Staff session");
      headers.set("X-CSRF-Token", state.csrf);
    }
    const response = await fetch(path, {
      credentials: "same-origin",
      ...options,
      method,
      body,
      headers,
    });
    const payload = response.status === 204 ? null : await response.json().catch(() => ({}));
    if (!response.ok) throw requestError(payload, response.status);
    return payload;
  }

  function idempotency(prefix) {
    return `${prefix}-${crypto.randomUUID()}`;
  }

  async function run(action, successMessage = "") {
    try {
      const result = await action();
      if (successMessage) toast(successMessage, "success");
      return result;
    } catch (error) {
      toast(error instanceof Error ? error.message : String(error), "error");
      return null;
    }
  }

  function emptyRecord(message) {
    return node("div", "empty-record", message);
  }

  function statusChip(status) {
    const chip = node("span", "status-chip", String(status || "unknown").toUpperCase());
    chip.dataset.status = status || "unknown";
    return chip;
  }

  function actionButton(label, handler, options = {}) {
    const button = node("button", options.danger ? "danger" : "", label);
    button.type = "button";
    if (options.testId) button.dataset.testid = options.testId;
    if (options.disabled) {
      button.disabled = true;
      button.title = options.title || "Permission or CSRF binding required";
    } else {
      button.addEventListener("click", () => void run(handler));
    }
    return button;
  }

  function recordRow({ title, identifier, status, meta = [], actions = [] }) {
    const row = node("article", "record-row");
    const primary = node("div", "record-primary");
    primary.append(node("strong", "", title || "UNNAMED"));
    if (identifier) primary.append(node("code", "", identifier));
    const metadata = node("div", "record-meta");
    if (status) metadata.append(statusChip(status));
    meta.filter(Boolean).forEach((value) => metadata.append(node("span", "", value)));
    const controls = node("div", "record-actions");
    actions.forEach((action) => controls.append(action));
    row.append(primary, metadata, controls);
    return row;
  }

  function configureNavigation() {
    const notificationLink = $("#notification-operations-link");
    notificationLink.hidden = !Boolean(
      state.context?.capabilities?.notification_operations_enabled
    );
    document.querySelectorAll("[data-permission]").forEach((button) => {
      const permitted = can(button.dataset.permission);
      button.disabled = !permitted;
      button.setAttribute("aria-disabled", String(!permitted));
    });
    $("#no-platform-access").hidden = state.permissions.size > 0;
  }

  function showView(view) {
    const button = document.querySelector(`[data-view="${view}"]`);
    if (!button || button.disabled) {
      toast("platform_permission_denied: this module is not assigned", "error");
      return;
    }
    state.view = view;
    document.querySelectorAll("[data-view]").forEach((item) => {
      item.classList.toggle("active", item.dataset.view === view);
    });
    document.querySelectorAll("[data-view-panel]").forEach((panel) => {
      const selected = panel.dataset.viewPanel === view;
      panel.hidden = !selected;
      panel.classList.toggle("active", selected);
    });
    window.history.replaceState(null, "", view === "overview" ? "#overview" : `#${view}`);
    if (!state.loaded.has(view)) void run(() => loadView(view));
  }

  async function loadView(view) {
    const loaders = {
      users: () => loadUsers(false),
      tenants: () => loadTenants(false),
      access: loadAccess,
      support: () => loadSupport(false),
      privacy: () => window.OmnigentPrivacy?.load(),
      audit: () => loadAudit(false),
    };
    if (loaders[view]) await loaders[view]();
    state.loaded.add(view);
  }

  function renderIdentity() {
    const principalId = state.context.principal_id;
    $("#principal-short").textContent = `STAFF / ${shortId(principalId)}`;
    $("#principal-id").textContent = principalId;
    $("#policy-version").textContent = `POLICY / ${state.context.policy_version}`;
    const roleList = $("#role-list");
    roleList.replaceChildren();
    const roles = state.context.roles || [];
    if (!roles.length) roleList.append(node("span", "role-chip", "ROLELESS"));
    roles.forEach((role) => roleList.append(node("span", "role-chip", role.toUpperCase())));
  }

  function renderPosture() {
    const definitions = state.catalog.filter((item) => state.permissions.has(item.name));
    const risks = ["low", "medium", "high", "critical"];
    const counts = new Map(risks.map((risk) => [risk, 0]));
    definitions.forEach((item) => counts.set(item.risk, (counts.get(item.risk) || 0) + 1));
    const maximum = Math.max(1, ...counts.values());
    const root = $("#posture-bars");
    root.replaceChildren();
    risks.forEach((risk) => {
      const row = node("div", "posture-row");
      row.dataset.risk = risk;
      const track = node("progress", "posture-track");
      track.max = maximum;
      track.value = counts.get(risk) || 0;
      track.setAttribute("aria-label", `${risk} permission exposure`);
      row.append(node("span", "", risk.toUpperCase()), track, node("strong", "", counts.get(risk) || 0));
      root.append(row);
    });
    $("#permission-count").textContent = `${state.permissions.size} PERMISSIONS`;
  }

  function renderAttention() {
    const items = [];
    const pendingSupport = state.support.filter((item) => item.status?.startsWith("pending"));
    const pendingOperations = state.operations.filter((item) => item.status?.startsWith("pending"));
    const pendingConflicts = state.conflicts.filter((item) => item.platform_review_status === "unreviewed");
    if (can("platform.support.read")) items.push([pendingSupport.length, "SUPPORT APPROVALS", "grant-scoped only"]);
    if (can("platform.operations.read")) items.push([pendingOperations.length, "ADMIN OPERATIONS", "immutable receipts"]);
    if (can("platform.identity_conflict.read")) items.push([pendingConflicts.length, "IDENTITY CONFLICTS", "content-blind cases"]);
    const list = $("#attention-list");
    list.replaceChildren();
    if (!items.length) list.append(emptyRecord("NO AUTHORIZED ATTENTION QUEUES"));
    items.forEach(([count, title, note], index) => {
      const item = node("li");
      const copy = node("div");
      copy.append(node("strong", "", title), node("small", "", note));
      item.append(node("span", "", String(index + 1).padStart(2, "0")), copy, node("b", "", String(count).padStart(2, "0")));
      list.append(item);
    });
  }

  function renderOverview() {
    $("#metric-tenants").textContent = can("platform.tenant.read") ? String(state.tenants.length).padStart(2, "0") : "—";
    $("#metric-users").textContent = can("platform.user.read") ? String(state.users.length).padStart(2, "0") : "—";
    $("#metric-support").textContent = can("platform.support.read") ? String(state.support.filter((item) => item.status?.startsWith("pending") || item.status === "active").length).padStart(2, "0") : "—";
    $("#metric-operations").textContent = can("platform.operations.read") ? String(state.operations.filter((item) => item.status?.startsWith("pending")).length).padStart(2, "0") : "—";
    $("#operations-count").textContent = can("platform.operations.read") ? String(state.operations.filter((item) => item.status?.startsWith("pending")).length).padStart(2, "0") : "—";
    renderPosture();
    renderAttention();
  }

  function renderUsers() {
    const term = $("#users-search").value.trim().toLowerCase();
    const status = $("#users-status").value;
    const values = state.users.filter((item) => {
      const haystack = `${item.display_name || ""} ${item.email_masked || ""} ${item.user_id}`.toLowerCase();
      return (!term || haystack.includes(term)) && (!status || item.status === status);
    });
    const list = $("#users-list");
    list.replaceChildren();
    $("#users-total").textContent = String(values.length).padStart(2, "0");
    if (!values.length) list.append(emptyRecord("NO VISIBLE GLOBAL USER PROJECTIONS"));
    values.forEach((item) => {
      const manage = item.status === "suspended" ? "restore" : "suspend";
      const managePermission = manage === "restore" ? "platform.user.restore" : "platform.user.suspend";
      const actions = [
        actionButton(manage.toUpperCase(), () => mutateUser(item, manage), {
          danger: manage === "suspend",
          disabled: !mutationReady(managePermission) || item.status === "deleted",
          testId: `user-${manage}-${item.user_id}`,
        }),
        actionButton("REVOKE SESSIONS", () => mutateUser(item, "revoke-sessions"), {
          disabled: !mutationReady("platform.user.sessions.revoke") || item.status === "deleted",
          testId: `user-revoke-sessions-${item.user_id}`,
        }),
      ];
      list.append(recordRow({
        title: item.display_name || `USER ${shortId(item.user_id)}`,
        identifier: `${item.email_masked || "EMAIL WITHHELD"} · ${item.user_id}`,
        status: item.status,
        meta: [`${item.membership_count ?? 0} memberships`, formatDate(item.updated_at)],
        actions,
      }));
    });
    $("#users-more").hidden = !state.cursors.users;
  }

  async function loadUsers(append) {
    const cursor = append ? state.cursors.users : null;
    const query = cursor ? `?limit=50&cursor=${encodeURIComponent(cursor)}` : "?limit=50";
    const payload = await api(`/v2/platform-admin/users${query}`);
    state.users = append ? state.users.concat(payload.items) : payload.items;
    state.cursors.users = payload.next_cursor;
    renderUsers();
    renderOverview();
  }

  async function mutateUser(item, action) {
    const preview = await api(`/v2/platform-admin/users/${item.user_id}/lifecycle-preview`);
    const lifecycle = action === "revoke-sessions" ? "revoke-sessions" : action;
    const fields = action === "revoke-sessions"
      ? [{ name: "reason", label: "REASON", type: "textarea", required: true }]
      : [
          { name: "approval_ref", label: "EXTERNAL APPROVAL REF", required: true },
          { name: "reason", label: "REASON", type: "textarea", required: true },
        ];
    const values = await openAction({
      title: `${action} global user`,
      summary: `${item.display_name || item.user_id} · authoritative ${preview.status} / V${preview.security_version}`,
      risk: action === "revoke-sessions" ? "HIGH" : "CRITICAL",
      confirm: action.toUpperCase(),
      fields,
    });
    if (!values) return;
    const body = { expected_version: preview.security_version, reason: values.reason };
    if (values.approval_ref) body.approval_ref = values.approval_ref;
    const payload = await api(`/v2/platform-admin/users/${item.user_id}/${lifecycle}`, {
      method: "POST",
      headers: { "Idempotency-Key": idempotency(`pc4-user-${action}`) },
      body,
    });
    item.status = payload.result.status;
    item.security_version = payload.result.security_version;
    renderUsers();
    await refreshOperations();
    toast(`${payload.action} accepted · ${shortId(payload.operation_id)}`, "success");
  }

  function renderTenants() {
    const term = $("#tenants-search").value.trim().toLowerCase();
    const status = $("#tenants-status").value;
    const values = state.tenants.filter((item) => {
      const haystack = `${item.name || ""} ${item.slug || ""} ${item.tenant_id}`.toLowerCase();
      return (!term || haystack.includes(term)) && (!status || item.status === status);
    });
    const list = $("#tenants-list");
    list.replaceChildren();
    $("#tenants-total").textContent = String(values.length).padStart(2, "0");
    if (!values.length) list.append(emptyRecord("NO VISIBLE TENANT PROJECTIONS"));
    values.forEach((item) => {
      const manage = item.status === "suspended" ? "restore" : "suspend";
      const actions = [
        actionButton(manage.toUpperCase(), () => mutateTenant(item, manage), {
          danger: manage === "suspend",
          disabled: !mutationReady("platform.tenant.lifecycle.manage"),
          testId: `tenant-${manage}-${item.tenant_id}`,
        }),
        actionButton("OWNER RECOVERY", () => recoverOwner(item), {
          disabled: !mutationReady("platform.tenant.owner_recover"),
          testId: `tenant-owner-recovery-${item.tenant_id}`,
        }),
      ];
      list.append(recordRow({
        title: item.name || item.slug,
        identifier: `${item.slug} · ${item.tenant_id}`,
        status: item.status,
        meta: [`${item.plan} / ${item.home_region}`, `${item.member_count} members · ${item.space_count} spaces`],
        actions,
      }));
    });
    $("#tenants-more").hidden = !state.cursors.tenants;
  }

  async function loadTenants(append) {
    const cursor = append ? state.cursors.tenants : null;
    const query = cursor ? `?limit=50&cursor=${encodeURIComponent(cursor)}` : "?limit=50";
    const payload = await api(`/v2/platform-admin/tenants${query}`);
    state.tenants = append ? state.tenants.concat(payload.items) : payload.items;
    state.cursors.tenants = payload.next_cursor;
    renderTenants();
    renderOverview();
  }

  async function mutateTenant(item, action) {
    const preview = await api(`/v2/platform-admin/tenants/${item.tenant_id}/lifecycle-preview`);
    const values = await openAction({
      title: `${action} Tenant`,
      summary: `${item.name} · authoritative ${preview.status} / V${preview.lifecycle_version}`,
      risk: "CRITICAL",
      confirm: action.toUpperCase(),
      fields: [
        { name: "approval_ref", label: "EXTERNAL APPROVAL REF", required: true },
        { name: "reason", label: "REASON", type: "textarea", required: true },
      ],
    });
    if (!values) return;
    const payload = await api(`/v2/platform-admin/tenants/${item.tenant_id}/${action}`, {
      method: "POST",
      headers: { "Idempotency-Key": idempotency(`pc4-tenant-${action}`) },
      body: {
        expected_version: preview.lifecycle_version,
        approval_ref: values.approval_ref,
        reason: values.reason,
      },
    });
    item.status = payload.result.status;
    renderTenants();
    await refreshOperations();
    toast(`${payload.action} accepted · ${shortId(payload.operation_id)}`, "success");
  }

  async function recoverOwner(item) {
    const request = await openAction({
      title: "Preview Owner Recovery",
      summary: `${item.name} · this does not mutate membership`,
      risk: "CRITICAL",
      confirm: "RUN PREFLIGHT",
      fields: [{ name: "target_user_id", label: "TARGET USER ID", required: true }],
    });
    if (!request) return;
    const preview = await api(`/v2/platform-admin/tenants/${item.tenant_id}/owner-recovery-preview?target_user_id=${encodeURIComponent(request.target_user_id)}`);
    if (preview.blockers.length) {
      toast(`owner_recovery_blocked: ${preview.blockers.join(", ")}`, "error");
      return;
    }
    const values = await openAction({
      title: "Execute Owner Recovery",
      summary: `Source ${shortId(preview.source_owner_id)} → target ${shortId(preview.target_user_id)} · hash ${shortId(preview.preview_hash)}`,
      risk: "CRITICAL",
      confirm: "TRANSFER OWNERSHIP",
      fields: [
        { name: "approval_ref", label: "EXTERNAL APPROVAL REF", required: true },
        { name: "reason", label: "REASON", type: "textarea", required: true },
      ],
    });
    if (!values) return;
    const payload = await api(`/v2/platform-admin/tenants/${item.tenant_id}/owner-recovery`, {
      method: "POST",
      headers: { "Idempotency-Key": idempotency("pc4-owner-recovery") },
      body: {
        target_user_id: preview.target_user_id,
        expected_tenant_version: preview.tenant_version,
        expected_source_membership_version: preview.source_membership_version,
        expected_target_membership_version: preview.target_membership_version,
        preview_hash: preview.preview_hash,
        approval_ref: values.approval_ref,
        reason: values.reason,
      },
    });
    await refreshOperations();
    toast(`Owner Recovery accepted · ${shortId(payload.operation_id)}`, "success");
  }

  function renderAccess() {
    const list = $("#conflicts-list");
    list.replaceChildren();
    $("#conflicts-total").textContent = String(state.conflicts.length).padStart(2, "0");
    if (!state.conflicts.length) list.append(emptyRecord("NO PENDING IDENTITY CONFLICT CASES"));
    state.conflicts.forEach((item) => {
      const actions = [
        actionButton("ASSIGN CANDIDATE", () => reviewConflict(item, "assign"), {
          disabled: !mutationReady("platform.identity_conflict.manage"),
          testId: `conflict-assign-${item.conflict_id}`,
        }),
        actionButton("BLOCK", () => reviewConflict(item, "block"), {
          danger: true,
          disabled: !mutationReady("platform.identity_conflict.manage"),
          testId: `conflict-block-${item.conflict_id}`,
        }),
      ];
      list.append(recordRow({
        title: `${item.provider} CONFLICT`,
        identifier: item.conflict_id,
        status: item.platform_review_status,
        meta: [`candidate ${shortId(item.candidate_user_id)}`, `V${item.version} · ${formatDate(item.updated_at)}`],
        actions,
      }));
    });

    const catalog = $("#permission-matrix");
    catalog.replaceChildren();
    const visible = state.catalog.filter((item) => state.permissions.has(item.name));
    visible.forEach((item) => {
      const row = node("div", "permission-item");
      row.dataset.risk = item.risk;
      row.append(node("strong", "", item.name), node("span", "", item.risk));
      catalog.append(row);
    });
    if (!visible.length) catalog.append(emptyRecord("NO PLATFORM CAPABILITIES"));
    $("#risk-summary").textContent = `${visible.filter((item) => item.risk === "critical").length} CRITICAL`;
  }

  async function loadAccess() {
    const [conflicts, catalog] = await Promise.all([
      api("/v2/platform-admin/identity-conflicts?status=pending&limit=50"),
      api("/v2/platform-admin/permissions"),
    ]);
    state.conflicts = conflicts.items;
    state.catalog = catalog.permissions;
    renderAccess();
    renderOverview();
  }

  async function reviewConflict(item, decision) {
    const fields = [
      ...(decision === "assign" ? [{ name: "candidate_user_id", label: "CANDIDATE USER ID", value: item.candidate_user_id || "", required: true }] : []),
      { name: "approval_ref", label: "EXTERNAL APPROVAL REF", required: true },
      { name: "reason", label: "REASON", type: "textarea", required: true },
    ];
    const values = await openAction({
      title: `${decision} Identity Conflict`,
      summary: `${item.provider} · ${item.conflict_id} · V${item.version}`,
      risk: "CRITICAL",
      confirm: decision.toUpperCase(),
      fields,
    });
    if (!values) return;
    const body = { expected_version: item.version, approval_ref: values.approval_ref, reason: values.reason };
    if (values.candidate_user_id) body.candidate_user_id = values.candidate_user_id;
    await api(`/v2/platform-admin/identity-conflicts/${item.conflict_id}/${decision}`, {
      method: "POST",
      headers: { "Idempotency-Key": idempotency(`pc4-conflict-${decision}`) },
      body,
    });
    state.conflicts = state.conflicts.filter((value) => value.conflict_id !== item.conflict_id);
    renderAccess();
    toast(`Identity Conflict ${decision} accepted`, "success");
  }

  function renderSupport() {
    const list = $("#support-list");
    list.replaceChildren();
    $("#support-total").textContent = String(state.support.length).padStart(2, "0");
    if (!state.support.length) list.append(emptyRecord("NO VISIBLE SUPPORT GRANTS"));
    state.support.forEach((item) => {
      const actions = [];
      if (item.status === "pending_staff_approval") {
        actions.push(
          actionButton("APPROVE", () => decideSupport(item, "approve"), {
            disabled: !mutationReady("platform.support_grant.manage"),
            testId: `support-approve-${item.grant_id}`,
          }),
          actionButton("REJECT", () => decideSupport(item, "reject"), {
            danger: true,
            disabled: !mutationReady("platform.support_grant.manage"),
            testId: `support-reject-${item.grant_id}`,
          }),
        );
      }
      if (["active", "pending_customer_approval", "pending_staff_approval"].includes(item.status)) {
        actions.push(actionButton("REVOKE", () => decideSupport(item, "revoke"), {
          danger: true,
          disabled: !mutationReady("platform.support_grant.manage"),
          testId: `support-revoke-${item.grant_id}`,
        }));
      }
      if (item.status === "active" && item.requested_by_principal_id === state.context.principal_id) {
        actions.push(actionButton("ISSUE SESSION", () => issueSupportSession(item), {
          disabled: !mutationReady("platform.support.request"),
          testId: `support-session-${item.grant_id}`,
        }));
      }
      list.append(recordRow({
        title: `${item.mode === "break_glass" ? "BREAK-GLASS" : "STANDARD"} / ${shortId(item.tenant_id)}`,
        identifier: item.grant_id,
        status: item.status,
        meta: [`${item.scopes.join(", ")} · V${item.version}`, `expires ${formatDate(item.expires_at)}`],
        actions,
      }));
    });
    $("#support-more").hidden = !state.cursors.support;
    const requestAllowed = can("platform.support.request") || can("platform.break_glass.request");
    $("#support-request-form").querySelectorAll("input, select, textarea, button").forEach((field) => {
      field.disabled = !requestAllowed || !state.csrf;
    });
  }

  async function loadSupport(append) {
    const cursor = append ? state.cursors.support : null;
    const query = cursor ? `?limit=50&cursor=${encodeURIComponent(cursor)}` : "?limit=50";
    const payload = await api(`/v2/platform-admin/support-access-grants${query}`);
    state.support = append ? state.support.concat(payload.items) : payload.items;
    state.cursors.support = payload.next_cursor;
    renderSupport();
    renderOverview();
  }

  async function requestSupport(event) {
    event.preventDefault();
    const mode = $("#support-mode").value;
    const payload = await api("/v2/platform-admin/support-access-grants", {
      method: "POST",
      headers: { "Idempotency-Key": idempotency("pc4-support-request") },
      body: {
        tenant_id: $("#support-tenant-id").value.trim(),
        mode,
        scopes: splitValues($("#support-scopes").value),
        project_ids: splitValues($("#support-project-ids").value),
        reason: $("#support-reason").value.trim(),
        incident_ref: $("#support-incident-ref").value.trim() || null,
        expires_at: new Date($("#support-expires-at").value).toISOString(),
      },
    });
    state.support.unshift(payload);
    renderSupport();
    await refreshOperations();
    toast(`Support Grant requested · ${shortId(payload.grant_id)}`, "success");
  }

  async function decideSupport(item, decision) {
    const values = await openAction({
      title: `${decision} Support Grant`,
      summary: `${item.mode} · ${item.tenant_id} · V${item.version}`,
      risk: "CRITICAL",
      confirm: decision.toUpperCase(),
      fields: [{ name: "reason", label: "DECISION REASON", type: "textarea", required: true }],
    });
    if (!values) return;
    const payload = await api(`/v2/platform-admin/support-access-grants/${item.grant_id}/${decision}`, {
      method: "POST",
      headers: { "Idempotency-Key": idempotency(`pc4-support-${decision}`) },
      body: { expected_version: item.version, reason: values.reason },
    });
    Object.assign(item, payload);
    renderSupport();
    await refreshOperations();
    toast(`Support Grant ${decision} accepted`, "success");
  }

  async function issueSupportSession(item) {
    const payload = await api(`/v2/platform-admin/support-access-grants/${item.grant_id}/sessions`, {
      method: "POST",
      headers: { "Idempotency-Key": idempotency("pc4-support-session") },
      body: { expected_version: item.version },
    });
    $("#support-one-time-token").textContent = payload.token;
    $("#token-dialog").showModal();
    await refreshOperations();
  }

  function renderAudit() {
    const list = $("#audit-list");
    list.replaceChildren();
    $("#audit-total").textContent = String(state.audit.length).padStart(2, "0");
    if (!state.audit.length) list.append(emptyRecord("NO VISIBLE AUDIT EVENTS IN THIS RANGE"));
    state.audit.forEach((item) => {
      const row = node("article", "audit-row");
      const copy = node("div", "audit-copy");
      copy.append(
        node("strong", "", item.event_type),
        node("small", "", `${item.actor_type}:${shortId(item.actor_id)} → ${item.target_type}:${shortId(item.target_id)} · ${formatDate(item.occurred_at)}`),
      );
      row.append(node("span", "audit-sequence", `#${item.sequence_no}`), copy, node("code", "audit-hash", item.event_hash));
      list.append(row);
    });
    $("#audit-more").hidden = !state.cursors.audit;
    $("#audit-export-open").disabled = !mutationReady("platform.audit.export");
  }

  async function loadAudit(append) {
    const tenantId = $("#audit-tenant-id").value.trim();
    const after = append ? state.cursors.audit : Number($("#audit-after").value || 0);
    const params = new URLSearchParams({ after_sequence: String(after || 0), limit: "100" });
    if (tenantId) params.set("tenant_id", tenantId);
    const payload = await api(`/v2/platform-admin/audit-events?${params}`);
    state.audit = append ? state.audit.concat(payload.items) : payload.items;
    state.cursors.audit = payload.next_sequence;
    renderAudit();
  }

  async function requestAuditExport() {
    const defaultFrom = state.audit[0]?.sequence_no || 1;
    const defaultTo = state.audit[state.audit.length - 1]?.sequence_no || defaultFrom;
    const values = await openAction({
      title: "Request Signed Audit Export",
      summary: "A different Staff principal must approve this operation.",
      risk: "HIGH",
      confirm: "REQUEST EXPORT",
      fields: [
        { name: "tenant_id", label: "TENANT ID / OPTIONAL", value: $("#audit-tenant-id").value.trim() },
        { name: "from_sequence", label: "FROM SEQUENCE", type: "number", value: defaultFrom, required: true, min: 1 },
        { name: "to_sequence", label: "TO SEQUENCE", type: "number", value: defaultTo, required: true, min: 1 },
        { name: "reason", label: "EXPORT REASON", type: "textarea", required: true },
      ],
    });
    if (!values) return;
    const payload = await api("/v2/platform-admin/audit-exports", {
      method: "POST",
      headers: { "Idempotency-Key": idempotency("pc4-audit-export") },
      body: {
        tenant_id: values.tenant_id || null,
        from_sequence: Number(values.from_sequence),
        to_sequence: Number(values.to_sequence),
        reason: values.reason,
      },
    });
    await refreshOperations();
    openOperations();
    toast(`Audit Export awaiting second Staff · ${shortId(payload.operation_id)}`, "success");
  }

  function renderOperations() {
    const list = $("#operations-list");
    list.replaceChildren();
    if (!state.operations.length) list.append(emptyRecord("NO VISIBLE ADMIN OPERATIONS"));
    state.operations.forEach((item) => {
      const actions = [];
      if (item.action === "audit_export" && item.status === "pending_staff_approval") {
        actions.push(actionButton("APPROVE EXPORT", () => approveOperation(item), {
          disabled: !mutationReady("platform.operation.approve") || item.requested_by_principal_id === state.context.principal_id,
          testId: `operation-approve-${item.operation_id}`,
        }));
      }
      list.append(recordRow({
        title: item.action.replaceAll("_", " ").toUpperCase(),
        identifier: item.operation_id,
        status: item.status,
        meta: [`${item.risk_level} · ${item.target_type}:${shortId(item.target_id)}`, formatDate(item.updated_at)],
        actions,
      }));
    });
    $("#operations-more").hidden = !state.cursors.operations;
    renderOverview();
  }

  async function loadOperations(append) {
    const cursor = append ? state.cursors.operations : null;
    const query = cursor ? `?limit=50&cursor=${encodeURIComponent(cursor)}` : "?limit=50";
    const payload = await api(`/v2/platform-admin/operations${query}`);
    state.operations = append ? state.operations.concat(payload.items) : payload.items;
    state.cursors.operations = payload.next_cursor;
    renderOperations();
  }

  async function refreshOperations() {
    if (!can("platform.operations.read")) return;
    await loadOperations(false);
  }

  async function approveOperation(item) {
    const values = await openAction({
      title: "Approve Signed Audit Export",
      summary: `${item.operation_id} · requested by ${shortId(item.requested_by_principal_id)} · V${item.version}`,
      risk: "CRITICAL",
      confirm: "SIGN EXPORT",
      fields: [{ name: "reason", label: "APPROVAL REASON", type: "textarea", required: true }],
    });
    if (!values) return;
    const payload = await api(`/v2/platform-admin/operations/${item.operation_id}/approve`, {
      method: "POST",
      body: { expected_version: item.version, reason: values.reason },
    });
    item.status = "succeeded";
    item.version += 1;
    renderOperations();
    toast(`Signed Export ${shortId(payload.export_id)} ready · key ${payload.signing_key_id}`, "success");
  }

  function openOperations() {
    if (!can("platform.operations.read")) {
      toast("platform_permission_denied: operations.read required", "error");
      return;
    }
    const drawer = $("#operations-drawer");
    if (!drawer.open) drawer.showModal();
    $("#operations-close").focus();
    void run(() => refreshOperations());
  }

  function closeOperations() {
    const drawer = $("#operations-drawer");
    if (drawer.open) drawer.close();
  }

  function trapOperationsFocus(event) {
    if (event.key !== "Tab") return;
    const drawer = $("#operations-drawer");
    const focusable = [...drawer.querySelectorAll("button:not([disabled]):not([hidden])")]
      .filter((item) => item.getClientRects().length > 0);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!drawer.contains(document.activeElement)) {
      event.preventDefault();
      first.focus();
    } else if (focusable.length === 1) {
      event.preventDefault();
      first.focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function openAction({ title, summary, risk, confirm, fields }) {
    const dialog = $("#action-dialog");
    if (state.dialogResolver) state.dialogResolver(null);
    $("#dialog-title").textContent = title;
    $("#dialog-summary").textContent = summary;
    $("#dialog-risk").textContent = risk;
    $("#dialog-confirm").textContent = confirm;
    const root = $("#dialog-fields");
    root.replaceChildren();
    fields.forEach((field) => {
      const label = node("label");
      label.append(node("span", "", field.label));
      const input = document.createElement(field.type === "textarea" ? "textarea" : "input");
      input.name = field.name;
      if (field.type && field.type !== "textarea") input.type = field.type;
      input.value = field.value ?? "";
      input.required = Boolean(field.required);
      if (field.min !== undefined) input.min = String(field.min);
      if (field.maxLength) input.maxLength = field.maxLength;
      label.append(input);
      root.append(label);
    });
    dialog.showModal();
    const first = root.querySelector("input, textarea");
    if (first) first.focus();
    return new Promise((resolve) => {
      state.dialogResolver = resolve;
    });
  }

  function settleDialog(value) {
    const resolver = state.dialogResolver;
    state.dialogResolver = null;
    if ($("#action-dialog").open) $("#action-dialog").close();
    if (resolver) resolver(value);
  }

  async function bootstrap() {
    const context = await api("/v2/platform-admin/context");
    state.context = context;
    state.permissions = new Set(context.permissions || []);
    renderIdentity();
    configureNavigation();

    const tasks = [];
    if (can("platform.permission.read")) tasks.push(api("/v2/platform-admin/permissions").then((value) => { state.catalog = value.permissions; }));
    if (can("platform.tenant.read")) tasks.push(loadTenants(false));
    if (can("platform.user.read")) tasks.push(loadUsers(false));
    if (can("platform.identity_conflict.read")) tasks.push(api("/v2/platform-admin/identity-conflicts?status=pending&limit=50").then((value) => { state.conflicts = value.items; }));
    if (can("platform.support.read")) tasks.push(loadSupport(false));
    if (can("platform.operations.read")) tasks.push(loadOperations(false));
    const results = await Promise.allSettled(tasks);
    const failures = results.filter((result) => result.status === "rejected");
    if (failures.length) {
      toast(`${failures.length} authorized module(s) failed to load; retry before action`, "error");
    }
    renderOverview();
    $("#console-shell").setAttribute("aria-busy", "false");
    state.loaded.add("overview");

    const initial = window.location.hash.slice(1);
    if (initial && document.querySelector(`[data-view="${initial}"]`)) showView(initial);
  }

  document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
  document.querySelectorAll("[data-view-link]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.viewLink)));
  $("#notification-operations-link").addEventListener("click", () => {
    if (!can("platform.notification.read")) {
      toast("platform_permission_denied: notification operations are not assigned", "error");
      return;
    }
    window.location.assign("/platform-notification-ops");
  });
  $("#users-filter-form").addEventListener("submit", (event) => { event.preventDefault(); renderUsers(); });
  $("#tenants-filter-form").addEventListener("submit", (event) => { event.preventDefault(); renderTenants(); });
  $("#users-more").addEventListener("click", () => void run(() => loadUsers(true)));
  $("#tenants-more").addEventListener("click", () => void run(() => loadTenants(true)));
  $("#conflicts-refresh").addEventListener("click", () => void run(loadAccess));
  $("#support-refresh").addEventListener("click", () => void run(() => loadSupport(false)));
  $("#support-more").addEventListener("click", () => void run(() => loadSupport(true)));
  $("#support-request-form").addEventListener("submit", (event) => void run(() => requestSupport(event)));
  $("#audit-filter-form").addEventListener("submit", (event) => { event.preventDefault(); void run(() => loadAudit(false)); });
  $("#audit-more").addEventListener("click", () => void run(() => loadAudit(true)));
  $("#audit-export-open").addEventListener("click", () => void run(requestAuditExport));
  $("#operations-toggle").addEventListener("click", openOperations);
  $("#operations-close").addEventListener("click", closeOperations);
  $("#operations-drawer").addEventListener("keydown", trapOperationsFocus);
  $("#operations-drawer").addEventListener("close", () => $("#operations-toggle").focus());
  $("#operations-more").addEventListener("click", () => void run(() => loadOperations(true)));
  $("#dialog-cancel").addEventListener("click", () => settleDialog(null));
  $("#action-dialog").addEventListener("cancel", (event) => { event.preventDefault(); settleDialog(null); });
  $("#action-dialog-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (!event.currentTarget.reportValidity()) return;
    settleDialog(Object.fromEntries(new FormData(event.currentTarget).entries()));
  });
  $("#token-dismiss").addEventListener("click", () => {
    $("#support-one-time-token").textContent = "";
    $("#token-dialog").close();
  });
  $("#token-dialog").addEventListener("close", () => {
    $("#support-one-time-token").textContent = "";
  });
  $("#support-mode").addEventListener("change", () => {
    const breakGlass = $("#support-mode").value === "break_glass";
    $("#support-incident-ref").required = breakGlass;
    const ttlMinutes = breakGlass ? 15 : 60;
    $("#support-expires-at").value = localDateTime(Date.now() + ttlMinutes * 60_000);
  });
  $("#logout-button").addEventListener("click", () => void run(async () => {
    await api("/v2/platform-admin/session/logout", { method: "POST" });
    sessionStorage.removeItem("omnigent.platform.csrf");
    window.location.reload();
  }));

  $("#support-expires-at").value = localDateTime(Date.now() + 60 * 60_000);
  window.setInterval(() => { $("#utc-clock").textContent = new Date().toISOString().slice(11, 19); }, 1000);
  $("#utc-clock").textContent = new Date().toISOString().slice(11, 19);
  void run(bootstrap);
})();
