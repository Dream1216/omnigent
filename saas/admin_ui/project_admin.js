(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const state = {
    csrf: sessionStorage.getItem("omnigent.saas.csrf") || "",
    actorId: "",
    tenantId: "",
    spaceId: "",
    contextSnapshot: "",
    scopes: [],
    projects: [],
    selectedProject: null,
    members: [],
    selectedMember: null,
    memberMutationPending: false,
    invitations: [],
    groups: [],
    roles: [],
    approvalInbox: [],
    myPreflights: [],
    billing: null,
    billingUsage: [],
    billingLedger: [],
    billingReconciliations: [],
    tenantRole: "",
    groupLoadRevision: 0,
    roleLoadRevision: 0,
    approvalLoadRevision: 0,
    memberLoadRevision: 0,
    invitationLoadRevision: 0,
    billingLoadRevision: 0,
    view: "projects",
  };

  const loginDeck = $("#login-deck");
  const workspace = $("#workspace");
  const eventLog = $("#event-log");
  const actionDialog = $("#action-dialog");
  let dialogResolver = null;

  function timestamp() {
    return new Date().toISOString().slice(11, 19);
  }

  function log(message, tone = "info") {
    const entry = document.createElement("li");
    entry.dataset.tone = tone;
    const time = document.createElement("time");
    time.textContent = timestamp();
    const text = document.createElement("span");
    text.textContent = message;
    entry.append(time, text);
    eventLog.prepend(entry);
    while (eventLog.children.length > 8) eventLog.lastElementChild.remove();
  }

  function requestError(payload, status) {
    const detail = payload?.detail || payload?.error || payload;
    const code = detail?.code || `http_${status}`;
    const message = detail?.message || "Request failed";
    return new Error(`${code}: ${message}`);
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    if (state.csrf && options.method && options.method !== "GET") headers.set("X-CSRF-Token", state.csrf);
    const response = await fetch(`/saas${path}`, { credentials: "same-origin", ...options, headers });
    const payload = response.status === 204 ? null : await response.json().catch(() => ({}));
    if (!response.ok) throw requestError(payload, response.status);
    return payload;
  }

  function idempotency(prefix) {
    return `${prefix}-${crypto.randomUUID()}`;
  }

  function setAuthenticated(userId) {
    state.actorId = userId;
    loginDeck.hidden = true;
    workspace.hidden = false;
    $("#logout-button").hidden = false;
    $("#actor-id").textContent = userId;
    $("#csrf-state").textContent = state.csrf ? "BOUND" : "REAUTH REQUIRED";
    log(`Actor ${userId.slice(0, 8)} authenticated`, "success");
  }

  function setLoggedOut() {
    state.groupLoadRevision += 1;
    state.roleLoadRevision += 1;
    state.approvalLoadRevision += 1;
    state.memberLoadRevision += 1;
    state.invitationLoadRevision += 1;
    state.billingLoadRevision += 1;
    state.actorId = "";
    state.csrf = "";
    state.contextSnapshot = "";
    state.scopes = [];
    state.tenantId = "";
    state.spaceId = "";
    state.projects = [];
    state.selectedProject = null;
    state.members = [];
    state.selectedMember = null;
    state.memberMutationPending = false;
    state.invitations = [];
    state.groups = [];
    state.roles = [];
    state.approvalInbox = [];
    state.myPreflights = [];
    state.billing = null;
    state.billingUsage = [];
    state.billingLedger = [];
    state.billingReconciliations = [];
    state.tenantRole = "";
    sessionStorage.removeItem("omnigent.saas.csrf");
    loginDeck.hidden = false;
    workspace.hidden = true;
    $("#logout-button").hidden = true;
    document.querySelector(".system-state").classList.remove("connected");
    $("#context-state").textContent = "NO CONTEXT";
    $("#snapshot-state").textContent = "UNBOUND";
    $("#scope-connect").disabled = true;
    hideOneTimeToken();
    showView("projects", { load: false });
  }

  function tenantPath(suffix = "") {
    if (!state.tenantId) throw new Error("scope_not_connected: connect a Tenant first");
    return `/tenants/${state.tenantId}${suffix}`;
  }

  function scopePath(suffix = "") {
    if (!state.tenantId || !state.spaceId) throw new Error("scope_not_connected: connect Tenant and Space first");
    return `/tenants/${state.tenantId}/spaces/${state.spaceId}${suffix}`;
  }

  function renderProjects() {
    const list = $("#project-list");
    list.replaceChildren();
    $("#project-count").textContent = String(state.projects.length).padStart(2, "0");
    $("#project-empty").hidden = state.projects.length > 0;
    state.projects.forEach((project, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `project-row${state.selectedProject?.project_id === project.project_id ? " selected" : ""}`;
      button.dataset.projectId = project.project_id;
      button.dataset.testid = `project-${project.project_id}`;
      const rowIndex = document.createElement("span");
      rowIndex.className = "row-index";
      rowIndex.textContent = String(index + 1).padStart(2, "0");
      const title = document.createElement("span");
      title.className = "row-title";
      const strong = document.createElement("strong");
      strong.textContent = project.name;
      const key = document.createElement("small");
      key.textContent = project.project_id;
      title.append(strong, key);
      const visibility = document.createElement("span");
      visibility.className = "row-visibility";
      visibility.textContent = project.visibility.toUpperCase();
      button.append(rowIndex, title, visibility);
      button.addEventListener("click", () => selectProject(project));
      list.append(button);
    });
  }

  function selectProject(project) {
    state.selectedProject = project;
    $("#selected-project-name").textContent = project.name;
    $("#selected-project-id").textContent = project.project_id;
    $("#project-version").textContent = `V${project.authorization_version}`;
    renderProjects();
    log(`Selected Project ${project.name}`);
    if (state.view === "approvals") void loadApprovalWorkspace();
  }

  async function loadCatalog() {
    const catalog = await api("/admin/permissions");
    $("#permission-count").textContent = `${catalog.permissions.length} / ${catalog.policy_version}`;
  }

  async function loadScopes() {
    const connect = $("#scope-connect");
    connect.disabled = true;
    state.scopes = await api("/context/scopes");
    const selector = $("#scope-select");
    selector.replaceChildren();
    if (!state.scopes.length) {
      const empty = document.createElement("option");
      empty.value = "";
      empty.textContent = "没有可用的 Tenant / Space";
      selector.append(empty);
      return;
    }
    state.scopes.forEach((scope, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = `${scope.tenant_name} / ${scope.space_name} · ${scope.tenant_role}:${scope.space_role}`;
      selector.append(option);
    });
    connect.disabled = false;
    log(`Resolved ${state.scopes.length} authorized scope(s)`, "success");
  }

  async function loadProjects() {
    state.projects = await api(scopePath("/projects"));
    if (state.selectedProject) {
      state.selectedProject = state.projects.find((item) => item.project_id === state.selectedProject.project_id) || null;
    }
    renderProjects();
    log(`Loaded ${state.projects.length} visible Project(s)`, "success");
  }

  function shortId(value) {
    return value ? value.slice(0, 8) : "—";
  }

  function formatDate(value) {
    return value ? new Date(value).toLocaleString() : "—";
  }

  function localDateTime(value) {
    const date = new Date(value);
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 16);
  }

  function inputIso(selector) {
    const value = $(selector).value;
    const date = new Date(value);
    if (!value || Number.isNaN(date.getTime())) throw new Error("billing_time_invalid: provide a valid time");
    return date.toISOString();
  }

  function setBillingDefaults() {
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    const queryStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const queryEnd = new Date(now.getTime() + 60 * 60 * 1000);
    const defaults = {
      "#billing-period-start": monthStart,
      "#billing-period-end": monthEnd,
      "#billing-pricing-effective": now,
      "#billing-pricing-until": monthEnd,
      "#billing-entitlement-start": monthStart,
      "#billing-entitlement-end": monthEnd,
      "#billing-query-start": queryStart,
      "#billing-query-end": queryEnd,
    };
    Object.entries(defaults).forEach(([selector, value]) => {
      if (!$(selector).value) $(selector).value = localDateTime(value);
    });
  }

  function billingCanManage() {
    return state.tenantRole === "owner" || state.tenantRole === "billing_admin";
  }

  function billingEmpty(message) {
    const empty = document.createElement("div");
    empty.className = "billing-empty";
    empty.textContent = message;
    return empty;
  }

  function billingRecord({ title, detail, badge, status = "" }) {
    const row = document.createElement("article");
    row.className = "billing-record";
    if (status) row.dataset.status = status;
    const copy = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = title;
    const metadata = document.createElement("p");
    metadata.textContent = detail;
    const chip = document.createElement("span");
    chip.textContent = badge;
    copy.append(heading, metadata);
    row.append(copy, chip);
    return row;
  }

  function renderBillingOverview() {
    const overview = state.billing || {};
    const subscription = overview.subscription;
    const balance = overview.balance;
    const latest = overview.latest_reconciliation;
    const stateCard = $("#billing-state");
    stateCard.dataset.status = subscription?.status || "unconfigured";
    stateCard.querySelector("strong").textContent = subscription?.status?.toUpperCase() || "UNCONFIGURED";
    $("#billing-nav-status").textContent = subscription?.status?.toUpperCase() || "—";
    $("#billing-available").textContent = balance ? String(balance.available_minor) : "—";
    $("#billing-reserved").textContent = balance ? String(balance.reserved_minor) : "—";
    $("#billing-consumed").textContent = balance ? String(balance.consumed_minor) : "—";
    $("#billing-currency").textContent = balance ? `${balance.currency} / MINOR UNITS` : "MINOR UNITS";
    $("#billing-reconciliation-state").textContent = latest?.status?.toUpperCase() || "NONE";
    $("#billing-reconciliation-count").textContent = `${latest?.mismatch_count || 0} EXCEPTIONS`;

    if (subscription) {
      $("#billing-plan-key").value = subscription.plan_key;
      $("#billing-pricing-plan").value = subscription.plan_key;
      $("#billing-subscription-status").value = subscription.status;
      $("#billing-period-start").value = localDateTime(subscription.current_period_start);
      $("#billing-period-end").value = localDateTime(subscription.current_period_end);
      $("#billing-provider").value = subscription.provider || "";
      $("#billing-customer-ref").value = subscription.provider_customer_ref || "";
      $("#billing-subscription-ref").value = subscription.provider_subscription_ref || "";
    }
    document.querySelectorAll("#billing-board form button[type='submit']").forEach((button) => {
      button.disabled = !billingCanManage();
      button.title = billingCanManage() ? "" : "当前 Tenant Role 仅允许 billing.read";
    });

    const entitlementList = $("#billing-entitlement-list");
    entitlementList.replaceChildren();
    const entitlements = overview.entitlements || [];
    if (!entitlements.length) entitlementList.append(billingEmpty("NO ENTITLEMENT FACTS IN THIS TENANT"));
    entitlements.forEach((value) => {
      entitlementList.append(
        billingRecord({
          title: `${value.scope_type} / ${value.meter}`,
          detail: `${value.scope_key} · ${value.consumed_quantity} consumed + ${value.reserved_quantity} reserved / ${value.limit_quantity || "unlimited"} ${value.unit} · V${value.version}`,
          badge: value.status.toUpperCase(),
          status: value.status,
        })
      );
    });
  }

  function renderBillingEvidence() {
    const usageList = $("#billing-usage-list");
    usageList.replaceChildren();
    if (!state.billingUsage.length) usageList.append(billingEmpty("NO USAGE FACTS IN SELECTED PERIOD"));
    state.billingUsage.forEach((value) => {
      usageList.append(
        billingRecord({
          title: value.meter,
          detail: `${value.quantity} ${value.unit} · ${value.provider}/${value.provider_request_id} · ${formatDate(value.occurred_at)}`,
          badge: `${value.currency} ${value.customer_charge_minor}`,
        })
      );
    });

    const ledgerList = $("#billing-ledger-list");
    ledgerList.replaceChildren();
    if (!state.billingLedger.length) ledgerList.append(billingEmpty("NO CUSTOMER LEDGER MOVEMENTS IN SELECTED PERIOD"));
    state.billingLedger.forEach((value) => {
      ledgerList.append(
        billingRecord({
          title: value.operation_type,
          detail: `AVAILABLE ${value.delta_available_minor} · RESERVED ${value.delta_reserved_minor} · CONSUMED ${value.delta_consumed_minor} · ${formatDate(value.occurred_at)}`,
          badge: `${value.currency} ${value.amount_minor}`,
        })
      );
    });
  }

  function renderBillingReconciliations() {
    const list = $("#billing-reconciliation-list");
    list.replaceChildren();
    if (!state.billingReconciliations.length) list.append(billingEmpty("NO RECONCILIATION BATCHES"));
    state.billingReconciliations.forEach((value) => {
      const row = billingRecord({
        title: `${value.status} / ${shortId(value.batch_id)}`,
        detail: `${formatDate(value.period_start)} → ${formatDate(value.period_end)} · usage ${value.usage_event_count} · customer ${value.customer_settled_minor} · provider ${value.provider_cost_minor} · ${value.evidence_sha256}`,
        badge: `${value.mismatch_count} EXCEPTIONS`,
        status: value.status,
      });
      if (value.mismatch_count) {
        const inspect = document.createElement("button");
        inspect.type = "button";
        inspect.textContent = "INSPECT RECONCILIATION EXCEPTIONS";
        inspect.addEventListener("click", () => void loadBillingMismatches(value, row));
        row.append(inspect);
      }
      list.append(row);
    });
  }

  async function loadBillingMismatches(batch, row) {
    try {
      const result = await api(tenantPath(`/billing/reconciliations/${batch.batch_id}/mismatches?limit=100`));
      row.querySelectorAll(".billing-mismatch").forEach((value) => value.remove());
      result.items.forEach((value) => {
        const mismatch = billingRecord({
          title: value.mismatch_type,
          detail: `EXPECTED ${value.expected_minor ?? "—"} / ACTUAL ${value.actual_minor ?? "—"} ${value.currency} · ${value.resolution || "unresolved"}`,
          badge: value.status.toUpperCase(),
          status: value.status,
        });
        mismatch.classList.add("billing-mismatch");
        if (value.status === "open" && billingCanManage()) {
          const resolve = document.createElement("button");
          resolve.type = "button";
          resolve.textContent = "RESOLVE WITH AUDIT REASON";
          resolve.addEventListener("click", () => void resolveBillingMismatch(value));
          mismatch.append(resolve);
        }
        row.append(mismatch);
      });
    } catch (error) {
      log(error.message, "error");
    }
  }

  async function resolveBillingMismatch(value) {
    const reason = await openActionDialog({
      title: "解决对账异常",
      operation: "BILLING RECONCILIATION / RESOLVE",
      target: value.mismatch_type,
      version: 1,
      summary: { expected_minor: value.expected_minor, actual_minor: value.actual_minor, currency: value.currency },
      confirm: "RESOLVE EXCEPTION",
      warning: "异常事实不可修改；此操作只追加解决主体、时间与审计原因。",
    });
    if (!reason) return;
    try {
      await api(tenantPath(`/billing/reconciliation-mismatches/${value.id}/resolve`), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-billing-mismatch-resolve") },
        body: JSON.stringify({ resolution: reason }),
      });
      log(`Billing mismatch ${shortId(value.id)} resolved`, "success");
      await loadBillingWorkspace();
    } catch (error) {
      log(error.message, "error");
    }
  }

  async function loadBillingWorkspace() {
    if (!state.contextSnapshot) return;
    setBillingDefaults();
    const revision = ++state.billingLoadRevision;
    const tenantId = state.tenantId;
    try {
      const parameters = new URLSearchParams({
        period_start: inputIso("#billing-query-start"),
        period_end: inputIso("#billing-query-end"),
        limit: "100",
      });
      const [overview, reconciliations, usage, ledger] = await Promise.all([
        api(tenantPath("/billing")),
        api(tenantPath("/billing/reconciliations?limit=50")),
        api(tenantPath(`/billing/usage-events?${parameters}`)),
        api(tenantPath(`/billing/ledger?${parameters}`)),
      ]);
      if (revision !== state.billingLoadRevision || tenantId !== state.tenantId) return;
      state.billing = overview;
      state.billingReconciliations = reconciliations.items;
      state.billingUsage = usage.items;
      state.billingLedger = ledger.items;
      renderBillingOverview();
      renderBillingReconciliations();
      renderBillingEvidence();
      log(`Loaded Tenant Billing authority for ${shortId(state.tenantId)}`, "success");
    } catch (error) {
      if (revision !== state.billingLoadRevision || tenantId !== state.tenantId) return;
      state.billing = null;
      state.billingReconciliations = [];
      state.billingUsage = [];
      state.billingLedger = [];
      renderBillingOverview();
      renderBillingReconciliations();
      renderBillingEvidence();
      log(error.message, "error");
    }
  }

  function memberLabel(member) {
    return member.display_name || member.primary_email_normalized || shortId(member.user_id);
  }

  function hideOneTimeToken() {
    $("#invite-one-time-token").textContent = "";
    $("#invite-token-card").hidden = true;
  }

  function showOneTimeToken(token) {
    if (!token) {
      hideOneTimeToken();
      log("Idempotent replay completed; bearer token is never replayed", "warning");
      return;
    }
    $("#invite-one-time-token").textContent = token;
    $("#invite-token-card").hidden = false;
  }

  function renderMembers(message = "当前 Tenant 没有可见成员。") {
    const list = $("#tenant-member-list");
    list.replaceChildren();
    const count = String(state.members.length).padStart(2, "0");
    $("#member-count").textContent = count;
    $("#member-nav-count").textContent = count;
    if (!state.members.length) {
      list.append(governanceEmpty(message));
      renderMemberDetail();
      return;
    }
    state.members.forEach((member) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = `member-row${state.selectedMember?.user_id === member.user_id ? " selected" : ""}`;
      row.dataset.testid = `tenant-member-${member.user_id}`;
      const identity = document.createElement("span");
      const name = document.createElement("strong");
      name.textContent = memberLabel(member);
      const detail = document.createElement("small");
      detail.textContent = `${member.primary_email_normalized || "NO EMAIL"} · ${member.user_id}`;
      identity.append(name, detail);
      const meta = document.createElement("span");
      meta.className = "member-row-meta";
      const role = document.createElement("span");
      role.textContent = member.tenant_role.toUpperCase();
      const status = document.createElement("span");
      status.textContent = member.tenant_status.toUpperCase();
      meta.append(role, status);
      row.append(identity, meta);
      row.addEventListener("click", () => selectMember(member));
      list.append(row);
    });
  }

  function selectMember(member) {
    state.selectedMember = member;
    renderMembers();
    renderMemberDetail();
    log(`Selected Tenant member ${memberLabel(member)}`);
  }

  function renderMemberDetail() {
    const member = state.selectedMember;
    $("#member-detail-empty").hidden = Boolean(member);
    $("#member-detail-content").hidden = !member;
    if (!member) return;
    const status = $("#member-detail-status");
    status.textContent = `${member.tenant_status.toUpperCase()} · V${member.tenant_membership_version}`;
    status.dataset.status = member.tenant_status;
    $("#member-detail-name").textContent = memberLabel(member);
    $("#member-detail-email").textContent = member.primary_email_normalized || "NO VERIFIED EMAIL";
    $("#member-detail-id").textContent = member.user_id;
    $("#tenant-member-role").value = member.tenant_role === "owner" ? "member" : member.tenant_role;
    $("#tenant-member-role").disabled = state.memberMutationPending || member.tenant_role === "owner";
    $("#tenant-role-form").querySelector("button").disabled =
      state.memberMutationPending || member.tenant_role === "owner";

    const loginMethods = $("#member-login-methods");
    loginMethods.replaceChildren();
    member.login_methods.forEach((method) => {
      const chip = document.createElement("span");
      chip.className = "login-method-chip";
      chip.dataset.verified = String(method.email_verified);
      chip.textContent = `${method.provider.toUpperCase()} / ${method.status.toUpperCase()} / ${method.email_verified ? "VERIFIED" : "UNVERIFIED"}`;
      loginMethods.append(chip);
    });
    if (!member.login_methods.length) loginMethods.append(governanceEmpty("没有可公开的登录方式姿态。"));

    const statusToggle = $("#tenant-member-status-toggle");
    statusToggle.textContent = member.tenant_status === "active" ? "SUSPEND TENANT ACCESS" : "RESUME TENANT ACCESS";
    statusToggle.disabled =
      state.memberMutationPending || member.tenant_role === "owner" || member.tenant_status === "removed";
    $("#tenant-owner-transfer").disabled =
      state.memberMutationPending ||
      member.user_id === state.actorId ||
      member.tenant_status !== "active" ||
      member.tenant_role === "owner";
    $("#tenant-member-remove").disabled =
      state.memberMutationPending || member.user_id === state.actorId || member.tenant_role === "owner";

    const spaceList = $("#member-space-access");
    spaceList.replaceChildren();
    $("#member-space-label").textContent = `${member.space_access.length} SPACE(S)`;
    if (!member.space_access.length) {
      spaceList.append(governanceEmpty("该成员当前没有 Space Membership。"));
      return;
    }
    member.space_access.forEach((access) => {
      const card = document.createElement("article");
      card.className = "space-access-card";
      card.dataset.testid = `member-space-${access.space_id}`;
      const heading = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = access.space_name;
      const version = document.createElement("small");
      version.textContent = `${access.status.toUpperCase()} · V${access.version}`;
      heading.append(name, version);
      const actions = document.createElement("div");
      actions.className = "space-access-actions";
      const role = document.createElement("select");
      role.dataset.testid = `member-space-role-${access.space_id}`;
      ["admin", "operator", "member", "viewer"].forEach((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value.toUpperCase();
        option.selected = value === access.role;
        role.append(option);
      });
      role.disabled = state.memberMutationPending || access.role === "owner";
      const save = document.createElement("button");
      save.type = "button";
      save.textContent = "SET ROLE";
      save.disabled = state.memberMutationPending || access.role === "owner";
      save.addEventListener("click", () => void updateSpaceRole(member, access, role.value));
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.textContent = access.status === "active" ? "SUSPEND" : "RESUME";
      toggle.disabled =
        state.memberMutationPending || access.role === "owner" || access.status === "removed";
      toggle.addEventListener("click", () => void mutateSpaceStatus(member, access));
      actions.append(role, save, toggle);
      card.append(heading, actions);
      spaceList.append(card);
    });
  }

  async function loadMembers() {
    const revision = ++state.memberLoadRevision;
    const actorId = state.actorId;
    const tenantId = state.tenantId;
    const selectedId = state.selectedMember?.user_id || "";
    const query = $("#tenant-member-search").value.trim();
    const status = $("#tenant-member-status").value;
    const parameters = new URLSearchParams({ limit: "100" });
    if (query) parameters.set("query", query);
    if (status) parameters.set("status", status);
    try {
      const result = await api(tenantPath(`/members?${parameters}`));
      if (revision !== state.memberLoadRevision || actorId !== state.actorId || tenantId !== state.tenantId) return;
      state.members = result.items;
      state.selectedMember = state.members.find((value) => value.user_id === selectedId) || null;
      renderMembers();
      renderMemberDetail();
      log(`Loaded ${state.members.length} Tenant member(s)`, "success");
    } catch (error) {
      if (revision !== state.memberLoadRevision || actorId !== state.actorId || tenantId !== state.tenantId) return;
      state.members = [];
      state.selectedMember = null;
      renderMembers("当前角色无 Tenant 成员目录读取权限。");
      log(error.message, "warning");
    }
  }

  function renderInvitations(message = "当前 Tenant 没有邀请记录。") {
    const list = $("#invitation-list");
    list.replaceChildren();
    if (!state.invitations.length) return list.append(governanceEmpty(message));
    state.invitations.forEach((invitation) => {
      const card = document.createElement("article");
      card.className = "invitation-card";
      card.dataset.testid = `invitation-${invitation.invitation_id}`;
      const heading = document.createElement("div");
      const email = document.createElement("strong");
      email.textContent = invitation.email_normalized;
      const status = document.createElement("span");
      status.className = "status-chip";
      status.textContent = invitation.status.toUpperCase();
      heading.append(email, status);
      const meta = document.createElement("p");
      meta.textContent = `${invitation.tenant_role.toUpperCase()}${invitation.space_name ? ` · ${invitation.space_name} / ${invitation.space_role.toUpperCase()}` : " · TENANT ONLY"} · V${invitation.version} · EXPIRES ${formatDate(invitation.expires_at)}`;
      card.append(heading, meta);
      if (["pending", "expired"].includes(invitation.status)) {
        const actions = document.createElement("div");
        actions.className = "invitation-actions";
        const reissue = document.createElement("button");
        reissue.type = "button";
        reissue.textContent = "ROTATE + REISSUE";
        reissue.addEventListener("click", () => void reissueInvitation(invitation));
        const revoke = document.createElement("button");
        revoke.type = "button";
        revoke.className = "danger-button";
        revoke.textContent = "REVOKE";
        revoke.addEventListener("click", () => void revokeInvitation(invitation));
        actions.append(reissue, revoke);
        card.append(actions);
      }
      list.append(card);
    });
  }

  async function loadInvitations() {
    const revision = ++state.invitationLoadRevision;
    const actorId = state.actorId;
    const tenantId = state.tenantId;
    try {
      const result = await api(tenantPath("/membership-invitations?limit=100"));
      if (revision !== state.invitationLoadRevision || actorId !== state.actorId || tenantId !== state.tenantId) return;
      state.invitations = result.items;
      renderInvitations();
    } catch (error) {
      if (revision !== state.invitationLoadRevision || actorId !== state.actorId || tenantId !== state.tenantId) return;
      state.invitations = [];
      renderInvitations("当前角色无邀请台账读取权限。");
      log(error.message, "warning");
    }
  }

  async function loadMemberWorkspace() {
    if (!state.contextSnapshot) return;
    await Promise.all([loadMembers(), loadInvitations()]);
  }

  function operationLabel(value) {
    return value === "group_archive" ? "GROUP ARCHIVE" : "CUSTOM ROLE RETIRE";
  }

  function effectiveStatus(value) {
    if (value.status === "pending_approval" && new Date(value.expires_at).getTime() <= Date.now()) return "expired";
    return value.status;
  }

  function impactEntries(summary = {}) {
    return Object.entries(summary).filter(([key, value]) => {
      if (key === "target_name" || key.endsWith("_ids")) return false;
      return ["string", "number", "boolean"].includes(typeof value);
    });
  }

  function appendImpactFacts(container, summary = {}) {
    const facts = document.createElement("dl");
    facts.className = "impact-grid";
    impactEntries(summary).slice(0, 6).forEach(([key, value]) => {
      const fact = document.createElement("div");
      fact.className = "impact-fact";
      const term = document.createElement("dt");
      term.textContent = key.replaceAll("_", " ");
      const description = document.createElement("dd");
      description.textContent = String(value);
      fact.append(term, description);
      facts.append(fact);
    });
    container.append(facts);
  }

  function governanceEmpty(message) {
    const empty = document.createElement("div");
    empty.className = "approval-empty";
    empty.textContent = message;
    return empty;
  }

  function renderGroups(message = "尚无 Tenant Group。") {
    const list = $("#group-list");
    list.replaceChildren();
    if (!state.groups.length) return list.append(governanceEmpty(message));
    state.groups.forEach((group) => {
      const row = document.createElement("div");
      row.className = "governance-row";
      row.dataset.testid = `group-row-${group.id}`;
      const identity = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = group.name;
      const meta = document.createElement("small");
      meta.textContent = `${group.status.toUpperCase()} · V${group.version} · ${group.id}`;
      identity.append(name, meta);
      const prepare = document.createElement("button");
      prepare.type = "button";
      prepare.textContent = group.status === "active" ? "PREPARE ARCHIVE" : group.status.toUpperCase();
      prepare.disabled = group.status !== "active";
      prepare.addEventListener("click", () => void preparePreflight("group_archive", group));
      row.append(identity, prepare);
      list.append(row);
    });
  }

  function renderRoles(message = "选择 Project 后读取 Custom Roles。") {
    const list = $("#role-list");
    list.replaceChildren();
    const disabled = !state.selectedProject;
    $("#role-name").disabled = disabled;
    $("#role-permissions").disabled = disabled;
    $("#role-create-form").querySelector("button").disabled = disabled;
    $("#role-project-label").textContent = state.selectedProject
      ? `${state.selectedProject.name} / ${shortId(state.selectedProject.project_id)}`
      : "SELECT PROJECT";
    if (!state.roles.length) return list.append(governanceEmpty(message));
    state.roles.forEach((role) => {
      const row = document.createElement("div");
      row.className = "governance-row";
      row.dataset.testid = `role-row-${role.id}`;
      const identity = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = role.name;
      const meta = document.createElement("small");
      meta.textContent = `${role.status.toUpperCase()} · V${role.version} · ${role.permissions.join(", ")}`;
      identity.append(name, meta);
      const prepare = document.createElement("button");
      prepare.type = "button";
      prepare.textContent = role.status === "active" ? "PREPARE RETIRE" : role.status.toUpperCase();
      prepare.disabled = role.status !== "active";
      prepare.addEventListener("click", () => void preparePreflight("custom_role_retire", role));
      row.append(identity, prepare);
      list.append(row);
    });
  }

  function approvalCard(value, own) {
    const card = document.createElement("article");
    const status = effectiveStatus(value);
    card.className = "approval-card";
    card.dataset.status = status;
    card.dataset.testid = `preflight-${value.preflight_id}`;
    const top = document.createElement("div");
    top.className = "card-top";
    const target = document.createElement("strong");
    target.textContent = value.impact_summary?.target_name || shortId(value.target_id);
    const chip = document.createElement("span");
    chip.className = "status-chip";
    chip.textContent = status.replaceAll("_", " ").toUpperCase();
    top.append(target, chip);
    const meta = document.createElement("p");
    meta.className = "card-meta";
    meta.textContent = `${operationLabel(value.operation_type)} · TARGET V${value.target_version} · REQUESTER ${shortId(value.requested_by)} · EXPIRES ${new Date(value.expires_at).toLocaleString()}`;
    card.append(top, meta);
    appendImpactFacts(card, value.impact_summary);
    const reason = document.createElement("p");
    reason.className = "audit-reason";
    reason.textContent = `REQUEST REASON / ${value.reason || "legacy request metadata unavailable"}`;
    card.append(reason);
    if (value.approval_reason) {
      const decisionReason = document.createElement("p");
      decisionReason.className = "audit-reason";
      decisionReason.textContent = `DECISION REASON / ${value.approval_reason}`;
      card.append(decisionReason);
    }
    const actions = document.createElement("div");
    actions.className = "card-actions";
    if (!own && status === "pending_approval") {
      [
        ["APPROVE", "approve"],
        ["REJECT", "reject"],
      ].forEach(([label, decision]) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = decision;
        button.textContent = label;
        button.addEventListener("click", () => void decidePreflight(value, decision));
        actions.append(button);
      });
    }
    if (own && status === "approved" && value.reason) {
      const execute = document.createElement("button");
      execute.type = "button";
      execute.className = "execute";
      execute.textContent = "EXECUTE APPROVED CHANGE";
      execute.addEventListener("click", () => void executePreflight(value));
      actions.append(execute);
    }
    if (actions.children.length) card.append(actions);
    return card;
  }

  function renderPreflights(container, values, own) {
    container.replaceChildren();
    if (!values.length) {
      container.append(governanceEmpty(own ? "尚未发起企业访问变更。" : "当前没有需要你处理的有效请求。"));
      return;
    }
    values.forEach((value) => container.append(approvalCard(value, own)));
  }

  async function loadGroups() {
    const revision = ++state.groupLoadRevision;
    try {
      const result = await api(tenantPath("/groups?limit=100"));
      if (revision !== state.groupLoadRevision) return;
      state.groups = result.items;
      renderGroups();
    } catch (error) {
      if (revision !== state.groupLoadRevision) return;
      state.groups = [];
      renderGroups("当前角色无 Tenant Group 读取权限。");
      log(error.message, "warning");
    }
  }

  async function loadRoles() {
    const revision = ++state.roleLoadRevision;
    const projectId = state.selectedProject?.project_id || "";
    if (!state.selectedProject) {
      state.roles = [];
      renderRoles();
      return;
    }
    try {
      const result = await api(scopePath(`/projects/${state.selectedProject.project_id}/custom-roles?limit=100`));
      if (revision !== state.roleLoadRevision || state.selectedProject?.project_id !== projectId) return;
      state.roles = result.items;
      renderRoles(state.roles.length ? "" : "当前 Project 尚无 Custom Role。");
    } catch (error) {
      if (revision !== state.roleLoadRevision || state.selectedProject?.project_id !== projectId) return;
      state.roles = [];
      renderRoles("当前角色无此 Project 的 Custom Role 读取权限。");
      log(error.message, "warning");
    }
  }

  async function loadApprovals() {
    const revision = ++state.approvalLoadRevision;
    const actorId = state.actorId;
    const tenantId = state.tenantId;
    const spaceId = state.spaceId;
    const projectId = state.selectedProject?.project_id || "";
    const isCurrent = () =>
      revision === state.approvalLoadRevision &&
      actorId === state.actorId &&
      tenantId === state.tenantId &&
      spaceId === state.spaceId &&
      projectId === (state.selectedProject?.project_id || "");
    let myItems = [];
    let groupItems = [];
    let roleItems = [];
    try {
      const mine = await api(tenantPath("/enterprise-access-preflights/mine?limit=100"));
      myItems = mine.items;
    } catch (error) {
      if (isCurrent()) log(error.message, "error");
    }
    try {
      const groups = await api(tenantPath("/enterprise-access-preflights/group-archive-inbox?limit=100"));
      groupItems = groups.items;
    } catch (error) {
      if (isCurrent()) log(error.message, "warning");
    }
    if (state.selectedProject) {
      try {
        const roles = await api(
          scopePath(
            `/projects/${state.selectedProject.project_id}/enterprise-access-preflights/custom-role-retire-inbox?limit=100`,
          ),
        );
        roleItems = roles.items;
      } catch (error) {
        if (isCurrent()) log(error.message, "warning");
      }
    }
    if (!isCurrent()) return;
    const seen = new Set();
    state.myPreflights = myItems;
    state.approvalInbox = [...groupItems, ...roleItems].filter((value) => {
      if (seen.has(value.preflight_id)) return false;
      seen.add(value.preflight_id);
      return true;
    });
    renderPreflights($("#approval-inbox"), state.approvalInbox, false);
    renderPreflights($("#my-preflights"), state.myPreflights, true);
    const count = String(state.approvalInbox.length).padStart(2, "0");
    $("#approval-count").textContent = count;
    $("#approval-nav-count").textContent = count;
  }

  async function loadApprovalWorkspace() {
    if (!state.contextSnapshot) return;
    await loadGroups();
    await loadRoles();
    await loadApprovals();
  }

  function showView(view, options = {}) {
    if (state.view === "members" && view !== "members") hideOneTimeToken();
    state.view = view;
    const approvals = view === "approvals";
    const members = view === "members";
    const billing = view === "billing";
    const projects = view === "projects";
    $("#project-board").hidden = !projects;
    $("#inspector").hidden = !projects;
    $("#member-board").hidden = !members;
    $("#approval-board").hidden = !approvals;
    $("#billing-board").hidden = !billing;
    $("#view-projects").classList.toggle("active", projects);
    $("#view-members").classList.toggle("active", members);
    $("#view-approvals").classList.toggle("active", approvals);
    $("#view-billing").classList.toggle("active", billing);
    if (members && options.load !== false) void loadMemberWorkspace();
    if (approvals && options.load !== false) void loadApprovalWorkspace();
    if (billing) syncBillingEntitlementTarget();
    if (billing && options.load !== false) void loadBillingWorkspace();
  }

  function finishDialog(value) {
    if (actionDialog.open) actionDialog.close();
    const resolve = dialogResolver;
    dialogResolver = null;
    if (resolve) resolve(value);
  }

  function openActionDialog({ title, operation, target, version, summary = {}, confirm, warning, reason = "", lockReason = false }) {
    $("#action-dialog-title").textContent = title;
    $("#action-dialog-kicker").textContent = operation;
    $("#action-dialog-warning").textContent = warning;
    $("#action-confirm").textContent = confirm;
    const reasonInput = $("#action-reason");
    reasonInput.value = reason;
    reasonInput.readOnly = lockReason;
    const impact = $("#action-impact");
    impact.replaceChildren();
    const identity = document.createElement("strong");
    identity.textContent = `${target} · TARGET V${version}`;
    impact.append(identity);
    appendImpactFacts(impact, summary);
    actionDialog.showModal();
    reasonInput.focus();
    return new Promise((resolve) => {
      dialogResolver = resolve;
    });
  }

  async function preparePreflight(operation, target) {
    const reason = await openActionDialog({
      title: operation === "group_archive" ? "生成 Group 归档快照" : "生成 Role 退役快照",
      operation: "PREPARE / NO CHANGE EXECUTED",
      target: target.name,
      version: target.version,
      confirm: "GENERATE IMPACT SNAPSHOT",
      warning: "此步骤只生成 15 分钟有效的服务端影响快照；必须由另一名当前有权管理员批准。",
    });
    if (!reason) return;
    try {
      const path =
        operation === "group_archive"
          ? tenantPath(`/groups/${target.id}/archive-preflights`)
          : scopePath(`/projects/${state.selectedProject.project_id}/custom-roles/${target.id}/retire-preflights`);
      const result = await api(path, {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-enterprise-preflight") },
        body: JSON.stringify({ expected_version: target.version, reason }),
      });
      log(`${operationLabel(operation)} impact snapshot ${shortId(result.preflight_id)} created`, "success");
      await loadApprovals();
    } catch (error) {
      log(error.message, "error");
    }
  }

  async function decidePreflight(value, decision) {
    const reason = await openActionDialog({
      title: decision === "approve" ? "批准影响快照" : "拒绝影响快照",
      operation: `${operationLabel(value.operation_type)} / ${decision.toUpperCase()}`,
      target: value.impact_summary?.target_name || shortId(value.target_id),
      version: value.target_version,
      summary: value.impact_summary,
      confirm: decision === "approve" ? "APPROVE EXACT IMPACT" : "REJECT REQUEST",
      warning:
        decision === "approve"
          ? "批准绑定当前 Target 版本、影响摘要和快照哈希；发起人仍需单独执行。"
          : "拒绝后该请求不可执行；如需重试，发起人必须创建新快照。",
    });
    if (!reason) return;
    try {
      const path =
        value.operation_type === "group_archive"
          ? tenantPath(`/groups/${value.target_id}/archive-preflights/${value.preflight_id}/decisions`)
          : scopePath(
              `/projects/${value.project_id}/custom-roles/${value.target_id}/retire-preflights/${value.preflight_id}/decisions`,
            );
      await api(path, {
        method: "POST",
        headers: { "Idempotency-Key": idempotency(`ui-preflight-${decision}`) },
        body: JSON.stringify({ decision, reason }),
      });
      log(`${operationLabel(value.operation_type)} ${decision}d`, decision === "approve" ? "success" : "warning");
      await loadApprovals();
    } catch (error) {
      log(error.message, "error");
    }
  }

  async function executePreflight(value) {
    const reason = await openActionDialog({
      title: "执行已批准变更",
      operation: `${operationLabel(value.operation_type)} / EXECUTE`,
      target: value.impact_summary?.target_name || shortId(value.target_id),
      version: value.target_version,
      summary: value.impact_summary,
      confirm: "EXECUTE IRREVERSIBLE CHANGE",
      warning: "执行前服务端会重新核验批准人权限、Target 版本、原因与完整快照哈希。",
      reason: value.reason,
      lockReason: true,
    });
    if (!reason) return;
    try {
      const path =
        value.operation_type === "group_archive"
          ? tenantPath(`/groups/${value.target_id}/archive`)
          : scopePath(`/projects/${value.project_id}/custom-roles/${value.target_id}/retire`);
      await api(path, {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-preflight-execute") },
        body: JSON.stringify({
          approval_preflight_id: value.preflight_id,
          expected_version: value.target_version,
          reason,
        }),
      });
      log(`${operationLabel(value.operation_type)} executed`, "success");
      await loadGroups();
      await loadRoles();
      await loadApprovals();
    } catch (error) {
      log(error.message, "error");
    }
  }

  function beginMemberMutation() {
    if (state.memberMutationPending) {
      log("member_mutation_pending: wait for the current change", "warning");
      return false;
    }
    state.memberMutationPending = true;
    renderMemberDetail();
    return true;
  }

  function endMemberMutation() {
    state.memberMutationPending = false;
    renderMemberDetail();
  }

  async function updateTenantRole() {
    const member = state.selectedMember;
    if (!member) return;
    const role = $("#tenant-member-role").value;
    if (role === member.tenant_role) return log("membership_unchanged: Tenant Role is already active", "warning");
    const reason = await openActionDialog({
      title: "更新 Tenant Role",
      operation: role === "admin" ? "HIGH RISK / FRESH AUTH REQUIRED" : "TENANT MEMBERSHIP / ROLE",
      target: memberLabel(member),
      version: member.tenant_membership_version,
      summary: { current_role: member.tenant_role, next_role: role, current_status: member.tenant_status },
      confirm: "APPLY VERSIONED ROLE",
      warning: role === "admin" ? "Admin 提权仅允许 Tenant Owner 在最近 5 分钟认证后执行，并会撤销目标用户全部会话。" : "角色变更使用 CAS 版本并撤销目标用户全部会话。",
    });
    if (!reason) return;
    if (!beginMemberMutation()) return;
    try {
      const result = await api(tenantPath(`/members/${member.user_id}/role`), {
        method: "PUT",
        headers: { "Idempotency-Key": idempotency("ui-tenant-member-role") },
        body: JSON.stringify({ role, expected_version: member.tenant_membership_version, reason }),
      });
      log(`Tenant Role changed at V${result.membership_version}; ${result.revoked_session_count} session(s) revoked`, "success");
      await loadMembers();
    } catch (error) {
      log(error.message, "error");
    } finally {
      endMemberMutation();
    }
  }

  async function mutateTenantStatus() {
    const member = state.selectedMember;
    if (!member) return;
    const action = member.tenant_status === "active" ? "suspend" : "resume";
    const reason = await openActionDialog({
      title: action === "suspend" ? "暂停 Tenant 访问" : "恢复 Tenant 访问",
      operation: `TENANT MEMBERSHIP / ${action.toUpperCase()}`,
      target: memberLabel(member),
      version: member.tenant_membership_version,
      summary: { current_status: member.tenant_status, next_status: action === "suspend" ? "suspended" : "active" },
      confirm: `${action.toUpperCase()} TENANT ACCESS`,
      warning: action === "suspend" ? "暂停将提升用户 Security Version 并撤销其全部会话。" : "恢复不会复活旧会话，用户必须重新认证。",
    });
    if (!reason) return;
    if (!beginMemberMutation()) return;
    try {
      const result = await api(tenantPath(`/members/${member.user_id}/${action}`), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency(`ui-tenant-member-${action}`) },
        body: JSON.stringify({ expected_version: member.tenant_membership_version, reason }),
      });
      log(`Tenant access ${action}d at V${result.membership_version}`, "success");
      await loadMembers();
    } catch (error) {
      log(error.message, "error");
    } finally {
      endMemberMutation();
    }
  }

  async function updateSpaceRole(member, access, role) {
    if (state.memberMutationPending) return log("member_mutation_pending: wait for the current change", "warning");
    if (role === access.role) return log("membership_unchanged: Space Role is already active", "warning");
    const reason = await openActionDialog({
      title: "更新 Space Role",
      operation: role === "admin" ? "HIGH RISK / FRESH AUTH REQUIRED" : "SPACE MEMBERSHIP / ROLE",
      target: `${memberLabel(member)} / ${access.space_name}`,
      version: access.version,
      summary: { current_role: access.role, next_role: role, current_status: access.status },
      confirm: "APPLY SPACE ROLE",
      warning: "服务端会重新验证 Tenant 与 Space 管理权限，CAS 成功后撤销目标用户全部会话。",
    });
    if (!reason) return;
    if (!beginMemberMutation()) return;
    try {
      const result = await api(tenantPath(`/spaces/${access.space_id}/members/${member.user_id}/role`), {
        method: "PUT",
        headers: { "Idempotency-Key": idempotency("ui-space-member-role") },
        body: JSON.stringify({ role, expected_version: access.version, reason }),
      });
      log(`Space Role changed at V${result.membership_version}`, "success");
      await loadMembers();
    } catch (error) {
      log(error.message, "error");
    } finally {
      endMemberMutation();
    }
  }

  async function mutateSpaceStatus(member, access) {
    if (state.memberMutationPending) return log("member_mutation_pending: wait for the current change", "warning");
    const action = access.status === "active" ? "suspend" : "resume";
    const reason = await openActionDialog({
      title: action === "suspend" ? "暂停 Space 访问" : "恢复 Space 访问",
      operation: `SPACE MEMBERSHIP / ${action.toUpperCase()}`,
      target: `${memberLabel(member)} / ${access.space_name}`,
      version: access.version,
      summary: { current_status: access.status, next_status: action === "suspend" ? "suspended" : "active" },
      confirm: `${action.toUpperCase()} SPACE ACCESS`,
      warning: "Space 访问变更同样提升 Security Version，旧会话不会继续生效。",
    });
    if (!reason) return;
    if (!beginMemberMutation()) return;
    try {
      const result = await api(tenantPath(`/spaces/${access.space_id}/members/${member.user_id}/${action}`), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency(`ui-space-member-${action}`) },
        body: JSON.stringify({ expected_version: access.version, reason }),
      });
      log(`Space access ${action}d at V${result.membership_version}`, "success");
      await loadMembers();
    } catch (error) {
      log(error.message, "error");
    } finally {
      endMemberMutation();
    }
  }

  async function transferTenantOwner() {
    const target = state.selectedMember;
    if (!target) return;
    const reason = await openActionDialog({
      title: "转移 Tenant Owner",
      operation: "IRREVERSIBLE AUTHORITY TRANSFER",
      target: memberLabel(target),
      version: target.tenant_membership_version,
      summary: { target_role: target.tenant_role, target_status: target.tenant_status },
      confirm: "TRANSFER OWNER + END SESSION",
      warning: "成功后当前 Owner 降为 Admin，目标提升为 Owner，双方会话被撤销，当前控制台立即退出。",
    });
    if (!reason) return;
    if (!beginMemberMutation()) return;
    try {
      const unfiltered = await api(tenantPath("/members?limit=100"));
      const source = unfiltered.items.find((member) => member.user_id === state.actorId);
      if (!source || source.tenant_role !== "owner") throw new Error("owner_required: current actor is not the Tenant Owner");
      await api(tenantPath("/ownership-transfers"), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-owner-transfer") },
        body: JSON.stringify({
          to_user_id: target.user_id,
          source_expected_version: source.tenant_membership_version,
          target_expected_version: target.tenant_membership_version,
          reason,
          space_id: null,
        }),
      });
      log(`Tenant Owner transferred to ${memberLabel(target)}; session ended`, "success");
      setLoggedOut();
    } catch (error) {
      log(error.message, "error");
    } finally {
      endMemberMutation();
    }
  }

  async function preflightMemberRemoval() {
    const member = state.selectedMember;
    if (!member) return;
    if (!beginMemberMutation()) return;
    try {
      const preflight = await api(tenantPath(`/members/${member.user_id}/removal-preflights`), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-member-removal-preflight") },
        body: JSON.stringify({ space_id: null }),
      });
      const reason = await openActionDialog({
        title: preflight.blocking_count ? "移除被依赖阻断" : "执行成员移除",
        operation: "MEMBER REMOVAL / SERVER IMPACT SNAPSHOT",
        target: memberLabel(member),
        version: member.tenant_membership_version,
        summary: {
          blocking_count: preflight.blocking_count,
          snapshot_hash: preflight.snapshot_hash.slice(0, 16),
          expires_at: formatDate(preflight.expires_at),
        },
        confirm: preflight.blocking_count ? "ACKNOWLEDGE BLOCKERS" : "EXECUTE EXACT SNAPSHOT",
        warning: preflight.blocking_count ? "存在阻断依赖，控制台不会提交删除。请先转移资源所有权后重新预检。" : "服务端执行前会重新验证快照哈希、过期时间、当前权限和最近认证。",
      });
      if (!reason || preflight.blocking_count) return;
      const removed = await api(tenantPath(`/member-removal-preflights/${preflight.preflight_id}/execute`), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-member-removal-execute") },
        body: JSON.stringify({ reason }),
      });
      log(`Member removed; ${removed.removed_space_memberships} Space membership(s) closed`, "success");
      state.selectedMember = null;
      await loadMembers();
    } catch (error) {
      log(error.message, "error");
    } finally {
      endMemberMutation();
    }
  }

  async function reissueInvitation(invitation) {
    const reason = await openActionDialog({
      title: "旋转 Invitation Token",
      operation: "INVITATION / ROTATE + REISSUE",
      target: invitation.email_normalized,
      version: invitation.version,
      summary: { status: invitation.status, expires_at: formatDate(invitation.expires_at) },
      confirm: "INVALIDATE OLD TOKEN",
      warning: "旧 Token 将立即失效；新 Token 只在本次响应显示一次。",
    });
    if (!reason) return;
    try {
      const result = await api(tenantPath(`/membership-invitations/${invitation.invitation_id}/reissue`), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-invitation-reissue") },
        body: JSON.stringify({ expected_version: invitation.version, ttl_hours: 168, reason }),
      });
      showOneTimeToken(result.one_time_token);
      log(`Invitation token rotated at V${result.version}`, "success");
      await loadInvitations();
    } catch (error) {
      log(error.message, "error");
    }
  }

  async function revokeInvitation(invitation) {
    const reason = await openActionDialog({
      title: "撤销 Invitation",
      operation: "INVITATION / REVOKE",
      target: invitation.email_normalized,
      version: invitation.version,
      summary: { status: invitation.status, expires_at: formatDate(invitation.expires_at) },
      confirm: "REVOKE INVITATION",
      warning: "撤销后 Token 永久失效；如需重新邀请必须生成新 Token。",
    });
    if (!reason) return;
    try {
      const result = await api(tenantPath(`/membership-invitations/${invitation.invitation_id}/revoke`), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-invitation-revoke") },
        body: JSON.stringify({ expected_version: invitation.version, reason }),
      });
      hideOneTimeToken();
      log(`Invitation revoked at V${result.version}`, "success");
      await loadInvitations();
    } catch (error) {
      log(error.message, "error");
    }
  }

  function showFailure(element, error) {
    element.textContent = error.message;
    element.classList.add("shake");
    window.setTimeout(() => element.classList.remove("shake"), 600);
    log(error.message, "error");
  }

  $("#view-projects").addEventListener("click", () => showView("projects"));
  $("#view-members").addEventListener("click", () => showView("members"));
  $("#view-approvals").addEventListener("click", () => showView("approvals"));
  $("#view-billing").addEventListener("click", () => showView("billing"));
  $("#approval-refresh").addEventListener("click", () => void loadApprovalWorkspace());
  $("#billing-refresh").addEventListener("click", () => void loadBillingWorkspace());
  $("#invitation-refresh").addEventListener("click", () => void loadInvitations());
  $("#invite-token-dismiss").addEventListener("click", hideOneTimeToken);

  function syncBillingEntitlementTarget() {
    const scope = $("#billing-entitlement-scope").value;
    const target = $("#billing-entitlement-target");
    target.disabled = scope === "tenant" || scope === "space" || scope === "project";
    if (scope === "tenant") target.value = state.tenantId;
    if (scope === "space") target.value = state.spaceId;
    if (scope === "project") target.value = state.selectedProject?.project_id || "SELECT PROJECT";
    if (scope === "user" || scope === "model") {
      if ([state.tenantId, state.spaceId, "SELECT PROJECT"].includes(target.value)) target.value = "";
      target.placeholder = scope === "user" ? "User UUID" : "Provider model key";
    }
  }

  $("#billing-entitlement-scope").addEventListener("change", syncBillingEntitlementTarget);

  $("#billing-subscription-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const provider = $("#billing-provider").value.trim();
    try {
      const result = await api(tenantPath("/billing/subscription"), {
        method: "PUT",
        headers: { "Idempotency-Key": idempotency("ui-billing-subscription") },
        body: JSON.stringify({
          plan_key: $("#billing-plan-key").value.trim(),
          status: $("#billing-subscription-status").value,
          current_period_start: inputIso("#billing-period-start"),
          current_period_end: inputIso("#billing-period-end"),
          provider: provider || null,
          provider_customer_ref: provider ? $("#billing-customer-ref").value.trim() || null : null,
          provider_subscription_ref: provider ? $("#billing-subscription-ref").value.trim() || null : null,
          expected_version: state.billing?.subscription?.version || null,
        }),
      });
      log(`Billing subscription committed at V${result.version}`, "success");
      await loadBillingWorkspace();
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#billing-pricing-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const meter = $("#billing-pricing-meter").value.trim();
    try {
      const result = await api(tenantPath("/billing/pricing-snapshots"), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-billing-pricing") },
        body: JSON.stringify({
          plan_key: $("#billing-pricing-plan").value.trim(),
          currency: $("#billing-pricing-currency").value.trim().toUpperCase(),
          rates: {
            [meter]: {
              unit: $("#billing-pricing-unit").value.trim(),
              unit_size: $("#billing-pricing-unit-size").value.trim(),
              minor_per_unit: Number($("#billing-pricing-minor").value),
            },
          },
          effective_from: inputIso("#billing-pricing-effective"),
          effective_until: inputIso("#billing-pricing-until"),
        }),
      });
      log(`Pricing snapshot V${result.version} sealed`, "success");
      await loadBillingWorkspace();
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#billing-entitlement-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const scope = $("#billing-entitlement-scope").value;
    const target = $("#billing-entitlement-target").value.trim();
    const meter = $("#billing-entitlement-meter").value.trim();
    if (scope === "project" && !state.selectedProject) return log("project_required: select a Project", "error");
    const scopeKey = {
      tenant: state.tenantId,
      space: state.spaceId,
      project: state.selectedProject?.project_id,
      user: target,
      model: target,
    }[scope];
    const existing = (state.billing?.entitlements || []).find(
      (value) => value.scope_type === scope && value.scope_key === scopeKey && value.meter === meter
    );
    try {
      const result = await api(tenantPath("/billing/entitlements"), {
        method: "PUT",
        headers: { "Idempotency-Key": idempotency("ui-billing-entitlement") },
        body: JSON.stringify({
          scope_type: scope,
          space_id: scope === "space" || scope === "project" ? state.spaceId : null,
          project_id: scope === "project" ? state.selectedProject.project_id : null,
          user_id: scope === "user" ? target : null,
          model_key: scope === "model" ? target : null,
          meter,
          unit: $("#billing-entitlement-unit").value.trim(),
          limit_quantity: $("#billing-entitlement-limit").value.trim() || null,
          concurrency_limit: $("#billing-entitlement-concurrency").value ? Number($("#billing-entitlement-concurrency").value) : null,
          hard_limit: true,
          period: "month",
          period_start: inputIso("#billing-entitlement-start"),
          period_end: inputIso("#billing-entitlement-end"),
          status: "active",
          expected_version: existing?.version || null,
        }),
      });
      log(`Entitlement ${result.meter} committed at V${result.version}`, "success");
      await loadBillingWorkspace();
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#billing-reconcile-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api(tenantPath("/billing/reconciliations"), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-billing-reconciliation") },
        body: JSON.stringify({
          period_start: inputIso("#billing-query-start"),
          period_end: inputIso("#billing-query-end"),
        }),
      });
      log(`Billing reconciliation ${shortId(result.batch_id)} finished as ${result.status}`, result.status === "completed" ? "success" : "warning");
      await loadBillingWorkspace();
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#member-filter-form").addEventListener("submit", (event) => {
    event.preventDefault();
    state.selectedMember = null;
    void loadMembers();
  });
  $("#tenant-role-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void updateTenantRole();
  });
  $("#tenant-member-status-toggle").addEventListener("click", () => void mutateTenantStatus());
  $("#tenant-owner-transfer").addEventListener("click", () => void transferTenantOwner());
  $("#tenant-member-remove").addEventListener("click", () => void preflightMemberRemoval());
  $("#invite-space-enabled").addEventListener("change", () => {
    $("#invite-space-role").disabled = !$("#invite-space-enabled").checked;
  });

  $("#invitation-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = $("#invite-email").value.trim();
    const tenantRole = $("#invite-tenant-role").value;
    const includeSpace = $("#invite-space-enabled").checked;
    const reason = await openActionDialog({
      title: "签发成员邀请",
      operation: tenantRole === "admin" || (includeSpace && $("#invite-space-role").value === "admin") ? "PRIVILEGED INVITATION / FRESH AUTH" : "MEMBERSHIP INVITATION / ISSUE",
      target: email,
      version: 1,
      summary: {
        tenant_role: tenantRole,
        space_role: includeSpace ? $("#invite-space-role").value : "none",
        ttl_hours: Number($("#invite-ttl").value),
      },
      confirm: "ISSUE ONE-TIME TOKEN",
      warning: "Token 只在成功响应中显示一次；服务端仅持久化摘要，Outbox 不包含明文 Token。",
    });
    if (!reason) return;
    try {
      const created = await api(tenantPath("/membership-invitations"), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-invitation-create") },
        body: JSON.stringify({
          email,
          tenant_role: tenantRole,
          space_id: includeSpace ? state.spaceId : null,
          space_role: includeSpace ? $("#invite-space-role").value : null,
          ttl_hours: Number($("#invite-ttl").value),
          reason,
        }),
      });
      $("#invite-email").value = "";
      showOneTimeToken(created.one_time_token);
      log(`Invitation ${shortId(created.invitation_id)} issued`, "success");
      await loadInvitations();
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#action-dialog-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const reason = $("#action-reason").value.trim();
    if (!reason) {
      $("#action-dialog-warning").textContent = "审计原因不能为空。";
      $("#action-reason").focus();
      return;
    }
    finishDialog(reason);
  });
  $("#action-cancel").addEventListener("click", () => finishDialog(null));
  actionDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    finishDialog(null);
  });

  $("#group-create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api(tenantPath("/groups"), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-group-create") },
        body: JSON.stringify({ name: $("#group-name").value.trim(), description: null }),
      });
      $("#group-name").value = "";
      log(`Tenant Group ${result.name} created`, "success");
      await loadGroups();
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#role-create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state.selectedProject) return log("project_required: select a Project", "error");
    const permissions = $("#role-permissions")
      .value.split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    try {
      const result = await api(scopePath(`/projects/${state.selectedProject.project_id}/custom-roles`), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-custom-role-create") },
        body: JSON.stringify({ name: $("#role-name").value.trim(), description: null, permissions }),
      });
      $("#role-name").value = "";
      log(`Custom Role ${result.name} created`, "success");
      await loadRoles();
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = $("#login-message");
    message.textContent = "VERIFYING…";
    try {
      const result = await api("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: $("#login-email").value, password: $("#login-password").value }),
      });
      state.csrf = result.csrf_token;
      sessionStorage.setItem("omnigent.saas.csrf", state.csrf);
      message.textContent = "";
      setAuthenticated(result.user_id);
      await Promise.all([loadCatalog(), loadScopes()]);
    } catch (error) {
      showFailure(message, error);
    }
  });

  $("#logout-button").addEventListener("click", async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch (error) {
      log(error.message, "error");
    } finally {
      setLoggedOut();
    }
  });

  $("#scope-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const selected = state.scopes[Number($("#scope-select").value)];
    if (!selected) return log("scope_not_authorized: select an available scope", "error");
    state.tenantId = selected.tenant_id;
    state.spaceId = selected.space_id;
    state.tenantRole = selected.tenant_role;
    state.billing = null;
    state.billingUsage = [];
    state.billingLedger = [];
    state.billingReconciliations = [];
    state.billingLoadRevision += 1;
    try {
      const context = await api("/context/snapshots", {
        method: "POST",
        body: JSON.stringify({ tenant_id: state.tenantId, space_id: state.spaceId }),
      });
      state.contextSnapshot = context.context_snapshot;
      $("#snapshot-state").textContent = `SIGNED / ${context.max_age_seconds}s`;
      await loadProjects();
      if (state.view === "members") await loadMemberWorkspace();
      if (state.view === "approvals") await loadApprovalWorkspace();
      if (state.view === "billing") {
        syncBillingEntitlementTarget();
        await loadBillingWorkspace();
      }
      document.querySelector(".system-state").classList.add("connected");
      $("#context-state").textContent = `SPACE / ${state.spaceId.slice(0, 8)}`;
      log(`Signed Context Snapshot issued for ${selected.tenant_name} / ${selected.space_name}`, "success");
    } catch (error) {
      state.contextSnapshot = "";
      $("#snapshot-state").textContent = "REJECTED";
      showFailure($("#context-state"), error);
    }
  });

  $("#project-create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const created = await api(scopePath("/projects"), {
        method: "POST",
        headers: { "Idempotency-Key": idempotency("ui-project-create") },
        body: JSON.stringify({ name: $("#project-name").value, visibility: $("#project-visibility").value }),
      });
      $("#project-name").value = "";
      await loadProjects();
      const project = state.projects.find((item) => item.project_id === created.project_id);
      if (project) selectProject(project);
      log(`Project created at authorization version ${created.authorization_version}`, "success");
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#decision-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const resultBox = $("#decision-result");
    if (!state.selectedProject) return showFailure(resultBox, new Error("project_required: select a Project"));
    const resourceType = $("#decision-resource-type").value.trim();
    const resourceId = $("#decision-resource-id").value.trim();
    try {
      const result = await api(scopePath(`/projects/${state.selectedProject.project_id}/access/decisions`), {
        method: "POST",
        body: JSON.stringify({
          action: $("#decision-action").value,
          subject_user_id: $("#decision-subject").value.trim(),
          resource_type: resourceType || null,
          resource_id: resourceId || null,
        }),
      });
      resultBox.className = `decision-result ${result.allowed ? "allowed" : "denied"}`;
      resultBox.replaceChildren();
      const verdict = document.createElement("strong");
      verdict.textContent = result.allowed ? "ALLOWED" : "DENIED";
      const reason = document.createElement("span");
      reason.textContent = `${result.reason} · V${result.project_authorization_version ?? "—"} · ${result.policy_version}`;
      resultBox.append(verdict, reason);
      const sources = $("#decision-sources");
      sources.replaceChildren();
      result.sources.forEach((source) => {
        const row = document.createElement("li");
        row.textContent = `${source.source_type} / ${source.role} / ${source.subject_id}`;
        sources.append(row);
      });
      log(`Decision ${result.allowed ? "allowed" : "denied"}: ${result.reason}`, result.allowed ? "success" : "warning");
    } catch (error) {
      showFailure(resultBox, error);
    }
  });

  $("#membership-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state.selectedProject) return log("project_required: select a Project", "error");
    const subject = $("#member-subject").value.trim();
    try {
      const result = await api(scopePath(`/projects/${state.selectedProject.project_id}/members/user/${subject}`), {
        method: "PUT",
        headers: { "Idempotency-Key": idempotency("ui-membership-set") },
        body: JSON.stringify({ role: $("#member-role").value }),
      });
      state.selectedProject.authorization_version = result.authorization_version;
      $("#project-version").textContent = `V${result.authorization_version}`;
      log(`Membership set to ${result.role} at V${result.authorization_version}`, "success");
    } catch (error) {
      log(error.message, "error");
    }
  });

  $("#member-revoke").addEventListener("click", async () => {
    if (!state.selectedProject) return log("project_required: select a Project", "error");
    const subject = $("#member-subject").value.trim();
    try {
      const result = await api(scopePath(`/projects/${state.selectedProject.project_id}/members/user/${subject}`), {
        method: "DELETE",
        headers: { "Idempotency-Key": idempotency("ui-membership-revoke") },
      });
      state.selectedProject.authorization_version = result.authorization_version;
      $("#project-version").textContent = `V${result.authorization_version}`;
      log(`Membership revoked at V${result.authorization_version}`, "success");
    } catch (error) {
      log(error.message, "error");
    }
  });

  async function boot() {
    try {
      const current = await api("/auth/status");
      if (current.authenticated) {
        setAuthenticated(current.user_id);
        await Promise.all([loadCatalog(), loadScopes()]);
        return;
      }
    } catch (error) {
      log(error.message, "error");
    }
    setLoggedOut();
  }

  boot();
})();
