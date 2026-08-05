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
    groups: [],
    roles: [],
    approvalInbox: [],
    myPreflights: [],
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
    state.actorId = "";
    state.csrf = "";
    state.contextSnapshot = "";
    state.scopes = [];
    state.tenantId = "";
    state.spaceId = "";
    state.projects = [];
    state.selectedProject = null;
    state.groups = [];
    state.roles = [];
    state.approvalInbox = [];
    state.myPreflights = [];
    sessionStorage.removeItem("omnigent.saas.csrf");
    loginDeck.hidden = false;
    workspace.hidden = true;
    $("#logout-button").hidden = true;
    document.querySelector(".system-state").classList.remove("connected");
    $("#context-state").textContent = "NO CONTEXT";
    $("#snapshot-state").textContent = "UNBOUND";
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
    state.scopes = await api("/context/scopes");
    const selector = $("#scope-select");
    selector.replaceChildren();
    if (!state.scopes.length) {
      const empty = document.createElement("option");
      empty.value = "";
      empty.textContent = "没有可用的 Tenant / Space";
      selector.append(empty);
      $("#scope-connect").disabled = true;
      return;
    }
    state.scopes.forEach((scope, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = `${scope.tenant_name} / ${scope.space_name} · ${scope.tenant_role}:${scope.space_role}`;
      selector.append(option);
    });
    $("#scope-connect").disabled = false;
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
    try {
      const result = await api(tenantPath("/groups?limit=100"));
      state.groups = result.items;
      renderGroups();
    } catch (error) {
      state.groups = [];
      renderGroups("当前角色无 Tenant Group 读取权限。");
      log(error.message, "warning");
    }
  }

  async function loadRoles() {
    if (!state.selectedProject) {
      state.roles = [];
      renderRoles();
      return;
    }
    try {
      const result = await api(scopePath(`/projects/${state.selectedProject.project_id}/custom-roles?limit=100`));
      state.roles = result.items;
      renderRoles(state.roles.length ? "" : "当前 Project 尚无 Custom Role。");
    } catch (error) {
      state.roles = [];
      renderRoles("当前角色无此 Project 的 Custom Role 读取权限。");
      log(error.message, "warning");
    }
  }

  async function loadApprovals() {
    let groupItems = [];
    let roleItems = [];
    try {
      const mine = await api(tenantPath("/enterprise-access-preflights/mine?limit=100"));
      state.myPreflights = mine.items;
    } catch (error) {
      state.myPreflights = [];
      log(error.message, "error");
    }
    try {
      const groups = await api(tenantPath("/enterprise-access-preflights/group-archive-inbox?limit=100"));
      groupItems = groups.items;
    } catch (error) {
      log(error.message, "warning");
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
        log(error.message, "warning");
      }
    }
    const seen = new Set();
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
    state.view = view;
    const approvals = view === "approvals";
    $("#project-board").hidden = approvals;
    $("#inspector").hidden = approvals;
    $("#approval-board").hidden = !approvals;
    $("#view-projects").classList.toggle("active", !approvals);
    $("#view-approvals").classList.toggle("active", approvals);
    if (approvals && options.load !== false) void loadApprovalWorkspace();
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

  function showFailure(element, error) {
    element.textContent = error.message;
    element.classList.add("shake");
    window.setTimeout(() => element.classList.remove("shake"), 600);
    log(error.message, "error");
  }

  $("#view-projects").addEventListener("click", () => showView("projects"));
  $("#view-approvals").addEventListener("click", () => showView("approvals"));
  $("#approval-refresh").addEventListener("click", () => void loadApprovalWorkspace());

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
    try {
      const context = await api("/context/snapshots", {
        method: "POST",
        body: JSON.stringify({ tenant_id: state.tenantId, space_id: state.spaceId }),
      });
      state.contextSnapshot = context.context_snapshot;
      $("#snapshot-state").textContent = `SIGNED / ${context.max_age_seconds}s`;
      await loadProjects();
      if (state.view === "approvals") await loadApprovalWorkspace();
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
