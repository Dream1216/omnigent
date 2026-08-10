(() => {
  "use strict";

  const root = document.querySelector("#notification-ops-shell");
  if (!root) return;

  const realm = document.documentElement.dataset.notificationRealm;
  const tenantMatch = location.pathname.match(/\/saas\/tenants\/([0-9a-f-]{36})\/notification-ops\/?$/i);
  const base = realm === "staff"
    ? "/v2/platform-admin/notification-operations"
    : `/saas/tenants/${tenantMatch ? tenantMatch[1] : "invalid"}/notification-operations`;
  const csrfKey = realm === "staff" ? "omnigent.platform.csrf" : "omnigent.saas.csrf";
  const state = {
    inbox: [],
    delegations: [],
    deliveries: [],
    preferences: [],
    templates: [],
    selected: new Set(),
    batch: null,
    singleDecision: null,
  };

  const query = (selector, within = document) => within.querySelector(selector);
  const queryAll = (selector, within = document) => [...within.querySelectorAll(selector)];
  const text = (tag, value, className) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value == null ? "—" : String(value);
    return node;
  };
  const key = (prefix) => `${prefix}-${crypto.randomUUID()}`;

  async function api(path, options = {}) {
    const method = options.method || "GET";
    const headers = { Accept: "application/json" };
    if (options.body) headers["Content-Type"] = "application/json";
    if (method !== "GET") {
      headers["X-CSRF-Token"] = sessionStorage.getItem(csrfKey) || "";
      if (options.idempotent !== false) headers["Idempotency-Key"] = key("notification-ui");
    }
    const response = await fetch(`${base}${path}`, {
      method,
      credentials: "same-origin",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    let payload = {};
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) {
      const error = new Error("notification_operation_failed");
      error.code = payload && payload.detail && payload.detail.code
        ? payload.detail.code
        : "notification_operation_failed";
      throw error;
    }
    return payload;
  }

  function showToast(code) {
    const toast = query("[data-toast]");
    toast.textContent = code;
    toast.hidden = false;
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => { toast.hidden = true; }, 3200);
  }

  function formatTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? "—" : date.toLocaleString("zh-CN", { hour12: false });
  }

  function setMetric(name, value) {
    const node = query(`[data-metric="${name}"]`);
    if (node) node.textContent = String(value);
  }

  function updateMetrics() {
    setMetric("pending", state.inbox.filter((item) => item.status === "pending").length);
    setMetric("critical", state.inbox.filter((item) => item.risk_level === "critical").length);
    setMetric("dead_letter", state.deliveries.filter((item) => item.status === "dead_letter").length);
    setMetric("selected", state.selected.size);
    const count = query("[data-selected-count]");
    if (count) count.textContent = String(state.selected.size);
    const rail = query("[data-batch-rail]");
    if (rail) rail.hidden = state.selected.size === 0;
  }

  function workCard(item) {
    const card = document.createElement("article");
    card.className = "work-card";
    card.dataset.risk = item.risk_level;
    card.dataset.workItemId = item.work_item_id;
    card.dataset.selected = state.selected.has(item.work_item_id) ? "true" : "false";

    const head = document.createElement("div");
    head.className = "work-card-head";
    const title = document.createElement("div");
    title.append(text("span", item.priority, "risk-chip"));
    title.append(text("h3", `${item.operation_kind} / ${item.action}`));
    title.append(text("p", `${item.target_type} · v${item.version}`));
    const select = document.createElement("label");
    select.className = "select-box";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = state.selected.has(item.work_item_id);
    checkbox.setAttribute("aria-label", `选择 ${item.operation_kind} 工单`);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.selected.add(item.work_item_id);
      else state.selected.delete(item.work_item_id);
      card.dataset.selected = checkbox.checked ? "true" : "false";
      state.batch = null;
      query("[data-batch-execute]").hidden = true;
      updateMetrics();
    });
    select.append(checkbox, text("span", "选择"));
    head.append(title, select);
    card.append(head);

    const meta = document.createElement("div");
    meta.append(text("span", item.risk_level, "risk-chip"));
    meta.append(" ", text("span", item.routing, "route-chip"));
    card.append(meta);
    card.append(text("p", `权限 ${item.required_permission}`));
    card.append(text("p", `到期 ${formatTime(item.due_at)}`));

    if (item.status === "pending" && !item.requested_by_me) {
      const actions = document.createElement("div");
      actions.className = "work-actions";
      for (const decision of ["approve", "reject"]) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = decision === "approve" ? "primary-action" : "danger-action";
        button.textContent = decision === "approve" ? "通过" : "拒绝";
        button.addEventListener("click", () => openDecision(item, decision));
        actions.append(button);
      }
      card.append(actions);
    }
    return card;
  }

  function renderInbox() {
    const list = query("[data-inbox-list]");
    list.replaceChildren(...state.inbox.map(workCard));
    query("[data-inbox-empty]").hidden = state.inbox.length > 0;
    const delegationSelect = query("[data-delegation-work]");
    delegationSelect.replaceChildren();
    for (const item of state.inbox.filter((candidate) => candidate.status === "pending")) {
      const option = document.createElement("option");
      option.value = item.work_item_id;
      option.textContent = `${item.operation_kind} / ${item.action} / v${item.version}`;
      option.dataset.version = item.version;
      delegationSelect.append(option);
    }
    updateMetrics();
  }

  function renderDelegations() {
    const list = query("[data-delegation-list]");
    list.replaceChildren(...state.delegations.map((item) => {
      const row = document.createElement("article");
      row.className = "delegation-row";
      row.append(text("strong", item.permission_code));
      row.append(text("span", item.delegated_by_me ? "我发起" : "委派给我"));
      row.append(text("span", item.status));
      row.append(text("span", `至 ${formatTime(item.expires_at)}`));
      if (item.delegated_by_me && item.status === "active") {
        const revoke = text("button", "撤销", "danger-action");
        revoke.type = "button";
        revoke.addEventListener("click", async () => {
          try {
            await api(`/delegations/${item.delegation_id}/revoke`, {
              method: "POST",
              body: { expected_version: item.version },
            });
            showToast("approval_delegation_revoked");
            await loadDelegations();
          } catch (error) { showToast(error.code); }
        });
        row.append(revoke);
      } else {
        row.append(text("span", "observe"));
      }
      return row;
    }));
  }

  function deliveryRow(item) {
    const row = document.createElement("article");
    row.className = "delivery-row";
    row.append(text("strong", item.event_type));
    row.append(text("span", item.channel));
    row.append(text("span", item.status, "delivery-status"));
    row.append(text("span", `${item.attempt_count}/${item.max_attempts}`));
    row.append(text("span", item.last_error_code || (item.recipient_read_at ? "read" : "clear")));
    if (item.status === "dead_letter") {
      const replay = text("button", "重放", "secondary-action");
      replay.type = "button";
      replay.addEventListener("click", async () => {
        try {
          await api(`/deliveries/${item.delivery_id}/replay`, {
            method: "POST",
            body: { expected_version: item.version },
          });
          showToast("delivery_replay_accepted");
          await loadDeliveries();
        } catch (error) { showToast(error.code); }
      });
      row.append(replay);
    } else if (item.channel === "in_app" && item.status === "succeeded" && !item.recipient_read_at) {
      const markRead = text("button", "标记已读", "secondary-action");
      markRead.type = "button";
      markRead.addEventListener("click", async () => {
        try {
          await api(`/deliveries/${item.delivery_id}/read`, {
            method: "POST",
            body: { expected_version: item.version },
          });
          showToast("delivery_marked_read");
          await loadDeliveries();
        } catch (error) { showToast(error.code); }
      });
      row.append(markRead);
    } else {
      row.append(text("span", "observe"));
    }
    return row;
  }

  function renderDeliveries() {
    const list = query("[data-delivery-list]");
    list.replaceChildren(...state.deliveries.map(deliveryRow));
    query("[data-delivery-empty]").hidden = state.deliveries.length > 0;
    updateMetrics();
  }

  function renderPreferences() {
    const list = query("[data-preference-list]");
    list.replaceChildren(...state.preferences.map((item) => {
      const row = document.createElement("div");
      row.className = "policy-item";
      const label = document.createElement("div");
      label.append(text("strong", item.event_type), text("small", `${item.channel} · ${item.locale}`));
      const toggle = text("button", item.enabled ? "ON" : "OFF", "toggle-action");
      toggle.type = "button";
      toggle.setAttribute("aria-pressed", item.enabled ? "true" : "false");
      toggle.addEventListener("click", async () => {
        try {
          await api(`/preferences/${item.preference_id}`, {
            method: "PATCH",
            body: { expected_version: item.version, enabled: !item.enabled, locale: item.locale },
          });
          showToast("preference_updated");
          await loadPreferences();
        } catch (error) { showToast(error.code); }
      });
      row.append(label, toggle);
      return row;
    }));
  }

  function renderTemplates() {
    const list = query("[data-template-list]");
    list.replaceChildren(...state.templates.map((item) => {
      const row = document.createElement("div");
      row.className = "policy-item";
      const label = document.createElement("div");
      label.append(text("strong", item.template_key), text("small", `${item.channel} · ${item.locale} · v${item.version} · ${item.status}`));
      row.append(label);
      if (realm === "staff" && item.status === "active") {
        const retire = text("button", "停用", "toggle-action");
        retire.type = "button";
        retire.addEventListener("click", async () => {
          try {
            await api(`/templates/${item.template_id}/retire`, {
              method: "POST",
              body: { expected_version: item.version },
            });
            showToast("template_retired");
            await loadTemplates();
          } catch (error) { showToast(error.code); }
        });
        row.append(retire);
      } else {
        row.append(text("span", "READ", "readonly-tag"));
      }
      return row;
    }));
  }

  async function loadInbox() {
    const payload = await api("/inbox?status=pending");
    state.inbox = Array.isArray(payload.items) ? payload.items : [];
    state.selected = new Set([...state.selected].filter((id) => state.inbox.some((item) => item.work_item_id === id)));
    renderInbox();
  }
  async function loadDeliveries() {
    const payload = await api(realm === "staff" ? "/deliveries?status=dead_letter" : "/deliveries");
    state.deliveries = Array.isArray(payload.items) ? payload.items : [];
    renderDeliveries();
  }
  async function loadDelegations() {
    const payload = await api("/delegations");
    state.delegations = Array.isArray(payload.items) ? payload.items : [];
    renderDelegations();
  }
  async function loadPreferences() {
    const payload = await api("/preferences");
    state.preferences = Array.isArray(payload.items) ? payload.items : [];
    renderPreferences();
  }
  async function loadTemplates() {
    const payload = await api("/templates");
    state.templates = Array.isArray(payload.items) ? payload.items : [];
    renderTemplates();
  }

  function openDecision(item, decision) {
    state.singleDecision = { item, decision };
    const dialog = query("[data-decision-dialog]");
    query("[data-decision-result]").textContent = "";
    dialog.showModal();
    query("[data-single-reason]").focus();
  }

  query("[data-decision-form]").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state.singleDecision) return;
    const reason = query("[data-single-reason]");
    const code = query("[data-single-decision-code]");
    try {
      const { item, decision } = state.singleDecision;
      await api(`/inbox/${item.work_item_id}/decision`, {
        method: "POST",
        body: { expected_version: item.version, decision, decision_code: code.value, reason: reason.value },
      });
      reason.value = "";
      query("[data-decision-dialog]").close();
      state.singleDecision = null;
      showToast("approval_decision_committed");
      await loadInbox();
    } catch (error) {
      reason.value = "";
      query("[data-decision-result]").textContent = error.code;
    }
  });

  queryAll("[data-batch-preview]").forEach((button) => button.addEventListener("click", async () => {
    const reason = query("[data-batch-reason]");
    if (!reason.value) { showToast("approval_reason_required"); reason.focus(); return; }
    const items = state.inbox
      .filter((item) => state.selected.has(item.work_item_id))
      .map((item) => ({ work_item_id: item.work_item_id, expected_version: item.version }));
    try {
      state.batch = await api("/batches/preview", {
        method: "POST",
        body: {
          decision: button.dataset.batchPreview,
          decision_code: query("[data-decision-code]").value,
          reason: reason.value,
          items,
        },
      });
      reason.value = "";
      reason.placeholder = "执行前再次输入同一审计原因";
      query("[data-batch-execute]").hidden = false;
      query("[data-batch-result]").textContent = `预检 ${state.batch.item_count} 项 · 批次 v${state.batch.version}`;
    } catch (error) { reason.value = ""; showToast(error.code); }
  }));

  query("[data-batch-execute]").addEventListener("click", async () => {
    if (!state.batch) return;
    try {
      const reason = query("[data-batch-reason]");
      if (!reason.value) { showToast("approval_reason_required"); reason.focus(); return; }
      state.batch = await api(`/batches/${state.batch.batch_id}/execute`, {
        method: "POST",
        idempotent: false,
        body: { expected_version: state.batch.version, reason: reason.value },
      });
      reason.value = "";
      query("[data-batch-result]").textContent = `${state.batch.status} · 成功 ${state.batch.success_count} · 失败 ${state.batch.failure_count}`;
      showToast(`batch_${state.batch.status}`);
      state.selected.clear();
      query("[data-batch-execute]").hidden = true;
      await loadInbox();
    } catch (error) { query("[data-batch-reason]").value = ""; showToast(error.code); }
  });

  query("[data-clear-selection]").addEventListener("click", () => {
    state.selected.clear();
    state.batch = null;
    renderInbox();
  });

  const delegationDialog = query("[data-delegation-dialog]");
  query("[data-open-delegation]").addEventListener("click", () => {
    const now = new Date();
    const expiry = new Date(now.valueOf() + 60 * 60 * 1000);
    const local = (value) => new Date(value.valueOf() - value.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    query("[data-delegation-start]").value = local(now);
    query("[data-delegation-end]").value = local(expiry);
    delegationDialog.showModal();
    query("[data-delegation-work]").focus();
  });
  query("[data-close-dialog]").addEventListener("click", () => delegationDialog.close());
  query("[data-close-decision]").addEventListener("click", () => {
    query("[data-single-reason]").value = "";
    query("[data-decision-dialog]").close();
  });
  query("[data-delegation-form]").addEventListener("submit", async (event) => {
    event.preventDefault();
    const selected = query("[data-delegation-work]").selectedOptions[0];
    const reason = query("[data-delegation-reason]");
    try {
      await api("/delegations", {
        method: "POST",
        body: {
          work_item_id: selected.value,
          expected_version: Number(selected.dataset.version),
          delegate_id: query("[data-delegate-id]").value,
          starts_at: new Date(query("[data-delegation-start]").value).toISOString(),
          expires_at: new Date(query("[data-delegation-end]").value).toISOString(),
          reason: reason.value,
        },
      });
      reason.value = "";
      delegationDialog.close();
      showToast("approval_delegation_created");
      await loadDelegations();
    } catch (error) { reason.value = ""; query("[data-delegation-result]").textContent = error.code; }
  });

  if (realm === "staff") {
    const templateDialog = query("[data-template-dialog]");
    query("[data-open-template]").addEventListener("click", () => templateDialog.showModal());
    query("[data-close-template]").addEventListener("click", () => templateDialog.close());
    query("[data-template-form]").addEventListener("submit", async (event) => {
      event.preventDefault();
      const handle = query("[data-template-handle]");
      const contentSha = query("[data-template-sha]");
      const schemaSha = query("[data-template-schema-sha]");
      try {
        await api("/templates", {
          method: "POST",
          body: {
            tenant_id: null,
            template_key: query("[data-template-key]").value,
            channel: query("[data-template-channel]").value,
            locale: query("[data-template-locale]").value,
            version: Number(query("[data-template-version]").value),
            content_artifact_handle: handle.value,
            content_sha256: contentSha.value,
            variables_schema_sha256: schemaSha.value,
          },
        });
        handle.value = ""; contentSha.value = ""; schemaSha.value = "";
        templateDialog.close();
        showToast("template_version_published");
        await loadTemplates();
      } catch (error) {
        handle.value = ""; contentSha.value = ""; schemaSha.value = "";
        query("[data-template-result]").textContent = error.code;
      }
    });
  }

  queryAll("[data-panel-target]").forEach((button) => button.addEventListener("click", () => {
    queryAll("[data-panel-target]").forEach((candidate) => candidate.classList.toggle("is-active", candidate === button));
    queryAll("[data-panel]").forEach((panel) => {
      const visible = panel.dataset.panel === button.dataset.panelTarget;
      panel.hidden = !visible;
      panel.classList.toggle("is-visible", visible);
    });
  }));

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    for (const dialog of queryAll("dialog[open]")) dialog.close();
    query("[data-single-reason]").value = "";
  });

  Promise.allSettled([
    loadInbox(), loadDelegations(), loadDeliveries(), loadPreferences(), loadTemplates(),
  ])
    .then((results) => {
      const failed = results.find((result) => result.status === "rejected");
      if (failed) showToast(failed.reason && failed.reason.code ? failed.reason.code : "notification_load_failed");
      root.setAttribute("aria-busy", "false");
    });
})();
