(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const state = {
    csrf: sessionStorage.getItem("omnigent.saas.csrf") || "",
    actorId: "",
    tenantId: "",
    spaceId: "",
    projects: [],
    selectedProject: null,
  };

  const loginDeck = $("#login-deck");
  const workspace = $("#workspace");
  const eventLog = $("#event-log");

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
    sessionStorage.removeItem("omnigent.saas.csrf");
    loginDeck.hidden = false;
    workspace.hidden = true;
    $("#logout-button").hidden = true;
    document.querySelector(".system-state").classList.remove("connected");
    $("#context-state").textContent = "NO CONTEXT";
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
  }

  async function loadCatalog() {
    const catalog = await api("/admin/permissions");
    $("#permission-count").textContent = `${catalog.permissions.length} / ${catalog.policy_version}`;
  }

  async function loadProjects() {
    state.projects = await api(scopePath("/projects"));
    if (state.selectedProject) {
      state.selectedProject = state.projects.find((item) => item.project_id === state.selectedProject.project_id) || null;
    }
    renderProjects();
    log(`Loaded ${state.projects.length} visible Project(s)`, "success");
  }

  function showFailure(element, error) {
    element.textContent = error.message;
    element.classList.add("shake");
    window.setTimeout(() => element.classList.remove("shake"), 600);
    log(error.message, "error");
  }

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
      await loadCatalog();
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
    state.tenantId = $("#tenant-id").value.trim();
    state.spaceId = $("#space-id").value.trim();
    try {
      await loadProjects();
      document.querySelector(".system-state").classList.add("connected");
      $("#context-state").textContent = `SPACE / ${state.spaceId.slice(0, 8)}`;
      const url = new URL(window.location.href);
      url.searchParams.set("tenant", state.tenantId);
      url.searchParams.set("space", state.spaceId);
      history.replaceState({}, "", url);
    } catch (error) {
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
    const params = new URLSearchParams(window.location.search);
    $("#tenant-id").value = params.get("tenant") || "";
    $("#space-id").value = params.get("space") || "";
    try {
      const current = await api("/auth/status");
      if (current.authenticated) {
        setAuthenticated(current.user_id);
        await loadCatalog();
        return;
      }
    } catch (error) {
      log(error.message, "error");
    }
    setLoggedOut();
  }

  boot();
})();
