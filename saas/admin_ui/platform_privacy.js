(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const STORAGE_KEY = "omnigent.platform.privacy.target";
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const state = {
    context: null,
    contextPromise: null,
    current: null,
    initialized: false,
    requestId: 0,
    controller: null,
  };

  function node(tag, className = "", text = "") {
    const value = document.createElement(tag);
    if (className) value.className = className;
    if (text !== "") value.textContent = String(text);
    return value;
  }

  function shortId(value) { return value ? String(value).slice(0, 8) : "—"; }

  function formatDate(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
  }

  function emptyRecord(message) { return node("div", "empty-record", message); }

  function statusChip(status) {
    const value = node("span", "status-chip", String(status || "unknown").toUpperCase());
    value.dataset.status = status || "unknown";
    return value;
  }

  function recordRow({ title, identifier, status, meta = [], action = null }) {
    const row = node("article", "record-row");
    const primary = node("div", "record-primary");
    primary.append(node("strong", "", title), node("code", "", identifier));
    const facts = node("div", "record-meta");
    facts.append(statusChip(status));
    meta.forEach((item) => facts.append(node("span", "", item)));
    const actions = node("div", "record-actions");
    if (action) actions.append(action);
    row.append(primary, facts, actions);
    return row;
  }

  async function request(path, options = {}) {
    const response = await fetch(path, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      ...options,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload.error || payload.detail || payload;
      const code = detail.code || `http_${response.status}`;
      const message = detail.message || "Request failed";
      throw new Error(`${code}: ${message}`);
    }
    return payload;
  }

  function setMessage(message = "", tone = "info") {
    const target = $("#privacy-message");
    target.textContent = message;
    target.dataset.tone = tone;
  }

  function setBusy(value) {
    $("#privacy-inspect").disabled = value;
    $("#privacy-target-form").setAttribute("aria-busy", String(value));
  }

  function clearResult(message = "NO TARGET BOUND") {
    state.current = null;
    $("#privacy-workbench").hidden = true;
    $("#privacy-empty").hidden = false;
    $("#privacy-empty span").textContent = message;
  }

  function targetPath(targetType, targetId) {
    return `/v2/platform-admin/privacy/${targetType}/${encodeURIComponent(targetId)}`;
  }

  function assertTarget(payload, targetType, targetId) {
    if (payload.target_type !== targetType || payload.target_id !== targetId) {
      throw new Error("platform_privacy_target_mismatch: response target changed");
    }
  }

  function storageEnvelope(targetType, targetId) {
    return {
      principalId: state.context.principal_id,
      policyVersion: state.context.policy_version,
      targetType,
      targetId,
    };
  }

  async function context() {
    if (!state.context) {
      if (!state.contextPromise) {
        state.contextPromise = request("/v2/platform-admin/context");
      }
      try {
        state.context = await state.contextPromise;
      } finally {
        state.contextPromise = null;
      }
    }
    if (!(state.context.permissions || []).includes("platform.privacy.read")) {
      throw new Error("platform_permission_denied: Privacy read permission is not assigned");
    }
    return state.context;
  }

  async function inspectTarget() {
    await context();
    const targetType = $("#privacy-target-type").value;
    const targetId = $("#privacy-target-id").value.trim().toLowerCase();
    if (!UUID.test(targetId)) {
      clearResult("INVALID TARGET");
      throw new Error("platform_privacy_invalid: exact UUID target required");
    }

    const requestId = ++state.requestId;
    if (state.controller) state.controller.abort();
    const controller = new AbortController();
    state.controller = controller;
    clearResult("READING AUTHORITY");
    setMessage(`READING ${targetType.toUpperCase()} / ${targetId}`);
    setBusy(true);
    const root = targetPath(targetType, targetId);
    try {
      const [preview, holds, manifests] = await Promise.all([
        request(`${root}/deletion-preview`, { signal: controller.signal }),
        request(`${root}/legal-holds?limit=50`, { signal: controller.signal }),
        request(`${root}/deletions?limit=50`, { signal: controller.signal }),
      ]);
      if (requestId !== state.requestId) return;
      assertTarget(preview, targetType, targetId);
      assertTarget(holds, targetType, targetId);
      assertTarget(manifests, targetType, targetId);
      state.current = {
        targetType,
        targetId,
        preview,
        holds: holds.items,
        holdCursor: holds.next_cursor,
        manifests: manifests.items,
        manifestCursor: manifests.next_cursor,
        selectedManifestId: manifests.items[0]?.manifest_id || null,
      };
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(storageEnvelope(targetType, targetId)));
      render();
      setMessage("AUTHORITATIVE READ COMPLETE");
    } catch (error) {
      if (error.name === "AbortError" || requestId !== state.requestId) return;
      clearResult("TARGET READ FAILED");
      sessionStorage.removeItem(STORAGE_KEY);
      setMessage(error.message, "error");
      throw error;
    } finally {
      if (requestId === state.requestId) setBusy(false);
    }
  }

  function surfaceTone(status) {
    if (status === "erased") return "success";
    if (["retained", "pending_retention"].includes(status)) return "retained";
    if (status === "pending") return "pending";
    return "failure";
  }

  function surfaceSummary(manifest) {
    const outcomes = Object.values(manifest?.surface_outcomes || {});
    return {
      total: outcomes.length,
      recorded: outcomes.filter((value) => value?.status !== "pending").length,
      retained: outcomes.filter((value) => ["retained", "pending_retention"].includes(value?.status)).length,
      failed: outcomes.filter((value) => surfaceTone(value?.status) === "failure").length,
    };
  }

  function render() {
    const current = state.current;
    if (!current) return;
    const { preview } = current;
    $("#privacy-empty").hidden = true;
    $("#privacy-workbench").hidden = false;
    $("#privacy-result-target").textContent = `TARGET / ${preview.target_type.toUpperCase()} / ${preview.target_id}`;
    $("#privacy-target-state").textContent = String(preview.target_status).toUpperCase();
    $("#privacy-target-version").textContent = `VERSION ${preview.target_version} · ${preview.target_type.toUpperCase()}`;
    $("#privacy-blocker-count").textContent = String(preview.blockers.length).padStart(2, "0");
    $("#privacy-target-blockers").textContent = preview.blockers.length ? preview.blockers.join(" · ") : "NO ACTIVE CONTROL-PLANE BLOCKERS";
    $("#privacy-hold-count").textContent = String(current.holds.filter((item) => item.status === "active").length).padStart(2, "0");
    $("#privacy-preview-hash").textContent = `HASH / ${preview.preview_hash}`;

    const impact = $("#privacy-impact-counts");
    impact.replaceChildren();
    Object.entries(preview.impact_counts).sort(([left], [right]) => left.localeCompare(right)).forEach(([name, count]) => {
      const row = node("div", "privacy-impact-row");
      row.append(node("span", "", name.replaceAll("_", " ").toUpperCase()), node("strong", "", count));
      impact.append(row);
    });
    if (!impact.childElementCount) impact.append(emptyRecord("NO DELETION IMPACT COUNTS"));
    renderHolds();
    renderManifests();
  }

  function renderHolds() {
    const current = state.current;
    const list = $("#privacy-holds-list");
    list.replaceChildren();
    if (!current.holds.length) list.append(emptyRecord("NO LEGAL HOLD HISTORY FOR THIS TARGET"));
    current.holds.forEach((item) => {
      const overdue = item.status === "active" && new Date(item.review_due_at).getTime() < Date.now();
      list.append(recordRow({
        title: overdue ? "REVIEW OVERDUE" : `${item.status} HOLD`,
        identifier: item.hold_id,
        status: overdue ? "overdue" : item.status,
        meta: [`scope ${item.scope.join(", ")}`, `authority ${item.authority_ref}`, `review ${formatDate(item.review_due_at)} · V${item.version}`],
      }));
    });
    $("#privacy-hold-page-state").textContent = `${current.holds.length} LOADED`;
    $("#privacy-holds-more").hidden = !current.holdCursor;
  }

  function manifestAction(item) {
    const action = node("button", "", "VIEW 15 SURFACES");
    action.type = "button";
    action.dataset.testid = `privacy-manifest-${item.manifest_id}`;
    action.addEventListener("click", () => {
      state.current.selectedManifestId = item.manifest_id;
      renderManifests();
    });
    return action;
  }

  function renderManifests() {
    const current = state.current;
    const list = $("#privacy-manifests-list");
    list.replaceChildren();
    $("#privacy-manifest-count").textContent = `${current.manifests.length} LOADED`;
    if (!current.manifests.length) list.append(emptyRecord("NO DELETION MANIFEST HISTORY FOR THIS TARGET"));
    current.manifests.forEach((item) => {
      const summary = surfaceSummary(item);
      const row = recordRow({
        title: `MANIFEST ${shortId(item.manifest_id)}`,
        identifier: item.manifest_id,
        status: item.status,
        meta: [`${summary.recorded}/${summary.total} receipts · ${summary.retained} retained · ${summary.failed} blocked`, `V${item.version} · ${formatDate(item.started_at)}`],
        action: manifestAction(item),
      });
      row.classList.toggle("selected", item.manifest_id === current.selectedManifestId);
      list.append(row);
    });
    $("#privacy-manifests-more").hidden = !current.manifestCursor;
    renderManifestDetail();
  }

  function renderManifestDetail() {
    const current = state.current;
    const selected = current.manifests.find((item) => item.manifest_id === current.selectedManifestId);
    $("#privacy-manifest-detail").hidden = !selected;
    if (!selected) {
      $("#privacy-surface-progress").textContent = "00/15";
      return;
    }
    const summary = surfaceSummary(selected);
    $("#privacy-surface-progress").textContent = `${String(summary.recorded).padStart(2, "0")}/${String(summary.total).padStart(2, "0")}`;
    $("#privacy-manifest-title").textContent = `${selected.status.toUpperCase()} / V${selected.version}`;
    $("#privacy-manifest-hash").textContent = selected.manifest_hash ? `MANIFEST HASH / ${selected.manifest_hash}` : "MANIFEST HASH / PENDING FINALIZATION";
    const grid = $("#privacy-surface-grid");
    grid.replaceChildren();
    Object.entries(selected.surface_outcomes).sort(([left], [right]) => left.localeCompare(right)).forEach(([surface, outcome], index) => {
      const status = outcome?.status || "unknown";
      const card = node("article", "privacy-surface-card");
      card.dataset.tone = surfaceTone(status);
      if (surface === "backups_and_snapshots") card.dataset.retention = "backup";
      const heading = node("div", "privacy-surface-heading");
      heading.append(node("span", "", String(index + 1).padStart(2, "0")), node("strong", "", surface.replaceAll("_", " ")));
      const facts = node("div", "privacy-surface-facts");
      facts.append(statusChip(status), node("span", "", String(outcome.disposition || "policy unavailable").toUpperCase()));
      if (outcome.remaining_item_count !== undefined) facts.append(node("span", "", `${outcome.remaining_item_count} ITEMS REMAIN`));
      if (outcome.retention_until) facts.append(node("span", "", `RETENTION UNTIL ${formatDate(outcome.retention_until)}`));
      if (outcome.key_id) facts.append(node("span", "", `KEY ${outcome.key_id}`));
      card.append(heading, facts);
      if (outcome.evidence_sha256) card.append(node("code", "", `EVIDENCE ${outcome.evidence_sha256}`));
      if (outcome.content_hash) card.append(node("code", "", `CONTENT ${outcome.content_hash}`));
      if (outcome.tombstone_sha256) card.append(node("code", "", `TOMBSTONE ${outcome.tombstone_sha256}`));
      grid.append(card);
    });
  }

  async function loadOlder(kind) {
    const current = state.current;
    if (!current) return;
    const isHolds = kind === "holds";
    const cursor = isHolds ? current.holdCursor : current.manifestCursor;
    if (!cursor) return;
    const button = isHolds ? $("#privacy-holds-more") : $("#privacy-manifests-more");
    button.disabled = true;
    const requestId = state.requestId;
    const root = targetPath(current.targetType, current.targetId);
    try {
      const page = await request(`${root}/${isHolds ? "legal-holds" : "deletions"}?limit=50&cursor=${encodeURIComponent(cursor)}`);
      if (requestId !== state.requestId || state.current !== current) return;
      assertTarget(page, current.targetType, current.targetId);
      if (isHolds) {
        const known = new Set(current.holds.map((item) => item.hold_id));
        current.holds.push(...page.items.filter((item) => !known.has(item.hold_id)));
        current.holdCursor = page.next_cursor;
        renderHolds();
      } else {
        const known = new Set(current.manifests.map((item) => item.manifest_id));
        current.manifests.push(...page.items.filter((item) => !known.has(item.manifest_id)));
        current.manifestCursor = page.next_cursor;
        renderManifests();
      }
    } catch (error) {
      setMessage(error.message, "error");
    } finally {
      button.disabled = false;
    }
  }

  async function load() {
    await context();
    if (state.initialized) return;
    state.initialized = true;
    clearResult();
    const saved = sessionStorage.getItem(STORAGE_KEY);
    if (!saved) return;
    try {
      const target = JSON.parse(saved);
      if (target.principalId !== state.context.principal_id || target.policyVersion !== state.context.policy_version || !["global_user", "tenant"].includes(target.targetType) || !UUID.test(target.targetId)) {
        throw new Error("stale target binding");
      }
      $("#privacy-target-type").value = target.targetType;
      $("#privacy-target-id").value = target.targetId;
      await inspectTarget();
    } catch {
      sessionStorage.removeItem(STORAGE_KEY);
      clearResult();
    }
  }

  $("#privacy-target-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void inspectTarget().catch((error) => setMessage(error.message, "error"));
  });
  $("#privacy-holds-more").addEventListener("click", () => void loadOlder("holds"));
  $("#privacy-manifests-more").addEventListener("click", () => void loadOlder("manifests"));
  $("#logout-button").addEventListener("click", () => sessionStorage.removeItem(STORAGE_KEY));
  window.OmnigentPrivacy = Object.freeze({ load });
})();
