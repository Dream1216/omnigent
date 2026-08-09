(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const STORAGE_KEY = "omnigent.platform.privacy.target";
  const CSRF_KEY = "omnigent.platform.csrf";
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const RESOURCE_CONFIG = Object.freeze({
    workItems: { path: "work-items", id: "work_item_id" },
    attempts: { path: "attempts", id: "attempt_id" },
    attestations: { path: "attestations", id: "attestation_id" },
    backups: { path: "backups", id: "backup_item_id" },
  });
  const state = {
    context: null,
    contextPromise: null,
    current: null,
    initialized: false,
    requestId: 0,
    resourceRequestId: 0,
    controller: null,
    command: null,
    commandTrigger: null,
  };

  function node(tag, className = "", text = "") {
    const value = document.createElement(tag);
    if (className) value.className = className;
    if (text !== "") value.textContent = String(text);
    return value;
  }

  function shortId(value) { return value ? String(value).slice(0, 8) : "—"; }

  function shortHash(value) {
    const text = String(value || "");
    return text.length > 24 ? `${text.slice(0, 12)}…${text.slice(-8)}` : text || "—";
  }

  function hashNode(label, value) {
    const result = node("code", "privacy-hash", `${label} / ${shortHash(value)}`);
    result.title = value || `${label} unavailable`;
    return result;
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

  function human(value) {
    return String(value || "unknown").replaceAll("_", " ").toUpperCase();
  }

  function emptyRecord(message) { return node("div", "empty-record", message); }

  function statusChip(status) {
    const value = node("span", "status-chip", human(status));
    value.dataset.status = status || "unknown";
    return value;
  }

  function actionButton(label, handler, { danger = false, disabled = false, testId = "", title = "" } = {}) {
    const button = node("button", danger ? "danger" : "", label);
    button.type = "button";
    if (testId) button.dataset.testid = testId;
    button.disabled = disabled;
    if (title) button.title = title;
    button.addEventListener("click", handler);
    return button;
  }

  function recordRow({ title, identifier, status, meta = [], actions = [], className = "" }) {
    const row = node("article", `record-row ${className}`.trim());
    const primary = node("div", "record-primary");
    primary.append(node("strong", "", title), node("code", "", identifier));
    const facts = node("div", "record-meta");
    facts.append(statusChip(status));
    meta.filter(Boolean).forEach((item) => facts.append(node("span", "", item)));
    const actionArea = node("div", "record-actions");
    actions.forEach((action) => actionArea.append(action));
    row.append(primary, facts, actionArea);
    return row;
  }

  function can(permission) {
    return Boolean(state.context?.permissions?.includes(permission));
  }

  function mutationReady(permission) {
    return can(permission) && Boolean(sessionStorage.getItem(CSRF_KEY));
  }

  function requestError(payload, status) {
    const detail = payload?.error || payload?.detail || payload;
    const code = detail?.code || `http_${status}`;
    const message = detail?.message || "Request failed";
    return new Error(`${code}: ${message}`);
  }

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    let body = options.body;
    if (body && typeof body !== "string") {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(body);
    }
    const method = (options.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      const csrf = sessionStorage.getItem(CSRF_KEY);
      if (!csrf) throw new Error("platform_csrf_unbound: reauthenticate Staff session");
      headers.set("X-CSRF-Token", csrf);
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

  function manifestPath(current, manifestId = current.selectedManifestId) {
    return `${targetPath(current.targetType, current.targetId)}/deletions/${encodeURIComponent(manifestId)}`;
  }

  function assertTarget(payload, targetType, targetId) {
    if (payload.target_type !== targetType || payload.target_id !== targetId) {
      throw new Error("platform_privacy_target_mismatch: response target changed");
    }
  }

  function assertManifestPage(payload, current, manifestId) {
    assertTarget(payload, current.targetType, current.targetId);
    if (payload.manifest_id !== manifestId || payload.content_access !== "none") {
      throw new Error("platform_privacy_manifest_mismatch: content-blind manifest binding changed");
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
      if (!state.contextPromise) state.contextPromise = request("/v2/platform-admin/context");
      try {
        state.context = await state.contextPromise;
      } finally {
        state.contextPromise = null;
      }
    }
    if (!can("platform.privacy.read")) {
      throw new Error("platform_permission_denied: Privacy read permission is not assigned");
    }
    return state.context;
  }

  function emptyResourceState() {
    return {
      workItems: [], attempts: [], attestations: [], backups: [],
      cursors: { workItems: null, attempts: null, attestations: null, backups: null },
      loaded: false,
    };
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
    setMessage(`BINDING ${targetType.toUpperCase()} / ${targetId}`);
    setBusy(true);
    const root = targetPath(targetType, targetId);
    try {
      const [preview, holds, manifests, operations] = await Promise.all([
        request(`${root}/deletion-preview`, { signal: controller.signal }),
        request(`${root}/legal-holds?limit=50`, { signal: controller.signal }),
        request(`${root}/deletions?limit=50`, { signal: controller.signal }),
        request(`${root}/operations?limit=50`, { signal: controller.signal }),
      ]);
      if (requestId !== state.requestId) return;
      [preview, holds, manifests, operations].forEach((payload) => assertTarget(payload, targetType, targetId));
      state.current = {
        targetType,
        targetId,
        preview,
        holds: holds.items,
        holdCursor: holds.next_cursor,
        manifests: manifests.items,
        manifestCursor: manifests.next_cursor,
        operations: operations.items,
        operationCursor: operations.next_cursor,
        selectedManifestId: manifests.items[0]?.manifest_id || null,
        resources: emptyResourceState(),
      };
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(storageEnvelope(targetType, targetId)));
      render();
      if (state.current.selectedManifestId) await loadSelectedResources();
      if (requestId !== state.requestId) return;
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
    if (["erased", "purged", "succeeded", "verified"].includes(status)) return "success";
    if (["retained", "pending_retention", "held"].includes(status)) return "retained";
    if (["pending", "leased", "retry", "retention_wait"].includes(status)) return "pending";
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
    $("#privacy-target-state").textContent = human(preview.target_status);
    $("#privacy-target-version").textContent = `VERSION ${preview.target_version} · ${preview.target_type.toUpperCase()}`;
    $("#privacy-blocker-count").textContent = String(preview.blockers.length).padStart(2, "0");
    $("#privacy-target-blockers").textContent = preview.blockers.length ? preview.blockers.join(" · ") : "NO ACTIVE CONTROL-PLANE BLOCKERS";
    $("#privacy-hold-count").textContent = String(current.holds.filter((item) => item.status === "active").length).padStart(2, "0");
    $("#privacy-preview-hash").textContent = `HASH / ${shortHash(preview.preview_hash)}`;
    $("#privacy-preview-hash").title = preview.preview_hash;

    const impact = $("#privacy-impact-counts");
    impact.replaceChildren();
    Object.entries(preview.impact_counts).sort(([left], [right]) => left.localeCompare(right)).forEach(([name, count]) => {
      const row = node("div", "privacy-impact-row");
      row.append(node("span", "", human(name)), node("strong", "", count));
      impact.append(row);
    });
    if (!impact.childElementCount) impact.append(emptyRecord("NO DELETION IMPACT COUNTS"));
    renderCommandAvailability();
    renderOperations();
    renderHolds();
    renderManifests();
  }

  function renderCommandAvailability() {
    const current = state.current;
    const requestDeletion = $("#privacy-request-deletion");
    const requestFinalize = $("#privacy-request-finalization");
    const mutationAllowed = mutationReady("platform.data_request.request");
    requestDeletion.hidden = !can("platform.data_request.request");
    requestFinalize.hidden = !can("platform.data_request.request");
    requestDeletion.disabled = !mutationAllowed || current.preview.blockers.length > 0;
    requestDeletion.title = !mutationAllowed
      ? "platform.data_request.request and a CSRF-bound Staff session are required"
      : current.preview.blockers.length ? "Authoritative preview has active blockers" : "Request a two-person deletion approval";
    requestFinalize.disabled = !mutationAllowed || !current.selectedManifestId;
    requestFinalize.title = !mutationAllowed
      ? "platform.data_request.request and a CSRF-bound Staff session are required"
      : !current.selectedManifestId ? "Select a deletion manifest first" : "Request independent finalization approval";
  }

  function operationActions(item) {
    if (item.status !== "pending_staff_approval") return [];
    if (item.requested_by_me || !can("platform.data_request.approve")) return [];
    const allowed = mutationReady("platform.data_request.approve");
    const reason = "platform.data_request.approve and a CSRF-bound Staff session are required";
    return [
      actionButton("APPROVE", (event) => openDecision(item, "approve", event.currentTarget), {
        disabled: !allowed,
        testId: `privacy-operation-approve-${item.operation_id}`,
        title: allowed ? "Approve and atomically execute this exact snapshot" : reason,
      }),
      actionButton("REJECT", (event) => openDecision(item, "reject", event.currentTarget), {
        danger: true,
        disabled: !allowed,
        testId: `privacy-operation-reject-${item.operation_id}`,
        title: allowed ? "Reject this exact snapshot" : reason,
      }),
    ];
  }

  function renderOperations() {
    const current = state.current;
    const list = $("#privacy-operation-list");
    list.replaceChildren();
    $("#privacy-operation-count").textContent = `${current.operations.length} OPERATIONS`;
    if (!current.operations.length) list.append(emptyRecord("NO GOVERNED OPERATIONS FOR THIS EXACT TARGET"));
    current.operations.forEach((item, index) => {
      const flags = [
        item.requested_by_me ? "REQUESTED BY YOU" : "INDEPENDENT REQUESTER",
        item.decision_recorded ? (item.decision_by_me ? "DECIDED BY YOU" : "DECISION RECORDED") : "AWAITING SECOND STAFF",
        `EXPIRES ${formatDate(item.expires_at)}`,
        `V${item.version}`,
      ];
      const row = recordRow({
        title: `${String(index + 1).padStart(2, "0")} / ${human(item.phase)}`,
        identifier: item.operation_id,
        status: item.status,
        meta: flags,
        actions: operationActions(item),
        className: "privacy-operation-row",
      });
      row.dataset.phase = item.phase;
      list.append(row);
    });
    $("#privacy-operations-more").hidden = !current.operationCursor;
  }

  function renderHolds() {
    const current = state.current;
    const list = $("#privacy-holds-list");
    list.replaceChildren();
    if (!current.holds.length) list.append(emptyRecord("NO LEGAL HOLD HISTORY FOR THIS TARGET"));
    current.holds.forEach((item) => {
      const overdue = item.status === "active" && new Date(item.review_due_at).getTime() < Date.now();
      list.append(recordRow({
        title: overdue ? "REVIEW OVERDUE" : `${human(item.status)} HOLD`,
        identifier: item.hold_id,
        status: overdue ? "overdue" : item.status,
        meta: [`SCOPE ${item.scope.join(", ")}`, `AUTHORITY ${item.authority_ref}`, `REVIEW ${formatDate(item.review_due_at)} · V${item.version}`],
      }));
    });
    $("#privacy-hold-page-state").textContent = `${current.holds.length} LOADED`;
    $("#privacy-holds-more").hidden = !current.holdCursor;
  }

  function manifestAction(item) {
    const action = node("button", "", "OPEN EVIDENCE BAY");
    action.type = "button";
    action.dataset.testid = `privacy-manifest-${item.manifest_id}`;
    action.setAttribute("aria-pressed", String(item.manifest_id === state.current.selectedManifestId));
    action.addEventListener("click", () => void selectManifest(item.manifest_id));
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
        meta: [`${summary.recorded}/${summary.total} SURFACES · ${summary.retained} RETAINED · ${summary.failed} BLOCKED`, `V${item.version} · ${formatDate(item.started_at)}`],
        actions: [manifestAction(item)],
      });
      row.classList.toggle("selected", item.manifest_id === current.selectedManifestId);
      list.append(row);
    });
    $("#privacy-manifests-more").hidden = !current.manifestCursor;
    renderManifestDetail();
  }

  async function selectManifest(manifestId) {
    const current = state.current;
    if (!current || current.selectedManifestId === manifestId && current.resources.loaded) return;
    current.selectedManifestId = manifestId;
    current.resources = emptyResourceState();
    renderCommandAvailability();
    renderManifests();
    await loadSelectedResources();
  }

  function selectedManifest() {
    const current = state.current;
    return current?.manifests.find((item) => item.manifest_id === current.selectedManifestId) || null;
  }

  function renderManifestDetail() {
    const current = state.current;
    const selected = selectedManifest();
    $("#privacy-manifest-detail").hidden = !selected;
    if (!selected) {
      $("#privacy-surface-progress").textContent = "00/15";
      $("#privacy-execution-note").textContent = "选择 Manifest 查看执行证据";
      return;
    }
    const summary = surfaceSummary(selected);
    $("#privacy-surface-progress").textContent = `${String(summary.recorded).padStart(2, "0")}/${String(summary.total).padStart(2, "0")}`;
    $("#privacy-manifest-title").textContent = `${human(selected.status)} / V${selected.version}`;
    $("#privacy-manifest-hash").textContent = selected.manifest_hash ? `MANIFEST HASH / ${shortHash(selected.manifest_hash)}` : "MANIFEST HASH / PENDING FINALIZATION";
    $("#privacy-manifest-hash").title = selected.manifest_hash || "Pending finalization";
    renderSurfaceProjection(selected);
    renderResources();
  }

  function renderSurfaceProjection(selected) {
    const grid = $("#privacy-surface-grid");
    grid.replaceChildren();
    Object.entries(selected.surface_outcomes).sort(([left], [right]) => left.localeCompare(right)).forEach(([surface, outcome], index) => {
      const status = outcome?.status || "unknown";
      const card = node("article", "privacy-surface-card");
      card.dataset.tone = surfaceTone(status);
      if (surface === "backups_and_snapshots") card.dataset.retention = "backup";
      const heading = node("div", "privacy-surface-heading");
      heading.append(node("span", "", String(index + 1).padStart(2, "0")), node("strong", "", human(surface)));
      const facts = node("div", "privacy-surface-facts");
      facts.append(statusChip(status), node("span", "", human(outcome.disposition || "policy unavailable")));
      if (outcome.remaining_item_count !== undefined) facts.append(node("span", "", `${outcome.remaining_item_count} ITEMS REMAIN`));
      if (outcome.retention_until) facts.append(node("span", "", `RETENTION ${formatDate(outcome.retention_until)}`));
      if (outcome.key_id) facts.append(node("span", "", `KEY ${outcome.key_id}`));
      card.append(heading, facts);
      if (outcome.evidence_sha256) card.append(hashNode("EVIDENCE", outcome.evidence_sha256));
      if (outcome.content_hash) card.append(hashNode("CONTENT", outcome.content_hash));
      if (outcome.tombstone_sha256) card.append(hashNode("TOMBSTONE", outcome.tombstone_sha256));
      grid.append(card);
    });
  }

  async function loadSelectedResources() {
    const current = state.current;
    const manifestId = current?.selectedManifestId;
    if (!current || !manifestId) return;
    const resourceRequestId = ++state.resourceRequestId;
    $("#privacy-resource-deck").setAttribute("aria-busy", "true");
    setMessage(`READING EXECUTION EVIDENCE / ${shortId(manifestId)}`);
    try {
      const pages = await Promise.all(Object.entries(RESOURCE_CONFIG).map(async ([kind, config]) => {
        const page = await request(`${manifestPath(current, manifestId)}/${config.path}?limit=100`, { signal: state.controller?.signal });
        assertManifestPage(page, current, manifestId);
        return [kind, page];
      }));
      if (state.current !== current || current.selectedManifestId !== manifestId || resourceRequestId !== state.resourceRequestId) return;
      pages.forEach(([kind, page]) => {
        current.resources[kind] = page.items;
        current.resources.cursors[kind] = page.next_cursor;
      });
      current.resources.loaded = true;
      renderResources();
    } catch (error) {
      if (error.name !== "AbortError" && state.current === current) setMessage(error.message, "error");
    } finally {
      if (resourceRequestId === state.resourceRequestId) $("#privacy-resource-deck").setAttribute("aria-busy", "false");
    }
  }

  function replayAction(kind, item) {
    if (item.status !== "dead_letter") return [];
    if (!can("platform.data_request.request")) return [];
    const allowed = mutationReady("platform.data_request.request");
    const label = kind === "backup" ? "REQUEST PURGE REPLAY" : "REQUEST DLQ REPLAY";
    return [actionButton(label, (event) => openReplay(kind, item, event.currentTarget), {
      disabled: !allowed,
      testId: `privacy-${kind}-replay-${kind === "backup" ? item.backup_item_id : item.work_item_id}`,
      title: allowed ? "Create an independently approved replay request" : "platform.data_request.request and CSRF binding required",
    })];
  }

  function renderWorkItems() {
    const resources = state.current.resources;
    const list = $("#privacy-work-items");
    list.replaceChildren();
    $("#privacy-work-count").textContent = `${resources.workItems.length} ITEMS`;
    if (!resources.workItems.length) list.append(emptyRecord(resources.loaded ? "NO EXECUTION WORK ITEMS" : "READING EXECUTOR QUEUE…"));
    resources.workItems.forEach((item) => {
      const hashes = item.last_error_sha256 ? `ERROR ${shortHash(item.last_error_sha256)}` : item.outcome_content_sha256 ? `OUTCOME ${shortHash(item.outcome_content_sha256)}` : "NO OUTCOME RECEIPT";
      list.append(recordRow({
        title: human(item.surface),
        identifier: item.work_item_id,
        status: item.status,
        meta: [`${item.attempt_count}/${item.max_attempts} ATTEMPTS · LEASE G${item.lease_generation} · REPLAY G${item.replay_generation}`, `${human(item.disposition)} · ${hashes}`, item.last_error_code ? `CODE ${item.last_error_code}` : `AVAILABLE ${formatDate(item.available_at)} · V${item.version}`],
        actions: replayAction("work", item),
        className: "privacy-resource-row",
      }));
    });
    $("#privacy-work-more").hidden = !resources.cursors.workItems;
  }

  function renderAttempts() {
    const resources = state.current.resources;
    const list = $("#privacy-attempts");
    list.replaceChildren();
    $("#privacy-attempt-count").textContent = `${resources.attempts.length} ATTEMPTS`;
    if (!resources.attempts.length) list.append(emptyRecord(resources.loaded ? "NO APPEND-ONLY ATTEMPTS" : "READING ATTEMPT LEDGER…"));
    resources.attempts.forEach((item) => {
      list.append(recordRow({
        title: `${human(item.surface)} / #${item.attempt_number}`,
        identifier: item.attempt_id,
        status: item.outcome,
        meta: [`LEASE G${item.lease_generation} · REPLAY G${item.replay_generation}`, item.error_code ? `ERROR ${item.error_code} · ${shortHash(item.error_sha256)}` : `EVIDENCE ${shortHash(item.evidence_payload_sha256)}`, `COMPLETED ${formatDate(item.completed_at)}`],
        className: "privacy-resource-row",
      }));
    });
    $("#privacy-attempt-more").hidden = !resources.cursors.attempts;
  }

  function renderBackups() {
    const resources = state.current.resources;
    const list = $("#privacy-backups");
    list.replaceChildren();
    $("#privacy-backup-count").textContent = `${resources.backups.length} OBJECTS`;
    if (!resources.backups.length) list.append(emptyRecord(resources.loaded ? "NO RETAINED BACKUP OBJECTS" : "READING BACKUP CATALOG…"));
    resources.backups.forEach((item) => {
      const lock = item.object_lock_until ? `LOCK ${formatDate(item.object_lock_until)}` : "NO OBJECT LOCK";
      list.append(recordRow({
        title: `${human(item.provider)} / ${human(item.backup_data_class)}`,
        identifier: item.backup_item_id,
        status: item.status,
        meta: [`PURGE DUE ${formatDate(item.purge_due_at)} · ${lock}`, `${item.attempt_count}/${item.max_attempts} ATTEMPTS · REPLAY G${item.replay_generation}`, item.purge_evidence_sha256 ? `PURGE EVIDENCE ${shortHash(item.purge_evidence_sha256)}` : item.last_error_code ? `ERROR ${item.last_error_code} · ${shortHash(item.last_error_sha256)}` : `CATALOG ${shortHash(item.catalog_snapshot_sha256)} · V${item.version}`],
        actions: replayAction("backup", item),
        className: "privacy-resource-row",
      }));
    });
    $("#privacy-backup-more").hidden = !resources.cursors.backups;
  }

  function renderAttestations() {
    const resources = state.current.resources;
    const list = $("#privacy-attestations");
    list.replaceChildren();
    $("#privacy-attestation-count").textContent = `${resources.attestations.length} ENVELOPES`;
    if (!resources.attestations.length) list.append(emptyRecord(resources.loaded ? "NO VERIFIED DSSE ENVELOPES" : "VERIFYING EVIDENCE INDEX…"));
    resources.attestations.forEach((item) => {
      const row = node("article", "privacy-attestation-card");
      const heading = node("div", "privacy-attestation-heading");
      const copy = node("div");
      copy.append(node("span", "", `${human(item.subject_kind)} / ${human(item.surface || "manifest")}`), node("strong", "", `${human(item.signature_algorithm)} VERIFIED`), node("code", "", item.attestation_id));
      heading.append(copy, statusChip("verified"));
      const proof = node("div", "privacy-proof-chain");
      [["PAYLOAD", item.payload_sha256], ["ENVELOPE", item.envelope_sha256], ["IMMUTABLE", item.immutability_receipt_sha256], ["KMS AUDIT", item.kms_audit_receipt_sha256]].forEach(([label, value]) => {
        const step = node("div");
        step.append(node("span", "", label), node("code", "", shortHash(value)));
        step.title = value;
        proof.append(step);
      });
      const revisions = node("p", "", `PRODUCT ${shortHash(item.product_revision)} · UPSTREAM ${shortHash(item.upstream_revision)} · SCHEMA ${item.schema_revision} · POLICY ${item.verifier_policy_version} · VERIFIED ${formatDate(item.verified_at)}`);
      row.append(heading, proof, revisions);
      list.append(row);
    });
    $("#privacy-attestation-more").hidden = !resources.cursors.attestations;
  }

  function setStage(id, status) {
    const value = $(`#privacy-stage-${id}`);
    value.dataset.status = status;
    value.setAttribute("aria-label", `${id} stage ${status}`);
  }

  function renderEvidenceStages() {
    const current = state.current;
    const selected = selectedManifest();
    const resources = current.resources;
    const startOperation = current.operations.find((item) => item.phase === "deletion_start" && item.manifest_id === selected.manifest_id);
    setStage("approval", startOperation?.status === "succeeded" ? "verified" : startOperation?.status === "pending_staff_approval" ? "pending" : "unverified");

    const workComplete = resources.workItems.length > 0 && resources.workItems.every((item) => item.status === "succeeded");
    const workFailed = resources.workItems.some((item) => item.status === "dead_letter");
    setStage("erasure", workComplete ? "verified" : workFailed ? "blocked" : "pending");

    const attestedSubjects = new Set(resources.attestations.filter((item) => ["surface", "backup"].includes(item.subject_kind)).map((item) => item.subject_id));
    const succeededSubjectIds = resources.workItems.filter((item) => item.status === "succeeded").map((item) => item.work_item_id);
    const dsseComplete = succeededSubjectIds.length > 0 && succeededSubjectIds.every((id) => attestedSubjects.has(id));
    setStage("dsse", dsseComplete ? "verified" : resources.attestations.length ? "partial" : "pending");

    const backupOutcome = selected.surface_outcomes?.backups_and_snapshots;
    const backupComplete = resources.backups.length
      ? resources.backups.every((item) => item.status === "purged")
      : backupOutcome?.status === "erased" && Number(backupOutcome?.remaining_item_count || 0) === 0;
    const backupBlocked = resources.backups.some((item) => ["dead_letter", "held"].includes(item.status));
    setStage("retention", backupComplete ? "verified" : backupBlocked ? "blocked" : "pending");

    const queued = resources.workItems.filter((item) => ["pending", "leased", "retry"].includes(item.status)).length;
    const dlq = resources.workItems.filter((item) => item.status === "dead_letter").length;
    const attemptsFailed = resources.attempts.filter((item) => item.outcome !== "succeeded").length;
    const backupsPending = resources.backups.filter((item) => item.status !== "purged").length;
    $("#privacy-work-summary").textContent = `${resources.workItems.filter((item) => item.status === "succeeded").length}/${resources.workItems.length}`;
    $("#privacy-attempt-summary").textContent = `${resources.attempts.length} · ${attemptsFailed}F`;
    $("#privacy-attestation-summary").textContent = String(resources.attestations.length).padStart(2, "0");
    $("#privacy-backup-summary").textContent = `${resources.backups.length - backupsPending}/${resources.backups.length}`;
    $("#privacy-execution-note").textContent = `${queued} ACTIVE · ${dlq} DLQ · ${resources.attestations.length} DSSE`;
  }

  function renderResources() {
    if (!state.current?.selectedManifestId) return;
    renderWorkItems();
    renderAttempts();
    renderBackups();
    renderAttestations();
    renderEvidenceStages();
  }

  async function loadMoreResource(kind) {
    const current = state.current;
    const config = RESOURCE_CONFIG[kind];
    const cursor = current?.resources.cursors[kind];
    if (!current || !config || !cursor || !current.selectedManifestId) return;
    const button = $(`[data-kind="${kind}"]`);
    button.disabled = true;
    const manifestId = current.selectedManifestId;
    try {
      const page = await request(`${manifestPath(current, manifestId)}/${config.path}?limit=100&cursor=${encodeURIComponent(cursor)}`);
      if (state.current !== current || current.selectedManifestId !== manifestId) return;
      assertManifestPage(page, current, manifestId);
      const known = new Set(current.resources[kind].map((item) => item[config.id]));
      current.resources[kind].push(...page.items.filter((item) => !known.has(item[config.id])));
      current.resources.cursors[kind] = page.next_cursor;
      renderResources();
    } catch (error) {
      setMessage(error.message, "error");
    } finally {
      button.disabled = false;
    }
  }

  async function loadOlder(kind) {
    const current = state.current;
    if (!current) return;
    const config = {
      holds: { cursor: "holdCursor", path: "legal-holds", items: "holds", id: "hold_id", render: renderHolds, button: "#privacy-holds-more" },
      manifests: { cursor: "manifestCursor", path: "deletions", items: "manifests", id: "manifest_id", render: renderManifests, button: "#privacy-manifests-more" },
      operations: { cursor: "operationCursor", path: "operations", items: "operations", id: "operation_id", render: renderOperations, button: "#privacy-operations-more" },
    }[kind];
    const cursor = config && current[config.cursor];
    if (!config || !cursor) return;
    const button = $(config.button);
    button.disabled = true;
    const requestId = state.requestId;
    try {
      const page = await request(`${targetPath(current.targetType, current.targetId)}/${config.path}?limit=50&cursor=${encodeURIComponent(cursor)}`);
      if (requestId !== state.requestId || state.current !== current) return;
      assertTarget(page, current.targetType, current.targetId);
      const known = new Set(current[config.items].map((item) => item[config.id]));
      current[config.items].push(...page.items.filter((item) => !known.has(item[config.id])));
      current[config.cursor] = page.next_cursor;
      config.render();
    } catch (error) {
      setMessage(error.message, "error");
    } finally {
      button.disabled = false;
    }
  }

  function setDialogMode(mode) {
    const isDecision = mode === "decision";
    $("#privacy-request-fields").hidden = isDecision;
    $("#privacy-decision-fields").hidden = !isDecision;
    $("#privacy-reason-code").disabled = isDecision;
    $("#privacy-case-reference").disabled = isDecision;
    $("#privacy-expires-at").disabled = isDecision;
    $("#privacy-decision-code").disabled = !isDecision;
  }

  function openCommand(command, trigger) {
    state.command = command;
    state.commandTrigger = trigger;
    setDialogMode(command.mode);
    $("#privacy-dialog-index").textContent = command.index;
    $("#privacy-dialog-title").textContent = command.title;
    $("#privacy-dialog-summary").textContent = command.summary;
    $("#privacy-dialog-fingerprint").textContent = shortHash(command.fingerprint);
    $("#privacy-dialog-fingerprint").title = command.fingerprint;
    $("#privacy-dialog-confirm").textContent = command.confirm;
    $("#privacy-dialog-confirm").classList.toggle("danger", command.decision === "reject");
    if (command.mode === "request") {
      $("#privacy-reason-code").value = command.reasonCode || "data_subject_request";
      $("#privacy-case-reference").value = "";
      $("#privacy-expires-at").value = localDateTime(Date.now() + 15 * 60_000);
    } else {
      $("#privacy-decision-code").value = command.decision === "approve"
        ? command.phase.includes("replay") ? "verified_replay" : "policy_confirmed"
        : "scope_rejected";
      $("#privacy-separation-copy").textContent = command.decision === "approve"
        ? "Approval will execute the exact bound snapshot in the same server transaction."
        : "Rejection records a terminal decision without executing the bound mutation.";
    }
    const dialog = $("#privacy-command-dialog");
    dialog.showModal();
    const first = command.mode === "request" ? $("#privacy-reason-code") : $("#privacy-decision-code");
    first.focus();
  }

  function openDeletionRequest(trigger) {
    const current = state.current;
    openCommand({
      mode: "request",
      kind: "deletion",
      index: "PRIVACY REQUEST / DELETION START",
      title: "Request exact deletion",
      summary: "Create an expiring, side-effect-free approval request bound to the current target version and preview hash.",
      fingerprint: current.preview.preview_hash,
      confirm: "REQUEST SECOND STAFF",
    }, trigger);
  }

  function openFinalizationRequest(trigger) {
    const selected = selectedManifest();
    if (!selected) return;
    openCommand({
      mode: "request",
      kind: "finalization",
      index: "PRIVACY REQUEST / FINALIZATION",
      title: "Request final attestation",
      summary: "Bind finalization to this manifest version. The server will reject incomplete work, missing DSSE, an active hold, or same-approver reuse.",
      fingerprint: selected.manifest_hash || selected.manifest_id,
      confirm: "REQUEST FINAL APPROVAL",
    }, trigger);
  }

  function openReplay(kind, item, trigger) {
    const selected = selectedManifest();
    const subjectId = kind === "backup" ? item.backup_item_id : item.work_item_id;
    openCommand({
      mode: "request",
      kind: kind === "backup" ? "backupReplay" : "workReplay",
      subject: item,
      reasonCode: "verified_operational_replay",
      index: `PRIVACY REQUEST / ${kind === "backup" ? "BACKUP PURGE" : "SURFACE DLQ"} REPLAY`,
      title: "Request controlled replay",
      summary: `Requeue only the selected dead-letter ${kind === "backup" ? "backup purge" : "surface work item"}; the approval snapshot includes its exact version and replay generation.`,
      fingerprint: `${selected.manifest_id}:${subjectId}:v${item.version}`,
      confirm: "REQUEST REPLAY APPROVAL",
    }, trigger);
  }

  function openDecision(operation, decision, trigger) {
    openCommand({
      mode: "decision",
      kind: "decision",
      operation,
      decision,
      phase: operation.phase,
      index: `PRIVACY DECISION / ${decision.toUpperCase()}`,
      title: `${decision === "approve" ? "Approve" : "Reject"} exact snapshot`,
      summary: `${human(operation.phase)} · version ${operation.version} · expires ${formatDate(operation.expires_at)}. Raw case content is intentionally unavailable.`,
      fingerprint: operation.snapshot_hash,
      confirm: decision === "approve" ? "APPROVE & EXECUTE" : "REJECT REQUEST",
    }, trigger);
  }

  function closeCommand() {
    const dialog = $("#privacy-command-dialog");
    if (dialog.open) dialog.close();
    const trigger = state.commandTrigger;
    state.command = null;
    state.commandTrigger = null;
    if (trigger?.isConnected) trigger.focus();
  }

  async function submitCommand() {
    const current = state.current;
    const command = state.command;
    if (!current || !command) return;
    const root = targetPath(current.targetType, current.targetId);
    let path;
    let body;
    let headers = {};
    if (command.mode === "decision") {
      path = `${root}/operations/${command.operation.operation_id}/decision`;
      headers = { "Idempotency-Key": idempotency(`privacy-${command.kind}`) };
      body = {
        expected_version: command.operation.version,
        decision: command.decision,
        decision_code: $("#privacy-decision-code").value,
      };
    } else {
      const common = {
        reason_code: $("#privacy-reason-code").value,
        case_reference: $("#privacy-case-reference").value.trim(),
        expires_at: new Date($("#privacy-expires-at").value).toISOString(),
      };
      headers = { "Idempotency-Key": idempotency(`privacy-${command.kind}`) };
      if (command.kind === "deletion") {
        path = `${root}/deletion-requests`;
        body = { ...common, expected_target_version: current.preview.target_version, preview_hash: current.preview.preview_hash };
      } else if (command.kind === "finalization") {
        const selected = selectedManifest();
        path = `${manifestPath(current)}/finalization-requests`;
        body = { ...common, expected_manifest_version: selected.version };
      } else if (command.kind === "workReplay") {
        path = `${manifestPath(current)}/work-items/${command.subject.work_item_id}/replay-requests`;
        body = { ...common, expected_version: command.subject.version };
      } else {
        path = `${manifestPath(current)}/backups/${command.subject.backup_item_id}/replay-requests`;
        body = { ...common, expected_version: command.subject.version };
      }
    }

    const confirm = $("#privacy-dialog-confirm");
    confirm.disabled = true;
    $("#privacy-command-form").setAttribute("aria-busy", "true");
    try {
      const result = await request(path, { method: "POST", headers, body });
      closeCommand();
      setMessage(`${human(result.phase)} / ${human(result.status)} / ${shortId(result.operation_id)}`, "success");
      await inspectTarget();
    } catch (error) {
      setMessage(error.message, "error");
    } finally {
      confirm.disabled = false;
      $("#privacy-command-form").setAttribute("aria-busy", "false");
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
  $("#privacy-operations-more").addEventListener("click", () => void loadOlder("operations"));
  document.querySelectorAll("[data-kind]").forEach((button) => button.addEventListener("click", () => void loadMoreResource(button.dataset.kind)));
  $("#privacy-request-deletion").addEventListener("click", (event) => openDeletionRequest(event.currentTarget));
  $("#privacy-request-finalization").addEventListener("click", (event) => openFinalizationRequest(event.currentTarget));
  $("#privacy-command-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void submitCommand();
  });
  $("#privacy-dialog-cancel").addEventListener("click", closeCommand);
  $("#privacy-dialog-close").addEventListener("click", closeCommand);
  $("#privacy-command-dialog").addEventListener("cancel", (event) => {
    event.preventDefault();
    closeCommand();
  });
  $("#logout-button").addEventListener("click", () => sessionStorage.removeItem(STORAGE_KEY));
  window.OmnigentPrivacy = Object.freeze({ load });
})();
