(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const state = {
    projects: [],
    runs: [],
    project: null,
    overview: null,
    busy: false,
    preview: null,
    epoch: 0,
  };
  const names = {
    snapshot: "准备源码",
    build: "构建中",
    release: "预览发布中",
    ready: "已就绪",
    failed: "失败",
    cancelled: "已取消",
    requested: "等待执行",
    queued: "排队中",
    superseding: "已被替换",
    superseded: "已被替换",
    reconciling: "部署中",
    waiting_capacity: "等待可用资源",
    artifact_verifying: "验证构建产物",
    awaiting_approval: "等待发布审批",
    committing: "提交发布配置",
    analyzing: "检查发布效果",
    retrying: "正在重试",
    cancelling: "正在取消",
    rolling_back: "回滚中",
    rolled_back: "已回滚",
  };
  const csrf = () => sessionStorage.getItem("omnigent.saas.csrf") || "";
  const short = (id) => (id || "—").slice(0, 12);
  const date = (value) =>
    new Date(value).toLocaleString("zh-CN", { hour12: false });
  function message(text, error = false) {
    $("message").textContent = text;
    $("message").className = error ? "error" : "";
  }
  async function api(path, options = {}) {
    const headers = new Headers(options.headers);
    if (options.body) headers.set("Content-Type", "application/json");
    if (options.method && options.method !== "GET")
      headers.set("X-CSRF-Token", csrf());
    const response = await fetch(`/saas${path}`, {
      ...options,
      headers,
      credentials: "same-origin",
      cache: "no-store",
    });
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error("服务暂时不可用，请刷新重试。");
    }
    if (!response.ok) {
      if (response.status === 401) {
        $("login").hidden = false;
        $("workspace").hidden = true;
        state.project = null;
      }
      const detail = payload.detail || payload.error || {};
      const code = detail.code || `HTTP ${response.status}`;
      throw new Error(
        {
          delivery_not_configured: "交付服务尚未配置。",
          delivery_scope_unavailable: "当前账号无权访问此项目。",
          preview_endpoint_unavailable: "预览已部署，访问域名尚未就绪。",
          preview_endpoint_stale: "预览域名已指向其他版本，请刷新后重试。",
          DCP_ACTIVE_RELEASE_CONFLICT: "生产版本已变化，请刷新后重新选择。",
          DCP_AUTHORIZATION_DENIED: "当前权限或发布授权不允许此操作。",
        }[code] || `操作未完成：${code}`,
      );
    }
    return payload;
  }
  function option(select, value, text) {
    const item = document.createElement("option");
    item.value = value;
    item.textContent = text;
    select.append(item);
  }
  function projectPath() {
    return `/delivery/projects/${state.project.id}`;
  }
  function currentRelease() {
    return state.overview?.releases.find(
      (r) => r.environment_id === state.project.production_environment,
    );
  }
  function generation() {
    return Math.max(
      0,
      ...state.overview.releases
        .filter(
          (r) => r.environment_id === state.project.production_environment,
        )
        .map((r) => r.target_generation),
    );
  }
  function controlState() {
    const project = state.project;
    $("context-row").hidden = !$("snapshot").value.startsWith("run:");
    $("project").disabled = state.busy;
    $("build-submit").disabled =
      state.busy || !project?.actions.build || !$("snapshot").value;
    $("rollback").disabled =
      state.busy ||
      !project?.actions.rollback ||
      !$("rollback-target").value ||
      !["ready", "failed"].includes(currentRelease()?.status);
    $("start-preview").disabled = state.busy || !$("run").value;
  }
  async function command(path, body) {
    const storageKey = `omnigent.delivery.command:${state.project.id}:${path}:${JSON.stringify(body)}`;
    let key = sessionStorage.getItem(storageKey);
    if (!key) {
      key = crypto.randomUUID();
      sessionStorage.setItem(storageKey, key);
    }
    const result = await api(path, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Idempotency-Key": key },
    });
    sessionStorage.removeItem(storageKey);
    return result;
  }
  async function perform(action) {
    if (state.busy) return;
    state.busy = true;
    controlState();
    try {
      await action();
    } catch (error) {
      message(error.message, true);
    } finally {
      state.busy = false;
      controlState();
    }
  }
  function confirm(title, text) {
    return new Promise((resolve) => {
      $("confirm-title").textContent = title;
      $("confirm-text").textContent = text;
      $("confirm").returnValue = "cancel";
      $("confirm").showModal();
      $("confirm").addEventListener(
        "close",
        () => resolve($("confirm").returnValue === "accept"),
        { once: true },
      );
    });
  }
  function button(text, action, enabled = true) {
    const node = document.createElement("button");
    node.type = "button";
    node.textContent = text;
    node.className = "secondary";
    node.disabled = !enabled;
    node.addEventListener("click", () => perform(action));
    return node;
  }
  function render() {
    const data = state.overview;
    const selectedSnapshot = $("snapshot").value;
    $("snapshot").replaceChildren();
    state.runs.forEach((run) =>
      option(
        $("snapshot"),
        `run:${run.id}`,
        `会话检查点 · ${date(run.created_at)} · ${short(run.id)}`,
      ),
    );
    data.snapshots.forEach((s) =>
      option($("snapshot"), s.id, `${date(s.created_at)} · ${short(s.id)}`),
    );
    if ([...$("snapshot").options].some((s) => s.value === selectedSnapshot))
      $("snapshot").value = selectedSnapshot;
    $("source-note").textContent = state.runs.length
      ? "会话来源将读取已完成 Run 的校验检查点，并自动导出构建源码。"
      : data.snapshots.length
        ? "快照经过校验；构建不会读取仍在修改的工作目录。"
        : "当前项目没有已验证的源码快照。请先完成源码导出。";
    const current = currentRelease();
    $("production").replaceChildren();
    if (current) {
      const status = document.createElement("span");
      status.className = `badge ${current.status}`;
      status.textContent = names[current.status] || current.status;
      const code = document.createElement("code");
      code.textContent = current.artifact_ref;
      const info = document.createElement("small");
      info.textContent = `版本 ${short(current.id)} · ${date(current.created_at)}`;
      $("production").append(status, code, info);
    } else $("production").textContent = "尚未发布生产版本。";
    const chosenTarget = $("rollback-target").value;
    $("rollback-target").replaceChildren();
    option($("rollback-target"), "", "选择一个历史版本");
    data.history
      .filter(
        (r) =>
          current &&
          r.environment_id === current.environment_id &&
          r.created_at < current.created_at,
      )
      .forEach((r) =>
        option(
          $("rollback-target"),
          r.id,
          `${date(r.created_at)} · ${short(r.id)} · ${short(r.artifact_ref.split("@sha256:")[1])}`,
        ),
      );
    if ([...$("rollback-target").options].some((o) => o.value === chosenTarget))
      $("rollback-target").value = chosenTarget;
    $("deliveries").replaceChildren();
    $("empty").hidden = data.deliveries.length > 0;
    data.deliveries.forEach((delivery) => {
      const row = document.createElement("tr");
      row.dataset.deliveryId = delivery.id;
      const time = document.createElement("td");
      time.textContent = date(delivery.created_at);
      const id = document.createElement("small");
      id.textContent = short(delivery.id);
      time.append(id);
      const status = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `badge ${delivery.status}`;
      badge.textContent = names[delivery.status] || delivery.status;
      status.append(badge);
      if (delivery.error_code) {
        const error = document.createElement("small");
        error.textContent = delivery.error_code;
        status.append(error);
      }
      const version = document.createElement("td");
      const release = data.releases.find((r) => r.id === delivery.release_id);
      const code = document.createElement("code");
      code.textContent = release
        ? release.artifact_ref
        : delivery.build_id
          ? `构建 ${short(delivery.build_id)}`
          : "等待构建";
      version.append(code);
      const actions = document.createElement("td");
      const build = data.builds.find((b) => b.id === delivery.build_id);
      if (["snapshot", "build"].includes(delivery.status)) {
        if (delivery.cancel_requested || build?.cancel_requested)
          badge.textContent = "正在取消构建";
        actions.append(
          button(
            "取消构建",
            async () => {
              await command(
                `${projectPath()}/deliveries/${delivery.id}/cancel`,
                {
                  expected_version: delivery.aggregate_version,
                },
              );
              message("已请求取消，正在等待构建服务确认停止。");
              await refresh();
            },
            state.project.actions.build &&
              !delivery.cancel_requested &&
              !build?.cancel_requested,
          ),
        );
      }
      if (delivery.preview_id)
        actions.append(
          button(
            "查看预览",
            async () => {
              const result = await api(
                `${projectPath()}/previews/${delivery.preview_id}/open`,
              );
              $("release-preview-link").href = result.url;
              $("release-preview").showModal();
            },
            delivery.status === "ready",
          ),
        );
      if (release?.status === "ready")
        actions.append(
          button(
            "发布生产",
            async () => {
              if (
                !(await confirm(
                  "发布到生产",
                  `将版本 ${short(release.id)} 发布到生产。制品：${release.artifact_ref}`,
                ))
              )
                return;
              await command(`${projectPath()}/releases/${release.id}/promote`, {
                expected_target_generation: generation(),
              });
              message("生产发布已受理，正在等待部署完成。");
              await refresh();
            },
            state.project.actions.publish,
          ),
        );
      if (["failed", "cancelled"].includes(delivery.status))
        actions.append(
          button(
            "重新构建",
            async () => {
              await command(`${projectPath()}/build`, {
                snapshot_id: delivery.spec.snapshot_id,
                mode: delivery.spec.mode,
                dockerfile_path: delivery.spec.dockerfile_path,
                service_port: delivery.spec.service_port,
                health_path: delivery.spec.health_path,
              });
              message("新的构建已受理，原失败记录已保留。");
              await refresh();
            },
            state.project.actions.build,
          ),
        );
      row.append(time, status, version, actions);
      $("deliveries").append(row);
    });
    controlState();
    $("updated").textContent =
      `更新于 ${new Date().toLocaleTimeString("zh-CN")}`;
  }
  async function refresh() {
    if (!state.project) return;
    const epoch = state.epoch;
    const data = await api(projectPath());
    if (epoch !== state.epoch) return;
    state.overview = data;
    render();
  }
  async function selectProject() {
    state.epoch += 1;
    state.project = state.projects.find((p) => p.id === $("project").value);
    state.overview = null;
    const sessionId = new URLSearchParams(location.search).get("session_id");
    const scopeRuns = sessionId
      ? (
          await api(`/delivery/sessions/${encodeURIComponent(sessionId)}`)
        ).runs.filter((r) => r.project_id === state.project.id)
      : await api(`${projectPath()}/runs`);
    state.runs = scopeRuns;
    state.preview = sessionStorage.getItem(
      `omnigent.delivery.preview:${state.project.id}`,
    );
    $("live-link").hidden = true;
    $("live-status").textContent = "";
    $("stop-preview").disabled = !state.preview;
    await refresh();
    if (!$("live-preview").hidden) {
      const epoch = state.epoch;
      const runs = await api(`${projectPath()}/runs`);
      if (epoch !== state.epoch) return;
      $("run").replaceChildren();
      runs.forEach((run) =>
        option($("run"), run.id, `${date(run.created_at)} · ${short(run.id)}`),
      );
      controlState();
      await pollPreview();
    }
  }
  async function load() {
    if (!csrf()) {
      $("login").hidden = false;
      $("workspace").hidden = true;
      message("请登录以查看项目并启用交付操作。");
      return;
    }
    const info = await api("/delivery/projects");
    state.projects = info.projects;
    $("login").hidden = true;
    $("workspace").hidden = !info.projects.length;
    $("project").replaceChildren();
    if (!info.projects.length) {
      message(
        info.configured
          ? "当前账号没有可访问的交付项目。"
          : "交付服务尚未配置。",
        true,
      );
      return;
    }
    info.projects.forEach((p) => option($("project"), p.id, p.name));
    const sessionId = new URLSearchParams(location.search).get("session_id");
    if (sessionId) {
      const session = await api(
        `/delivery/sessions/${encodeURIComponent(sessionId)}`,
      );
      if (session.runs.length) $("project").value = session.runs[0].project_id;
    }
    $("live-preview").hidden = !info.live_preview_enabled;
    await selectProject();
  }
  function previewBase() {
    const p = state.project;
    return `/tenants/${p.tenant_id}/spaces/${p.space_id}/projects/${p.id}/previews`;
  }
  async function pollPreview() {
    if (!state.preview || !state.project) return;
    const epoch = state.epoch;
    const result = await api(`${previewBase()}/${state.preview}`);
    if (epoch !== state.epoch) return;
    $("live-status").textContent =
      `运行预览：${names[result.status] || result.status}`;
    $("live-link").hidden = !result.url;
    if (result.url) $("live-link").href = result.url;
    $("stop-preview").disabled = ["stopped", "expired", "failed"].includes(
      result.status,
    );
  }
  $("login").addEventListener("submit", (event) => {
    event.preventDefault();
    perform(async () => {
      const result = await api("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: $("email").value,
          password: $("password").value,
        }),
      });
      $("password").value = "";
      sessionStorage.setItem("omnigent.saas.csrf", result.csrf_token);
      message("");
      await load();
    });
  });
  $("project").addEventListener("change", () => perform(selectProject));
  $("refresh").addEventListener("click", () => perform(refresh));
  $("snapshot").addEventListener("change", controlState);
  $("rollback-target").addEventListener("change", controlState);
  $("run").addEventListener("change", controlState);
  $("build").addEventListener("submit", (event) => {
    event.preventDefault();
    perform(async () => {
      const source = $("snapshot").value;
      const fromRun = source.startsWith("run:");
      await command(
        `${projectPath()}/${fromRun ? "build-from-run" : "build"}`,
        {
          ...(fromRun
            ? { run_id: source.slice(4), context_path: $("context-path").value }
            : { snapshot_id: source }),
          mode: $("mode").value,
          dockerfile_path: $("dockerfile").value,
          service_port: Number($("port").value),
          health_path: $("health").value,
        },
      );
      message("构建已受理，完成后会自动发布预览。");
      await refresh();
    });
  });
  $("rollback").addEventListener("click", () =>
    perform(async () => {
      const current = currentRelease();
      const target = $("rollback-target").value;
      if (!current || !target) return;
      if (
        !(await confirm(
          "回滚生产版本",
          `将生产版本 ${short(current.id)} 回滚到所选历史版本 ${short(target)}。`,
        ))
      )
        return;
      await command(`${projectPath()}/releases/${current.id}/rollback`, {
        target_release_id: target,
        expected_target_generation: generation(),
      });
      message("回滚已受理，正在等待所选历史版本部署完成。");
      await refresh();
    }),
  );
  $("start-preview").addEventListener("click", () =>
    perform(async () => {
      const result = await command(previewBase(), {
        run_id: $("run").value,
        preview_kind: "static_web_v1",
      });
      state.preview = result.preview_id;
      sessionStorage.setItem(
        `omnigent.delivery.preview:${state.project.id}`,
        state.preview,
      );
      await pollPreview();
    }),
  );
  $("stop-preview").addEventListener("click", () =>
    perform(async () => {
      await api(`${previewBase()}/${state.preview}`, {
        method: "DELETE",
        headers: { "Idempotency-Key": crypto.randomUUID() },
      });
      await pollPreview();
    }),
  );
  async function poll() {
    if (!document.hidden && state.project && !state.busy) {
      try {
        await refresh();
        await pollPreview();
      } catch (error) {
        message(error.message, true);
      }
    }
    setTimeout(poll, 5000);
  }
  load().catch((error) => message(error.message, true));
  setTimeout(poll, 5000);
})();
