(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const csrf = sessionStorage.getItem("omnigent.saas.csrf") || "";
  let current = null;

  function toast(message, tone = "info") {
    const item = document.createElement("div");
    item.className = "toast";
    item.dataset.tone = tone;
    item.textContent = message;
    $("#toasts").prepend(item);
    window.setTimeout(() => item.remove(), 7000);
  }

  async function api(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});
    let body = options.body;
    if (body && typeof body !== "string") {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(body);
    }
    if (method !== "GET" && method !== "HEAD") {
      if (!csrf) throw new Error("登录会话缺少 CSRF，请退出后重新登录");
      headers.set("X-CSRF-Token", csrf);
    }
    const response = await fetch(path, {
      credentials: "same-origin",
      ...options,
      method,
      headers,
      body,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload.error || payload.detail || {};
      throw new Error(
        `${detail.code || `http_${response.status}`}: ${detail.message || "请求失败"}`,
      );
    }
    return payload;
  }

  function models() {
    return [
      ...new Set(
        $("#models")
          .value.split("\n")
          .map((value) => value.trim())
          .filter(Boolean),
      ),
    ];
  }

  function updateModelSelects(values, selected) {
    for (const target of [$("#default-model"), $("#test-model")]) {
      target.replaceChildren(
        ...values.map((value) => {
          const option = document.createElement("option");
          option.value = value;
          option.textContent = value;
          option.selected = value === selected;
          return option;
        }),
      );
    }
  }

  function render(value) {
    current = value;
    const available = value.allowed_models?.length
      ? value.allowed_models
      : models();
    $("#enabled").checked = Boolean(value.enabled);
    $("#api-key").value = "";
    $("#models").value = available.join("\n");
    updateModelSelects(available, value.default_model || available[0]);
    $("#monthly-budget").value = String(
      (value.monthly_budget_microusd || 100000000) / 1000000,
    );
    $("#daily-tokens").value = String(
      value.per_tenant_daily_token_limit || 1000000,
    );
    $("#provider-state").textContent = String(
      value.state || "not_configured",
    ).toUpperCase();
    $("#provider-version").textContent = `VERSION ${value.version || 0}`;
    $("#state-card").dataset.state = value.state || "not_configured";
    $("#key-state").textContent = value.api_key_configured
      ? "KEY ENCRYPTED / PRESERVED"
      : "KEY REQUIRED";
    $("#verified-at").textContent = value.last_verified_at
      ? `${value.last_verified_model} / ${new Date(value.last_verified_at).toLocaleString()}`
      : "WAITING FOR VERIFIED CONFIG";
  }

  async function load() {
    const [context, configuration] = await Promise.all([
      api("/saas/admin/platform-model-provider/context"),
      api("/saas/admin/platform-model-provider/configuration"),
    ]);
    if (context.realm !== "single_owner_beta_tenant_bridge")
      throw new Error("治理边界不匹配");
    render(configuration);
    $("#shell").setAttribute("aria-busy", "false");
  }

  async function save(event) {
    event.preventDefault();
    const selectedModels = models();
    if (
      !selectedModels.length ||
      !selectedModels.includes($("#default-model").value)
    ) {
      throw new Error("默认模型必须在允许目录中");
    }
    const key = $("#api-key").value;
    return api("/saas/admin/platform-model-provider/configuration", {
      method: "PUT",
      body: {
        expected_version: current?.version || 0,
        enabled: $("#enabled").checked,
        base_url: "https://api.deepseek.com",
        api_type: "openai_chat_completions",
        api_key: key || null,
        allowed_models: selectedModels,
        default_model: $("#default-model").value,
        monthly_budget_microusd: Math.round(
          Number($("#monthly-budget").value) * 1000000,
        ),
        per_tenant_daily_token_limit: Number($("#daily-tokens").value),
      },
    });
  }

  async function verify() {
    return api("/saas/admin/platform-model-provider/test", {
      method: "POST",
      body: {
        expected_version: current.version,
        model: $("#test-model").value,
      },
    });
  }

  $("#models").addEventListener("change", () =>
    updateModelSelects(models(), $("#default-model").value),
  );
  $("#configuration-form").addEventListener("submit", (event) => {
    $("#save").disabled = true;
    save(event)
      .then((value) => {
        render(value);
        toast("加密配置已保存，下一步执行真实流式验证", "success");
      })
      .catch((error) => toast(error.message, "error"))
      .finally(() => {
        $("#save").disabled = false;
      });
  });
  $("#test").addEventListener("click", () => {
    $("#test").disabled = true;
    verify()
      .then((value) => {
        render(value);
        toast("DeepSeek 真实流式验证通过", "success");
      })
      .catch((error) => toast(error.message, "error"))
      .finally(() => {
        $("#test").disabled = false;
      });
  });
  load().catch((error) => toast(error.message, "error"));
})();
