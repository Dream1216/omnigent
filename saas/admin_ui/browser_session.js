(() => {
  "use strict";
  const key = "omnigent.saas.csrf";
  function read() {
    for (const name of ["localStorage", "sessionStorage"]) {
      try {
        const value = window[name].getItem(key);
        if (value !== null) return value;
      } catch (_) {}
    }
    return "";
  }
  function write(value) {
    let persisted = false;
    for (const name of ["localStorage", "sessionStorage"]) {
      try {
        window[name].setItem(key, value);
        persisted = true;
      } catch (_) {}
    }
    if (!persisted) throw new Error("Browser storage is unavailable");
  }
  async function configureLogin(form, message) {
    const fields = form.querySelector("fieldset");
    const link = form.querySelector("[data-central-login]");
    const target = location.pathname + location.search;
    link.href = `/saas/login?return_to=${encodeURIComponent(target)}`;
    try {
      const response = await fetch("/saas/auth/options", {
        credentials: "same-origin",
        cache: "no-store",
        signal: AbortSignal.timeout(10000),
      });
      const options = response.status === 404
        ? { mode: "legacy", password_enabled: true }
        : await response.json();
      if (response.status !== 404 && !response.ok) throw new Error();
      if (!["legacy", "dual", "casdoor"].includes(options.mode) ||
          options.password_enabled !== (options.mode !== "casdoor")) throw new Error();
      fields.hidden = !options.password_enabled;
      fields.disabled = !options.password_enabled;
      return options.password_enabled;
    } catch (_) {
      fields.disabled = true;
      message.textContent = "暂时无法获取登录方式，请刷新重试。";
      return false;
    }
  }
  window.OmnigentSaasSession = Object.freeze({
    read,
    write,
    clear: () => write(""),
    configureLogin,
  });
  window.addEventListener("storage", (event) => {
    if (event.key !== key) return;
    try {
      window.sessionStorage.setItem(key, event.newValue || "");
    } catch (_) {}
  });
})();
