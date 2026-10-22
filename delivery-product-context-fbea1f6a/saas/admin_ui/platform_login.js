(() => {
  "use strict";

  const form = document.querySelector("#staff-login-form");
  const username = document.querySelector("#staff-username");
  const password = document.querySelector("#staff-password");
  const errorMessage = document.querySelector("#staff-login-error");
  const submit = document.querySelector("#staff-login-submit");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    submit.disabled = true;
    form.setAttribute("aria-busy", "true");
    errorMessage.textContent = "";
    try {
      const response = await fetch("/v2/platform-admin/session/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.value, password: password.value }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const message = payload?.error?.message || "登录失败，请检查用户名和密码。";
        throw new Error(message);
      }
      sessionStorage.setItem("omnigent.platform.csrf", payload.csrf_token);
      password.value = "";
      window.location.assign("/platform-admin");
    } catch (error) {
      password.value = "";
      errorMessage.textContent = error instanceof Error ? error.message : "登录失败，请重试。";
      password.focus();
    } finally {
      submit.disabled = false;
      form.removeAttribute("aria-busy");
    }
  });
})();
