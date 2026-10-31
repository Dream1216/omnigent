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
  window.OmnigentSaasSession = Object.freeze({
    read,
    write,
    clear: () => write(""),
  });
  window.addEventListener("storage", (event) => {
    if (event.key !== key) return;
    try {
      window.sessionStorage.setItem(key, event.newValue || "");
    } catch (_) {}
  });
})();
