// Theme bootstrap, loaded as a classic (parser-blocking) script in <head> so it
// runs before first paint and no flash of the wrong theme can occur. Living in
// public/ as a same-origin external file lets the CSP drop 'unsafe-inline' from
// script-src (see contentSecurityPolicy in handler/handler.go).
(() => {
  try {
    const theme = localStorage.getItem("myoauth-theme");
    if (theme === "light" || theme === "dark") {
      document.documentElement.dataset.theme = theme;
    }
  } catch {}
})();
