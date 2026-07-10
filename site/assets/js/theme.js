// Pre-paint theme: applies the stored theme before first render so the page
// never flashes the wrong palette. Loaded synchronously in <head> (see
// head.html) so it runs before the body paints. Kept as an external file — not
// an inline <script> — so the page's Content-Security-Policy can drop
// script-src 'unsafe-inline' entirely. Default is 'auto' (follow OS); the user
// can override via the toggle, which writes 'light' or 'dark' to localStorage.
(function () {
  try {
    var v = localStorage.getItem('feedTheme');
    var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    var dark = (v === 'dark') || ((v === null || v === 'auto') && prefersDark);
    if (dark) document.documentElement.classList.add('dark');
  } catch (_) { /* ignore */ }
})();
