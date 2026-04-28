// Theme toggle + Pagefind search + date filter + mobile menu wiring.
// Default mode is 'auto' (follow OS); the toggle cycles auto → light → dark.

const THEME_KEY = 'feedTheme'; // 'light' | 'dark' | 'auto'

function getStoredTheme() {
  try {
    const v = localStorage.getItem(THEME_KEY);
    if (v === 'light' || v === 'dark' || v === 'auto') return v;
  } catch (_) { /* localStorage may be unavailable */ }
  return 'auto';
}

function setStoredTheme(value) {
  try { localStorage.setItem(THEME_KEY, value); } catch (_) {}
}

function systemPrefersDark() {
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function effectiveMode(stored) {
  return stored === 'auto' ? (systemPrefersDark() ? 'dark' : 'light') : stored;
}

function applyTheme(stored) {
  const mode = effectiveMode(stored);
  document.documentElement.classList.toggle('dark', mode === 'dark');
  document.documentElement.dataset.themeLoaded = '1';
  document.querySelectorAll('[data-theme-state]').forEach((el) => {
    el.dataset.themeState = stored;
    el.setAttribute('aria-pressed', mode === 'dark' ? 'true' : 'false');
    const label = el.querySelector('[data-theme-label]');
    if (label) label.textContent = stored === 'auto' ? 'Auto' : (mode === 'dark' ? 'Dark' : 'Light');
  });
}

function cycleTheme() {
  const order = ['auto', 'light', 'dark'];
  const next = order[(order.indexOf(getStoredTheme()) + 1) % order.length];
  setStoredTheme(next);
  applyTheme(next);
}

function initThemeToggle() {
  applyTheme(getStoredTheme());

  document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
    btn.addEventListener('click', cycleTheme);
  });

  // React to OS theme change only when user is on 'auto'.
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = () => { if (getStoredTheme() === 'auto') applyTheme('auto'); };
    if (mq.addEventListener) mq.addEventListener('change', handler);
    else if (mq.addListener) mq.addListener(handler);
  }
}

// ----------------------------------------------------------------------
// Pagefind search

function initSearch() {
  const container = document.getElementById('search-ui');
  if (!container) return;

  // Pagefind UI is loaded as a regular <script> in head.html; the tag self-removes
  // if /pagefind/pagefind-ui.js doesn't exist (no built index yet).
  // After DOMContentLoaded the deferred script has executed, so window.PagefindUI
  // is either defined (built) or absent (skip search wiring).
  if (typeof window.PagefindUI === 'undefined') {
    container.innerHTML = '<p class="px-4 py-3 text-sm text-muted">Search index missing. Run <code class="font-mono">make build</code> (or <code class="font-mono">make dev</code>) to generate it.</p>';
    return;
  }

  new window.PagefindUI({
    element: '#search-ui',
    showImages: false,
    showSubResults: true,
    resetStyles: false,
    excerptLength: 24,
    processTerm: (term) => term.toLowerCase(),
    translations: {
      placeholder: 'Search threats, actors, MITRE techniques…',
      clear_search: 'Clear',
      load_more: 'Load more',
      search_label: 'Search',
      filters_label: 'Filters',
      zero_results: 'No briefs match "[SEARCH_TERM]"',
      many_results: '[COUNT] briefs match "[SEARCH_TERM]"',
      one_result: '1 brief matches "[SEARCH_TERM]"',
      searching: 'Searching for "[SEARCH_TERM]"…',
    },
  });
}

// ----------------------------------------------------------------------
// Date-window filter on the briefs listing.

function initDateFilter() {
  const group = document.querySelector('[data-date-filter-group]');
  if (!group) return;

  const buttons = group.querySelectorAll('[data-date-filter]');
  const cards = document.querySelectorAll('[data-brief-date]');
  const sections = document.querySelectorAll('[data-month-section]');
  const empty = document.querySelector('[data-empty-message]');

  function applyFilter(windowDays) {
    const now = Date.now() / 1000;
    const cutoff = windowDays === 0 ? 0 : now - (windowDays * 86400);

    cards.forEach((card) => {
      const ts = +card.dataset.briefDate;
      const visible = windowDays === 0 || ts >= cutoff;
      card.style.display = visible ? '' : 'none';
    });

    let totalVisible = 0;
    sections.forEach((sec) => {
      const visibleCards = sec.querySelectorAll('[data-brief-date]');
      let count = 0;
      visibleCards.forEach((c) => { if (c.style.display !== 'none') count++; });
      sec.style.display = count === 0 ? 'none' : '';
      const counter = sec.querySelector('[data-month-count]');
      if (counter) counter.textContent = count;
      totalVisible += count;
    });

    if (empty) empty.classList.toggle('hidden', totalVisible > 0);
  }

  function setActive(activeBtn) {
    buttons.forEach((b) => {
      const active = b === activeBtn;
      b.classList.toggle('border-accent/40', active);
      b.classList.toggle('bg-accent/10', active);
      b.classList.toggle('text-text', active);
      b.classList.toggle('font-medium', active);
      b.classList.toggle('border-stroke', !active);
      b.classList.toggle('text-muted', !active);
    });
  }

  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const days = parseInt(btn.dataset.dateFilter, 10) || 0;
      applyFilter(days);
      setActive(btn);
    });
  });
}

// ----------------------------------------------------------------------
// Mobile menu (mirrors website/ pattern)

function initMobileMenu() {
  const btn = document.getElementById('menu-toggle');
  const menu = document.getElementById('mobile-menu');
  if (!btn || !menu) return;

  function toggle(open) {
    const isOpen = typeof open === 'boolean' ? open : menu.classList.contains('hidden');
    menu.classList.toggle('hidden', !isOpen);
    btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  }

  btn.addEventListener('click', () => toggle());
  menu.querySelectorAll('a').forEach((a) => a.addEventListener('click', () => toggle(false)));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !menu.classList.contains('hidden')) toggle(false);
  });
}

// ----------------------------------------------------------------------
// Live feed updates: tag briefs the user hasn't seen since their last
// visit with a "new" pill, and poll the RSS in the background to nudge
// them when more land while the tab is open.

const LAST_VIEWED_KEY = 'feedLastViewed';
const FEED_POLL_MS = 5 * 60 * 1000;
const FEED_BANNER_ID = 'feed-update-banner';

function readLastViewed() {
  try {
    const v = parseInt(localStorage.getItem(LAST_VIEWED_KEY), 10);
    return Number.isFinite(v) ? v : 0;
  } catch (_) { return 0; }
}

function writeLastViewed(ts) {
  try { localStorage.setItem(LAST_VIEWED_KEY, String(ts)); } catch (_) {}
}

function markUnseenBriefs(cards, sinceTs) {
  if (!sinceTs) return;
  cards.forEach((card) => {
    const ts = +card.dataset.briefDate;
    if (!ts || ts <= sinceTs) return;
    if (card.querySelector('[data-new-pill]')) return;
    const pill = document.createElement('span');
    pill.dataset.newPill = '1';
    pill.className = 'inline-flex items-center px-1.5 py-0.5 ml-2 rounded font-mono uppercase tracking-wider bg-accent/15 text-accent text-[10px] align-middle';
    pill.textContent = 'new';
    const heading = card.querySelector('h3');
    if (heading) heading.appendChild(pill);
  });
}

function showRefreshBanner(count) {
  if (document.getElementById(FEED_BANNER_ID)) return;
  const btn = document.createElement('button');
  btn.id = FEED_BANNER_ID;
  btn.type = 'button';
  btn.className = 'fixed bottom-6 left-1/2 -translate-x-1/2 z-40 px-4 py-2 rounded-full bg-accent text-white text-sm font-semibold shadow-soft hover:scale-[1.02] transition flex items-center gap-2';
  btn.innerHTML = `<span aria-hidden="true">●</span> ${count} new ${count === 1 ? 'brief' : 'briefs'} — refresh`;
  btn.setAttribute('aria-live', 'polite');
  btn.addEventListener('click', () => window.location.reload());
  document.body.appendChild(btn);
}

async function pollForNewBriefs(latestOnPage) {
  try {
    const res = await fetch('/feed.xml', { cache: 'no-cache' });
    if (!res.ok) return 0;
    const text = await res.text();
    let count = 0;
    for (const m of text.matchAll(/<pubDate>([^<]+)<\/pubDate>/g)) {
      const ts = Math.floor(new Date(m[1]).getTime() / 1000);
      if (Number.isFinite(ts) && ts > latestOnPage) count++;
    }
    return count;
  } catch (_) {
    return 0;
  }
}

function initLiveUpdate() {
  const cards = document.querySelectorAll('[data-brief-date]');
  if (!cards.length) return;

  let latestOnPage = 0;
  cards.forEach((c) => {
    const ts = +c.dataset.briefDate;
    if (Number.isFinite(ts) && ts > latestOnPage) latestOnPage = ts;
  });

  // Mark items the user hasn't seen since their previous visit, then
  // bump the pointer to the most recent timestamp on this page so the
  // pills don't stick around on every reload.
  markUnseenBriefs(cards, readLastViewed());
  if (latestOnPage > 0) writeLastViewed(latestOnPage);

  // RSS lives on every listing path that emits one (home, sections,
  // taxonomy terms). `feed.xml` is always relative-correct because of
  // Hugo's per-section RSS.
  let stop = false;
  const tick = async () => {
    if (stop) return;
    if (!document.hidden) {
      const count = await pollForNewBriefs(latestOnPage);
      if (count > 0) {
        showRefreshBanner(count);
        stop = true;
      }
    }
  };
  // First poll a minute in (give analytics + Pagefind room to settle),
  // then on the steady cadence.
  setTimeout(tick, 60 * 1000);
  setInterval(tick, FEED_POLL_MS);
}

// ----------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initSearch();
  initMobileMenu();
  initDateFilter();
  initLiveUpdate();
});
