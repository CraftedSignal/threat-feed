import {
  canonicalBriefURL,
  filterBriefs,
  hasBriefFilters,
  paginateBriefs,
  parseBriefQuery,
  projectBriefControls,
  updateBriefQuery,
} from './brief-filters.js';

// Theme toggle + Pagefind search + addressable brief filters + mobile menu wiring.
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

  // pagefind-ui.js is loaded as a deferred <script> in head.html; the tag
  // self-removes if /pagefind/pagefind-ui.js doesn't exist (no built index
  // yet). After DOMContentLoaded the deferred script has run, so
  // window.PagefindUI is either defined (built) or absent (skip wiring).
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
    // Order every result set by brief date, newest first. With `sort` set,
    // Pagefind uses the query purely as a filter and drops relevance ranking,
    // so results always read chronologically - matching the briefs listing.
    // Depends on data-pagefind-sort="date[datetime]" in the brief single-page
    // templates; the Pagefind index must be rebuilt (make build) to pick it up.
    sort: { date: 'desc' },
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
// Brief listing filters. The server-rendered page stays untouched until a
// filter is active; filtered views use the complete metadata index and apply
// filtering before client-side pagination.

function initBriefFilters() {
  const controls = document.querySelector('[data-brief-filters]');
  const serverResults = document.querySelector('[data-server-results]');
  const clientResults = document.querySelector('[data-filter-results]');
  const status = document.querySelector('[data-filter-status]');
  if (!controls || !serverResults || !clientResults || !status) return;

  const indexURL = controls.dataset.indexUrl || '/briefs/index.json';
  const serverPagination = [...document.querySelectorAll('[data-server-pagination]')];
  let state = parseBriefQuery(window.location.search);
  let indexPromise;
  let renderVersion = 0;

  function setActiveStyle(button, pressed, exposePressed = true) {
    if (!button) return;
    if (exposePressed) button.setAttribute('aria-pressed', pressed ? 'true' : 'false');
    button.classList.toggle('border-accent/40', pressed);
    button.classList.toggle('bg-accent/10', pressed);
    button.classList.toggle('text-text', pressed);
    button.classList.toggle('font-medium', pressed);
    button.classList.toggle('border-stroke', !pressed);
    button.classList.toggle('text-muted', !pressed);
  }

  function projectControls() {
    const view = projectBriefControls(state);
    const dateLabel = controls.querySelector('[data-date-label]');
    const severityLabel = controls.querySelector('[data-sev-label]');
    if (dateLabel) dateLabel.textContent = view.windowLabel;
    if (severityLabel) severityLabel.textContent = view.severityLabel;
    controls.querySelectorAll('[data-date-filter]').forEach((button) => {
      setActiveStyle(button, (button.dataset.dateFilter || null) === state.window);
    });
    controls.querySelectorAll('[data-attr-sev]').forEach((button) => setActiveStyle(button, view.selected.severities[button.dataset.attrSev]));
    controls.querySelectorAll('[data-attr-type]').forEach((button) => setActiveStyle(button, view.selected.types[button.dataset.attrType]));
    controls.querySelectorAll('[data-attr-flag]').forEach((button) => setActiveStyle(button, view.selected.flags[button.dataset.attrFlag]));
    setActiveStyle(controls.querySelector('[data-date-trigger]'), Boolean(state.window), false);
    setActiveStyle(controls.querySelector('[data-sev-trigger]'), state.severities.length > 0, false);
    const clear = controls.querySelector('[data-clear-filters]');
    if (clear) clear.hidden = !view.active;
  }

  function closeMenus({ restoreFocus = false } = {}) {
    controls.querySelectorAll('[data-filter-menu]').forEach((menu) => menu.classList.add('hidden'));
    controls.querySelectorAll('[data-filter-trigger]').forEach((trigger) => {
      const wasOpen = trigger.getAttribute('aria-expanded') === 'true';
      trigger.setAttribute('aria-expanded', 'false');
      if (restoreFocus && wasOpen) trigger.focus();
    });
  }

  controls.querySelectorAll('[data-filter-trigger]').forEach((trigger) => {
    trigger.addEventListener('click', (event) => {
      event.stopPropagation();
      const menu = document.getElementById(trigger.getAttribute('aria-controls'));
      const open = trigger.getAttribute('aria-expanded') !== 'true';
      closeMenus();
      if (open && menu) {
        menu.classList.remove('hidden');
        trigger.setAttribute('aria-expanded', 'true');
        menu.querySelector('button')?.focus();
      }
    });
  });
  document.addEventListener('click', () => closeMenus());
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeMenus({ restoreFocus: true });
  });

  function loadIndex({ retry = false } = {}) {
    if (retry) indexPromise = null;
    if (!indexPromise) {
      indexPromise = fetch(indexURL, { credentials: 'omit' }).then((response) => {
        if (!response.ok) throw new Error(`The brief index returned ${response.status}.`);
        return response.json();
      }).then((data) => {
        if (!data || !Array.isArray(data.items) || !data.generated_at) {
          throw new Error('The brief index response is incomplete.');
        }
        return data;
      });
    }
    return indexPromise;
  }

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function badge(text, className) {
    return node('span', `inline-flex items-center px-1.5 py-0.5 rounded font-mono uppercase tracking-wider text-[11px] ${className}`, text);
  }

  function createClientCard(item) {
    const card = node('a', 'brief-card block rounded-xl border border-stroke bg-panel/70 hover:bg-panel hover:border-accent/40 p-5 transition group');
    card.href = item.url;
    card.dataset.briefDate = String(Math.floor(Date.parse(item.activity_at) / 1000));
    const row = node('div', 'flex items-start gap-4');
    const labels = node('div', 'pt-0.5 flex-none flex flex-col items-stretch gap-1 min-w-[88px] max-w-[88px]');
    labels.append(badge(item.severity === 'informational' ? 'info' : item.severity, `sev-badge sev-${item.severity} justify-center`));
    labels.append(badge(item.type === 'coverage' ? 'rule' : item.type, `type-badge type-${item.type} justify-center`));

    const body = node('div', 'flex-1 min-w-0');
    const headline = node('div', 'flex items-baseline justify-between gap-3');
    headline.append(node('h3', 'font-display text-base md:text-lg font-semibold text-text leading-snug group-hover:text-accent transition line-clamp-2', item.title));
    const countLine = node('span', 'hidden md:flex items-center gap-3 text-xs text-muted whitespace-nowrap');
    const countLabels = { rules: 'rules', ttps: 'TTPs', cves: 'CVEs', iocs: 'IOCs' };
    Object.entries(countLabels).forEach(([key, label]) => {
      const count = Number(item.counts?.[key] || 0);
      if (count > 0) countLine.append(node('span', '', `${count} ${count === 1 ? label.replace(/s$/, '') : label}`));
    });
    headline.append(countLine);
    body.append(headline);
    if (item.summary) body.append(node('p', 'mt-1.5 text-sm text-muted line-clamp-2', item.summary));

    const footer = node('div', 'mt-3 flex items-end justify-between gap-3 text-[11px]');
    const facts = node('div', 'flex flex-wrap items-center gap-x-3 gap-y-1.5 min-w-0');
    const itemFlags = new Set(Array.isArray(item.flags) ? item.flags : Object.keys(item.flags || {}).filter((key) => item.flags[key]));
    if (itemFlags.has('exploited')) facts.append(badge('exploited', 'bg-sev-critical/10 text-sev-critical'));
    if (itemFlags.has('poc')) facts.append(badge('PoC', 'bg-sev-high/10 text-sev-high border border-sev-high/30'));
    if (itemFlags.has('ioc')) facts.append(badge('IOCs', 'bg-panel-2 text-text'));
    if (item.primary_product) facts.append(badge(item.primary_product, 'bg-panel-2 text-text'));
    if (item.primary_actor) facts.append(badge(item.primary_actor, 'bg-accent/10 text-accent'));
    (item.tags || []).slice(0, 5).forEach((tag) => facts.append(badge(tag, 'bg-panel-2 text-muted')));
    footer.append(facts);
    const time = node('time', 'font-mono text-muted whitespace-nowrap', formatRelativeTime(new Date(item.activity_at)));
    time.dateTime = item.activity_at;
    time.title = new Date(item.activity_at).toLocaleString();
    footer.append(time);
    body.append(footer);
    row.append(labels, body);
    card.append(row);
    return card;
  }

  function createFilteredPagination(page) {
    if (page.totalPages <= 1) return null;
    const nav = node('nav', 'flex items-center justify-between border-t border-stroke pt-6 mt-4 text-sm text-muted');
    nav.setAttribute('aria-label', 'Filtered briefs pagination');
    nav.append(node('div', '', `Page ${page.page} of ${page.totalPages}`));
    const links = node('div', 'flex items-center gap-2');
    if (page.hasPrev) {
      const previous = node('a', 'brief-filter-page', '← Newer');
      previous.href = canonicalBriefURL('/briefs/', state, page.page - 1);
      previous.dataset.filterPage = String(page.page - 1);
      links.append(previous);
    }
    if (page.hasNext) {
      const next = node('a', 'brief-filter-page', 'Older →');
      next.href = canonicalBriefURL('/briefs/', state, page.page + 1);
      next.dataset.filterPage = String(page.page + 1);
      links.append(next);
    }
    nav.append(links);
    return nav;
  }

  function renderFiltered(items, page) {
    clientResults.replaceChildren();
    if (page.totalItems === 0) {
      const empty = node('div', 'rounded-xl border border-stroke bg-panel/60 px-5 py-10 text-center');
      empty.append(node('h2', 'font-display text-lg font-semibold text-text', 'No briefs match these filters'));
      empty.append(node('p', 'mt-2 text-sm text-muted', 'Clear a filter or broaden the selected severities and types.'));
      clientResults.append(empty);
      return;
    }

    const monthFormat = new Intl.DateTimeFormat('en', { month: 'long', year: 'numeric', timeZone: 'UTC' });
    let currentMonth = '';
    let section;
    let list;
    page.items.forEach((item) => {
      const month = monthFormat.format(new Date(item.activity_at));
      if (month !== currentMonth) {
        currentMonth = month;
        section = node('section', 'space-y-3');
        section.append(node('h2', 'font-display text-lg font-semibold text-text', month));
        list = node('div', 'space-y-3');
        section.append(list);
        clientResults.append(section);
      }
      list.append(createClientCard(item));
    });
    const pagination = createFilteredPagination(page);
    if (pagination) clientResults.append(pagination);
  }

  function showServerResults() {
    controls.removeAttribute('aria-busy');
    serverResults.classList.remove('hidden');
    serverPagination.forEach((element) => element.classList.remove('hidden'));
    clientResults.classList.add('hidden');
    clientResults.replaceChildren();
    status.classList.add('hidden');
    status.textContent = '';
  }

  async function applyState({ retry = false } = {}) {
    const version = ++renderVersion;
    projectControls();
    if (!hasBriefFilters(state)) {
      showServerResults();
      return;
    }
    serverResults.classList.add('hidden');
    serverPagination.forEach((element) => element.classList.add('hidden'));
    clientResults.classList.remove('hidden');
    clientResults.replaceChildren();
    status.classList.remove('hidden');
    status.textContent = 'Loading the complete brief index…';
    controls.setAttribute('aria-busy', 'true');
    try {
      const index = await loadIndex({ retry });
      if (version !== renderVersion) return;
      const items = filterBriefs(index.items, state, index.generated_at);
      const page = paginateBriefs(items, state.page, index.page_size || 30);
      if (page.page !== state.page) {
        state = { ...state, page: page.page };
        history.replaceState({}, '', canonicalBriefURL('/briefs/', state));
      }
      renderFiltered(items, page);
      status.textContent = page.totalItems === 1
        ? '1 brief matches'
        : `${page.totalItems.toLocaleString()} briefs match${page.totalPages > 1 ? ` · Page ${page.page} of ${page.totalPages}` : ''}`;
    } catch (error) {
      if (version !== renderVersion) return;
      clientResults.replaceChildren();
      const panel = node('div', 'rounded-xl border border-sev-high/40 bg-panel px-5 py-6 text-sm');
      panel.append(node('p', 'font-semibold text-text', 'The complete brief index could not be loaded.'));
      panel.append(node('p', 'mt-1 text-muted', error instanceof Error ? error.message : 'Check your connection and try again.'));
      const retryButton = node('button', 'brief-filter-page mt-4', 'Try again');
      retryButton.type = 'button';
      retryButton.addEventListener('click', () => applyState({ retry: true }));
      panel.append(retryButton);
      clientResults.append(panel);
      status.textContent = 'Brief filters unavailable';
    } finally {
      if (version === renderVersion) controls.removeAttribute('aria-busy');
    }
  }

  function commit(nextState) {
    state = nextState;
    const target = hasBriefFilters(state) ? canonicalBriefURL('/briefs/', state) : '/briefs/';
    if (`${window.location.pathname}${window.location.search}` !== target) history.pushState({}, '', target);
    closeMenus();
    applyState();
  }

  controls.addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (!button) return;
    if (button.matches('[data-date-filter]')) {
      const value = button.dataset.dateFilter || null;
      commit(value ? updateBriefQuery(state, { group: 'window', value }) : { ...state, window: null, page: 1 });
    } else if (button.matches('[data-attr-sev]')) {
      commit(updateBriefQuery(state, { group: 'severities', value: button.dataset.attrSev }));
    } else if (button.matches('[data-attr-type]')) {
      commit(updateBriefQuery(state, { group: 'types', value: button.dataset.attrType }));
    } else if (button.matches('[data-attr-flag]')) {
      commit(updateBriefQuery(state, { group: 'flags', value: button.dataset.attrFlag }));
    } else if (button.matches('[data-clear-filters]')) {
      commit(parseBriefQuery(''));
    }
  });

  clientResults.addEventListener('click', (event) => {
    const link = event.target.closest('[data-filter-page]');
    if (!link) return;
    event.preventDefault();
    commit({ ...state, page: Number.parseInt(link.dataset.filterPage, 10) || 1 });
    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({ top: controls.getBoundingClientRect().top + window.scrollY - 80, behavior: reduceMotion ? 'auto' : 'smooth' });
  });

  window.addEventListener('popstate', () => {
    state = parseBriefQuery(window.location.search);
    applyState();
  });

  const canonical = hasBriefFilters(state) ? canonicalBriefURL('/briefs/', state) : null;
  if (canonical && `${window.location.pathname}${window.location.search}` !== canonical) {
    history.replaceState({}, '', canonical);
  } else if (!canonical && window.location.search) {
    history.replaceState({}, '', window.location.pathname);
  }
  applyState();
}

// Keep legacy name wired so DOMContentLoaded still works.
function initDateFilter() { initBriefFilters(); }

// ----------------------------------------------------------------------
// Live relative timestamps. Hugo renders the initial value as a no-JS
// fallback; the browser keeps it fresh while the tab is open.
const RELATIVE_TIME_UPDATE_MS = 30 * 1000;

function formatRelativeTime(date, now = new Date()) {
  const diff = Math.max(0, Math.floor((now.getTime() - date.getTime()) / 1000));
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  if (diff < 2592000) return `${Math.floor(diff / 604800)}w ago`;
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function initRelativeTimes() {
  const nodes = [...document.querySelectorAll('time[data-relative-time][datetime]')];
  if (!nodes.length) return;
  const entries = nodes
    .map((node) => ({ node, date: new Date(node.getAttribute('datetime')) }))
    .filter((entry) => Number.isFinite(entry.date.getTime()));
  if (!entries.length) return;

  function update() {
    const now = new Date();
    entries.forEach(({ node, date }) => {
      node.textContent = formatRelativeTime(date, now);
    });
  }

  update();
  window.setInterval(update, RELATIVE_TIME_UPDATE_MS);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) update();
  });
}

// ----------------------------------------------------------------------
// Scroll offset CSS variable - keeps [data-month-section] scroll-margin-top
// aligned with the actual combined height of the sticky header + filter bar.

function initScrollOffset() {
  const header = document.querySelector('header');
  const filterBar = document.querySelector('[data-date-filter-group]')?.closest('section');
  if (!header) return;

  function update() {
    const offset = header.offsetHeight + (filterBar ? filterBar.offsetHeight : 0) + 16;
    document.documentElement.style.setProperty('--scroll-offset', offset + 'px');
  }

  update();
  window.addEventListener('resize', update, { passive: true });
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
// visit, and poll the RSS in the background to nudge them when more land
// while the tab is open.

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
    card.dataset.briefUnseen = 'true';
    if (card.querySelector('[data-new-pill]')) return;
    const pill = document.createElement('span');
    pill.dataset.newPill = '1';
    pill.className = 'inline-flex items-center px-1.5 py-0.5 rounded font-mono uppercase tracking-wider bg-accent/15 text-accent text-[10px]';
    pill.textContent = 'new';
    const slot = card.querySelector('[data-new-pill-slot]');
    if (slot) {
      slot.classList.remove('hidden');
      slot.classList.add('inline-flex', 'items-center');
      slot.appendChild(pill);
    }
  });
}

function showRefreshBanner(count) {
  if (document.getElementById(FEED_BANNER_ID)) return;
  const btn = document.createElement('button');
  btn.id = FEED_BANNER_ID;
  btn.type = 'button';
  btn.className = 'fixed bottom-6 left-1/2 -translate-x-1/2 z-40 px-4 py-2 rounded-full bg-accent text-white text-sm font-semibold shadow-soft hover:scale-[1.02] transition flex items-center gap-2';
  btn.innerHTML = `<span aria-hidden="true">●</span> ${count} new ${count === 1 ? 'brief' : 'briefs'} - refresh`;
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
  // marker doesn't stick around on every reload.
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

// ----------------------------------------------------------------------
// Client-side taxonomy filter. On /vendors/, /actors/, /products/,
// /tags/ the page is itself a list of terms - full-site Pagefind is
// the wrong tool because typing "Amaz" should narrow the visible
// vendors to Amazon, not return every brief that mentions Amazon.
//
// Two modes, picked per-page by the template:
//   DOM mode (default): the rendered HTML contains every term card,
//   filter just toggles `.hidden` on each card. Used for /types/ where
//   the term list is small and complete.
//
//   JSON mode (`data-taxonomy-source="json"` on the input): HTML only
//   renders the top-N terms. The filter pulls the full term list from
//   the page's `index.json` on first keypress, then renders matching
//   cards into `[data-taxonomy-results]` and hides the default block.
//   Used for taxonomies that grow unboundedly (tags, vendors, products,
//   actors).

function initTaxonomyFilter() {
  const input = document.querySelector('[data-taxonomy-filter]');
  if (!input) return;
  const empty = document.querySelector('[data-taxonomy-empty]');

  if (input.dataset.taxonomySource === 'json') {
    initTaxonomyFilterJSON(input, empty);
  } else {
    initTaxonomyFilterDOM(input, empty);
  }
}

function initTaxonomyFilterDOM(input, empty) {
  const cards = document.querySelectorAll('[data-taxonomy-term]');
  if (!cards.length) return;
  function apply() {
    const q = input.value.toLowerCase().trim();
    let visible = 0;
    cards.forEach((c) => {
      const term = c.dataset.taxonomyTerm || '';
      const match = !q || term.includes(q);
      c.classList.toggle('hidden', !match);
      if (match) visible++;
    });
    if (empty) empty.classList.toggle('hidden', visible > 0);
  }
  input.addEventListener('input', apply);
}

function initTaxonomyFilterJSON(input, empty) {
  const defaultBlock = document.querySelector('[data-taxonomy-default]');
  const results = document.querySelector('[data-taxonomy-results]');
  if (!defaultBlock || !results) return;

  let allTerms = null;
  let loading = null;

  function loadAll() {
    if (allTerms) return Promise.resolve(allTerms);
    if (loading) return loading;
    const url = window.location.pathname.replace(/\/?$/, '/') + 'index.json';
    loading = fetch(url, { credentials: 'omit' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        allTerms = Array.isArray(data) ? data : [];
        return allTerms;
      })
      .catch(() => {
        allTerms = [];
        return allTerms;
      });
    return loading;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function renderMatches(matches) {
    results.innerHTML = matches.map((t) => (
      '<a href="' + escapeHtml(t.url) + '" class="flex items-center justify-between rounded-xl border border-stroke bg-panel/60 px-4 py-3 hover:border-accent/40 transition group">' +
        '<span class="font-medium text-text group-hover:text-accent transition">' + escapeHtml(t.title) + '</span>' +
        '<span class="font-mono text-sm text-muted">' + escapeHtml(t.count) + '</span>' +
      '</a>'
    )).join('');
  }

  async function apply() {
    const q = input.value.toLowerCase().trim();
    if (!q) {
      defaultBlock.classList.remove('hidden');
      results.classList.add('hidden');
      results.innerHTML = '';
      if (empty) empty.classList.add('hidden');
      return;
    }
    const terms = await loadAll();
    const matches = terms.filter((t) => (t.title || '').toLowerCase().includes(q));
    defaultBlock.classList.add('hidden');
    results.classList.remove('hidden');
    renderMatches(matches);
    if (empty) empty.classList.toggle('hidden', matches.length > 0);
  }

  input.addEventListener('input', apply);
}

// "Copy all" IOC buttons. Delegated from the document so a single listener
// covers every brief page — and, crucially, so the former inline `onclick`
// handler can go away and the page CSP can drop script-src 'unsafe-inline'.
function initCopyIocs() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-iocs]');
    if (!btn) return;
    let values;
    try { values = JSON.parse(btn.dataset.iocs).join('\n'); } catch (_) { return; }
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(values).then(() => {
      const orig = btn.textContent;
      btn.textContent = 'copied!';
      setTimeout(() => { btn.textContent = orig; }, 1500);
    }).catch(() => {});
  });
}

const BRIEF_SIDEBAR_KEY = 'feedBriefSidebarCollapsed';

function initBriefSidebarToggle() {
  document.querySelectorAll('[data-brief-layout]').forEach((layout) => {
    const sidebar = layout.querySelector('[data-brief-sidebar]');
    const content = sidebar?.querySelector('[data-brief-sidebar-content]');
    const btn = sidebar?.querySelector('[data-brief-sidebar-toggle]');
    if (!sidebar || !content || !btn) return;

    const label = btn.querySelector('[data-brief-sidebar-toggle-label]');
    const setCollapsed = (collapsed) => {
      layout.dataset.sidebarCollapsed = collapsed ? 'true' : 'false';
      content.hidden = collapsed;
      btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      btn.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
      btn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
      if (label) label.textContent = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
      try { localStorage.setItem(BRIEF_SIDEBAR_KEY, collapsed ? 'true' : 'false'); } catch (_) {}
    };

    let collapsed = false;
    try { collapsed = localStorage.getItem(BRIEF_SIDEBAR_KEY) === 'true'; } catch (_) {}
    setCollapsed(collapsed);
    btn.addEventListener('click', () => setCollapsed(layout.dataset.sidebarCollapsed !== 'true'));
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initSearch();
  initMobileMenu();
  initScrollOffset();
  initDateFilter();
  initRelativeTimes();
  initLiveUpdate();
  initTaxonomyFilter();
  initCopyIocs();
  initBriefSidebarToggle();
});
