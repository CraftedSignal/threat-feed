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
  const input = document.querySelector('pagefind-input');
  if (!input) return;

  // pagefind-component-ui.js is loaded as a deferred <script> in head.html; the tag
  // self-removes if the file doesn't exist (no built index yet), leaving
  // window.PagefindComponents undefined.
  if (typeof window.PagefindComponents === 'undefined') {
    input.insertAdjacentHTML('beforebegin', '<p class="px-4 py-3 text-sm text-muted">Search index missing. Run <code class="font-mono">make build</code> (or <code class="font-mono">make dev</code>) to generate it.</p>');
    return;
  }

  const instance = window.PagefindComponents.getInstanceManager().getInstance('default');
  instance.setTranslations({
    clear_search: 'Clear',
    load_more: 'Load more',
    search_label: 'Search',
    filters_label: 'Filters',
    zero_results: 'No briefs match "[SEARCH_TERM]"',
    many_results: '[COUNT] briefs match "[SEARCH_TERM]"',
    one_result: '[COUNT] brief matches "[SEARCH_TERM]"',
    searching: 'Searching for "[SEARCH_TERM]"…',
  });

  // When a result's title already highlights the match, suppress the body
  // excerpt — it's a redundant double-match on the same content.
  // MutationObserver is used because pagefind adds results dynamically.
  const resultsEl = document.querySelector('pagefind-results');
  if (resultsEl) {
    const suppressExcerpts = () => {
      resultsEl.querySelectorAll('.pf-result-content').forEach((content) => {
        if (content.querySelector('.pf-result-title mark')) {
          const excerpt = content.querySelector('.pf-result-excerpt');
          if (excerpt) excerpt.style.display = 'none';
        }
      });
    };
    new MutationObserver(suppressExcerpts).observe(resultsEl, { childList: true, subtree: true });
  }
}

// ----------------------------------------------------------------------
// Brief listing filters: date-window + attribute (type/severity/flags).
// Both filters contribute to visibility independently; a card is shown
// only when it passes both. Pagination nav is hidden when any filter
// narrows the view (since Hugo pagination is server-rendered and the
// filter only applies to the current page).

function initBriefFilters() {
  const dateGroup = document.querySelector('[data-date-filter-group]');
  const attrGroup = document.querySelector('[data-attr-filter-group]');
  if (!dateGroup && !attrGroup) return;

  const cards        = [...document.querySelectorAll('[data-brief-date]')];
  const sections     = [...document.querySelectorAll('[data-month-section]')];
  const empty        = document.querySelector('[data-empty-message]');
  const paginationEls = [...document.querySelectorAll('[data-briefs-pagination]')];
  const paginationWarning = document.querySelector('[data-filter-pagination-warning]');
  const isPaginated  = dateGroup?.hasAttribute('data-paginated');

  // Track filter state.
  let activeDateDays = 0;          // 0 = all time
  const activeTypes  = new Set();  // e.g. 'advisory', 'threat'
  const activeSevs   = new Set();  // e.g. 'critical', 'high'
  const activeFlags  = new Set();  // e.g. 'poc', 'exploited', 'ioc'

  function isFiltered() {
    return activeDateDays !== 0 || activeTypes.size > 0 || activeSevs.size > 0 || activeFlags.size > 0;
  }

  function recalc() {
    const now = Date.now() / 1000;
    const cutoff = activeDateDays === 0 ? 0 : now - activeDateDays * 86400;

    cards.forEach((card) => {
      const dateOk = activeDateDays === 0 || (+card.dataset.briefDate) >= cutoff;
      const typeOk = activeTypes.size === 0 || activeTypes.has(card.dataset.briefType);
      const sevOk  = activeSevs.size  === 0 || activeSevs.has(card.dataset.briefSev);
      const pocOk      = !activeFlags.has('poc')      || card.dataset.briefPoc      === '1';
      const exploitedOk= !activeFlags.has('exploited')|| card.dataset.briefExploited=== '1';
      const iocOk      = !activeFlags.has('ioc')      || card.dataset.briefIoc      === '1';
      card.style.display = (dateOk && typeOk && sevOk && pocOk && exploitedOk && iocOk) ? '' : 'none';
    });

    let totalVisible = 0;
    sections.forEach((sec) => {
      let count = 0;
      sec.querySelectorAll('[data-brief-date]').forEach((c) => {
        if (c.style.display !== 'none') count++;
      });
      sec.style.display = count === 0 ? 'none' : '';
      const counter = sec.querySelector('[data-month-count]');
      if (counter) counter.textContent = count;
      totalVisible += count;
    });

    if (empty) empty.classList.toggle('hidden', totalVisible > 0);

    // Hide pagination nav when any filter is active — it only applies to
    // the current page so Older/Newer links are misleading when filtered.
    paginationEls.forEach((el) => el.classList.toggle('hidden', isFiltered()));

    if (paginationWarning) {
      paginationWarning.classList.toggle(
        'hidden',
        !(totalVisible === 0 && isPaginated && isFiltered()),
      );
    }
  }

  // Active/inactive styling helpers.
  function chipActive(btn) {
    btn.classList.add('border-accent/40', 'bg-accent/10', 'text-text', 'font-medium');
    btn.classList.remove('border-stroke', 'text-muted');
  }
  function chipInactive(btn) {
    btn.classList.remove('border-accent/40', 'bg-accent/10', 'text-text', 'font-medium');
    btn.classList.add('border-stroke', 'text-muted');
  }


  // Shared dropdown helper — menus use position:absolute relative to their
  // .relative wrapper, so no positioning calculation needed here.
  function openDropdown(_trigger, menu) {
    menu.classList.remove('hidden');
  }
  function closeAllDropdowns() {
    document.querySelectorAll('[data-date-menu],[data-sev-menu]').forEach((m) => m.classList.add('hidden'));
  }
  document.addEventListener('click', closeAllDropdowns);

  // Date dropdown.
  const dateDropdown = document.querySelector('[data-date-dropdown]');
  const dateTrigger  = document.querySelector('[data-date-trigger]');
  const dateMenu     = document.querySelector('[data-date-menu]');
  const dateLabel    = document.querySelector('[data-date-label]');

  if (dateTrigger && dateMenu) {
    dateTrigger.addEventListener('click', (e) => {
      e.stopPropagation();
      const wasHidden = dateMenu.classList.contains('hidden');
      closeAllDropdowns();
      if (wasHidden) openDropdown(dateTrigger, dateMenu);
    });
  }

  if (dateGroup) {
    const dateBtns = dateGroup.querySelectorAll('[data-date-filter]');
    dateBtns.forEach((btn) => {
      if (btn.dataset.dateFilter === '0') btn.classList.add('font-medium', 'text-text');
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        activeDateDays = parseInt(btn.dataset.dateFilter, 10) || 0;
        dateBtns.forEach((b) => {
          b.classList.toggle('font-medium', b === btn);
          b.classList.toggle('text-text', b === btn);
          b.classList.toggle('text-muted', b !== btn);
        });
        if (dateLabel) dateLabel.textContent = btn.textContent.trim();
        if (dateTrigger) {
          if (activeDateDays === 0) chipInactive(dateTrigger);
          else chipActive(dateTrigger);
        }
        dateMenu?.classList.add('hidden');
        recalc();
      });
    });
  }

  // Attribute filter — type and severity are multi-select OR within group;
  // flags are independent toggles.
  if (attrGroup) {
    attrGroup.querySelectorAll('[data-attr-type]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const val = btn.dataset.attrType;
        if (activeTypes.has(val)) { activeTypes.delete(val); chipInactive(btn); }
        else                      { activeTypes.add(val);    chipActive(btn);   }
        recalc();
      });
    });

    // Severity dropdown wiring.
    const sevDropdown = attrGroup.querySelector('[data-sev-dropdown]');
    const sevTrigger  = attrGroup.querySelector('[data-sev-trigger]');
    const sevMenu     = attrGroup.querySelector('[data-sev-menu]');
    const sevLabel    = attrGroup.querySelector('[data-sev-label]');

    if (sevTrigger && sevMenu) {
      sevTrigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const wasHidden = sevMenu.classList.contains('hidden');
        closeAllDropdowns();
        if (wasHidden) openDropdown(sevTrigger, sevMenu);
      });
    }

    function updateSevTrigger() {
      if (!sevLabel) return;
      if (activeSevs.size === 0) {
        sevLabel.textContent = 'Severity';
        if (sevTrigger) chipInactive(sevTrigger);
      } else {
        sevLabel.textContent = 'Severity · ' + activeSevs.size;
        if (sevTrigger) chipActive(sevTrigger);
      }
    }

    attrGroup.querySelectorAll('[data-attr-sev]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const val = btn.dataset.attrSev;
        if (activeSevs.has(val)) {
          activeSevs.delete(val);
          btn.classList.remove('text-text', 'font-medium');
          btn.classList.add('text-muted');
        } else {
          activeSevs.add(val);
          btn.classList.add('text-text', 'font-medium');
          btn.classList.remove('text-muted');
        }
        updateSevTrigger();
        recalc();
      });
    });

    attrGroup.querySelectorAll('[data-attr-flag]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const val = btn.dataset.attrFlag;
        if (activeFlags.has(val)) { activeFlags.delete(val); chipInactive(btn); }
        else                      { activeFlags.add(val);    chipActive(btn);   }
        recalc();
      });
    });
  }
}

// Keep legacy name wired so DOMContentLoaded still works.
function initDateFilter() { initBriefFilters(); }

// ----------------------------------------------------------------------
// Scroll offset CSS variable — keeps [data-month-section] scroll-margin-top
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

// ----------------------------------------------------------------------
// Client-side taxonomy filter. On /vendors/, /actors/, /products/,
// /tags/ the page is itself a list of terms — full-site Pagefind is
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

document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initSearch();
  initMobileMenu();
  initScrollOffset();
  initDateFilter();
  initLiveUpdate();
  initTaxonomyFilter();
});
