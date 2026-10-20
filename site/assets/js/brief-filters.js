const VALID_WINDOWS = new Set(['24h']);
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
const TYPE_ORDER = ['threat', 'advisory', 'coverage', 'rumour'];
const FLAG_ORDER = ['poc', 'exploited', 'ioc'];
const DAY_MS = 24 * 60 * 60 * 1000;

function orderedValues(raw, allowed) {
  const requested = new Set(String(raw || '').split(',').filter(Boolean));
  return allowed.filter((value) => requested.has(value));
}
export function parseBriefQuery(input = '') {
  const params = input instanceof URLSearchParams
    ? input
    : new URLSearchParams(String(input).replace(/^\?/, ''));
  const parsedPage = Number.parseInt(params.get('page') || '1', 10);
  const windowValue = params.get('window');
  return {
    window: VALID_WINDOWS.has(windowValue) ? windowValue : null,
    severities: orderedValues(params.get('severity'), SEVERITY_ORDER),
    types: orderedValues(params.get('type'), TYPE_ORDER),
    flags: orderedValues(params.get('flags'), FLAG_ORDER),
    page: Number.isSafeInteger(parsedPage) && parsedPage > 0 ? parsedPage : 1,
  };
}

export function serializeBriefQuery(state) {
  const normalized = parseBriefQuery(new URLSearchParams({
    ...(state?.window ? { window: state.window } : {}),
    ...(state?.severities?.length ? { severity: state.severities.join(',') } : {}),
    ...(state?.types?.length ? { type: state.types.join(',') } : {}),
    ...(state?.flags?.length ? { flags: state.flags.join(',') } : {}),
    ...(state?.page > 1 ? { page: String(state.page) } : {}),
  }));
  const params = new URLSearchParams();
  if (normalized.window) params.set('window', normalized.window);
  if (normalized.severities.length) params.set('severity', normalized.severities.join(','));
  if (normalized.types.length) params.set('type', normalized.types.join(','));
  if (normalized.flags.length) params.set('flags', normalized.flags.join(','));
  if (normalized.page > 1) params.set('page', String(normalized.page));
  return params.toString();
}

export function hasBriefFilters(state) {
  return Boolean(
    state?.window
    || state?.severities?.length
    || state?.types?.length
    || state?.flags?.length,
  );
}

function timestamp(value) {
  const result = Date.parse(value || '');
  return Number.isFinite(result) ? result : Number.NEGATIVE_INFINITY;
}

function hasFlag(item, flag) {
  if (Array.isArray(item.flags)) return item.flags.includes(flag);
  return item.flags?.[flag] === true;
}

export function filterBriefs(items, state, generatedAt) {
  const normalized = parseBriefQuery(serializeBriefQuery(state));
  const buildTime = timestamp(generatedAt);
  const cutoff = normalized.window === '24h' && Number.isFinite(buildTime)
    ? buildTime - DAY_MS
    : Number.NEGATIVE_INFINITY;

  return [...(Array.isArray(items) ? items : [])]
    .filter((item) => {
      if (timestamp(item.activity_at) < cutoff) return false;
      if (normalized.severities.length && !normalized.severities.includes(item.severity)) return false;
      if (normalized.types.length && !normalized.types.includes(item.type)) return false;
      if (normalized.flags.length && !normalized.flags.every((flag) => hasFlag(item, flag))) return false;
      return true;
    })
    .sort((left, right) => {
      const activityDifference = timestamp(right.activity_at) - timestamp(left.activity_at);
      if (activityDifference) return activityDifference;
      return String(left.url).localeCompare(String(right.url), 'en');
    });
}

export function paginateBriefs(items, requestedPage = 1, pageSize = 30) {
  const safeItems = Array.isArray(items) ? items : [];
  const safePageSize = Number.isSafeInteger(pageSize) && pageSize > 0 ? pageSize : 30;
  const totalItems = safeItems.length;
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / safePageSize);
  const candidatePage = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  const page = totalPages === 0 ? 1 : Math.min(candidatePage, totalPages);
  const offset = (page - 1) * safePageSize;
  return {
    items: safeItems.slice(offset, offset + safePageSize),
    page,
    pageSize: safePageSize,
    totalItems,
    totalPages,
    hasPrev: page > 1,
    hasNext: totalPages > 0 && page < totalPages,
  };
}

export function canonicalBriefURL(base, state, page = state?.page || 1) {
  const normalized = { ...state, page };
  const query = serializeBriefQuery(normalized);
  const path = String(base || '/briefs/').split('?')[0];
  return query ? `${path}?${query}` : path;
}

export function updateBriefQuery(state, change) {
  const next = parseBriefQuery(serializeBriefQuery({ ...state, page: 1 }));
  const { group, value } = change || {};
  if (group === 'window') {
    next.window = next.window === value ? null : (VALID_WINDOWS.has(value) ? value : null);
  }
  const groups = {
    severities: SEVERITY_ORDER,
    types: TYPE_ORDER,
    flags: FLAG_ORDER,
  };
  if (groups[group]?.includes(value)) {
    const selected = new Set(next[group]);
    if (selected.has(value)) selected.delete(value);
    else selected.add(value);
    next[group] = groups[group].filter((item) => selected.has(item));
  }
  next.page = 1;
  return next;
}

export function projectBriefControls(state) {
  const normalized = parseBriefQuery(serializeBriefQuery(state));
  const selected = {
    severities: Object.fromEntries(SEVERITY_ORDER.map((value) => [value, normalized.severities.includes(value)])),
    types: Object.fromEntries(TYPE_ORDER.map((value) => [value, normalized.types.includes(value)])),
    flags: Object.fromEntries(FLAG_ORDER.map((value) => [value, normalized.flags.includes(value)])),
  };
  return {
    windowLabel: normalized.window === '24h' ? 'Last 24 hours' : 'All time',
    severityLabel: normalized.severities.length ? `Severity · ${normalized.severities.length}` : 'Severity',
    active: hasBriefFilters(normalized),
    selected,
  };
}
