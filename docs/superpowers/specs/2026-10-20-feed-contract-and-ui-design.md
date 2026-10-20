# Public feed contract and UI design

## Intent

Make the public threat feed reproducible for people and machines. Readers must be able to retrieve the complete Last 24 hours result set, bookmark it, share it, paginate it, and understand why an item matters. Feed endpoints must describe their real retention and fields, and newly generated briefs or STIX artifacts must be rejected when they violate the public contract.

## Approved product decisions

- The time shortcut is named **Last 24 hours**.
- Its state is canonical URL state: `/briefs/?window=24h`.
- Activity time is the later of immutable first publication and the most recent material revision.
- Browser reload, bookmark open, clean-profile open, Back/Forward, and pagination restore the same query and results.
- Publication history is append-only and visible on detail pages.
- STIX is a production format after it satisfies exact parity and structural validation; documentation must not call a known-invalid export production-ready.

## Complete filtering

The existing server-rendered first page remains the default fast, crawlable view. Hugo also emits `/briefs/index.json`, a compact index of every canonical brief containing the fields required for the visible card and filter controls. The browser fetches this index only when a filter query is present or a user commits the first filter.

Canonical parameters are:

- `window=24h`
- `severity=critical,high` using canonical severity keys
- `type=threat,advisory,coverage,rumour`
- `flags=poc,exploited,ioc`
- `page=N` for the filtered collection

Committed changes use `history.pushState`; restoration uses `popstate`. All filter state is derivable from the URL without local or session storage. Filtering precedes pagination. The page presents a result summary and retains query parameters in next/previous links. Last 24 hours uses a single build timestamp embedded in the index so every client sees one internally consistent boundary for that build.

## Reading experience

Desktop keeps the established compact card grammar. Mobile gets a first-screen Triage facts block before long-form prose with applicability, affected product/version, exploitation evidence, technical severity, action priority/reason, source count, publication/revision time, and detection availability. The block uses data already present in public frontmatter and omits unavailable facts rather than inventing them.

Filter menus expose expanded and selected state, support Escape and focus return, announce result-count changes, and provide at least 44 CSS-pixel targets. Motion respects `prefers-reduced-motion`. Visible labels replace hover-only abbreviations on touch layouts.

## Public feed contracts

- JSON documentation uses the live JSON Feed 1.1 field names and `_cs_*` extensions.
- RSS is explicitly a recent-items channel and retains 2,000 items, enough to cover the audited bursty month; JSON pagination remains the completeness contract.
- The existing exact-high endpoint is labeled **High only** everywhere. No label may imply critical items are included.
- Alternate-feed discovery points to nonempty canonical feeds.
- STIX documentation describes the validated object set, stable IDs/versioning, canonical brief URLs, monthly/rolling scopes, and manifest metadata.
- A custom sitemap emits each canonical URL once, stays below the protocol limit, and declares itself in `robots.txt`.

## Deployment gates

A Go checker validates changed public Markdown and STIX artifacts without requiring network access:

- changed briefs have immutable identity/revision fields, structured CVEs for every public CVE token, canonical ATT&CK names, required sources for threats/rumours, safe public HTML, and noncontradictory exploitation evidence;
- STIX bundles have unique object representations, millisecond timestamps, resolvable report references, canonical CraftedSignal URLs, and report counts matching manifest metadata;
- generated sitemap locations are unique and below the protocol limit.

Pull requests validate changed artifacts. Production site builds validate every STIX file changed since the prior successful deployment and every changed brief. Legacy unchanged pages do not block rollout, while any newly emitted regression does.

## Compatibility

- Unfiltered `/briefs/` and its existing page URLs remain server-rendered and usable without JavaScript.
- Existing feed URLs remain stable.
- Old briefs missing new frontmatter render with conservative fallbacks; new or changed briefs must satisfy the stronger contract.
- No generated brief prose is rewritten by the UI work.

## Verification

- Pure JavaScript tests cover query parsing, canonical serialization, 24-hour boundaries, filtering-before-pagination, and history restoration inputs.
- Hugo build fixtures prove the full index contains all canonical pages and filtered pagination returns the full fixture set.
- Go tests cover Markdown/STIX/sitemap validation.
- A production Hugo + Pagefind build and the full Go suite pass.
