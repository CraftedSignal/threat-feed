# Public Feed Contract and UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce public artifact quality, publish truthful feed contracts, and make complete Last 24 hours filtering bookmarkable and usable across desktop and mobile.

**Architecture:** Hugo keeps the default server-rendered list and emits one compact full-corpus index for filtered browsing. A pure JavaScript filter module owns URL state and filtering-before-pagination, while `app.js` binds it to accessible controls. A Go artifact checker protects changed Markdown, STIX, and generated sitemap outputs in CI.

**Tech Stack:** Go 1.27, Hugo 0.168+, JavaScript ES2020, Node 24 test runner, Tailwind CSS, Pagefind.

**Spec:** `docs/superpowers/specs/2026-10-20-feed-contract-and-ui-design.md`

## Global Constraints

- `/briefs/?window=24h` is the canonical Last 24 hours URL.
- Filter state must survive reload, sharing, clean-profile open, Back/Forward, and filtered pagination without browser storage.
- Filtering happens across the full canonical corpus before 30-item pagination.
- Unfiltered pages remain server-rendered and usable without JavaScript.
- Existing feed URLs remain stable; exact-high feeds are labeled High only.
- Changed public artifacts fail deployment on semantic or STIX contract violations.
- Generated content is not manually rewritten as part of UI work.

## Review Focus

- A build occurring near the 24-hour boundary must use one consistent cutoff across all items and result pages.
- Unknown query keys/values must be ignored or canonicalized without breaking navigation.
- Back/Forward must restore controls, result count, page, and items without duplicate history entries.
- Legacy pages missing new metadata must render safely while changed pages fail stronger validation.
- The filter index must stay compact and must not duplicate full rendered HTML for every brief.

---

### Task 1: Public artifact checker

**Files:**
- Create: `internal/publicfeed/check.go`
- Create: `internal/publicfeed/check_test.go`
- Create: `cmd/feedcheck/main.go`
- Test: `internal/publicfeed/check_test.go`

**Interfaces:**
- Produces: `CheckBrief(path string, data []byte) []Issue`, `CheckSTIX(path string, data []byte) []Issue`, `CheckSitemap(data []byte) []Issue`, and a CLI accepting explicit paths plus `--generated-site`.
- Consumes: canonical ATT&CK catalog from `pkg/mitre`.

- [ ] **Step 1: Write failing table tests** for missing identity/revision fields, undeclared public CVEs, noncanonical ATT&CK names, unsourced threat/rumour, contradictory exploit evidence, active raw HTML, duplicate/conflicting STIX IDs, missing report refs, imprecise timestamps, missing canonical URLs, report-count mismatch, and duplicate sitemap locations.
- [ ] **Step 2: Run** `go test ./internal/publicfeed -count=1` and confirm failures.
- [ ] **Step 3: Implement** parsers and deterministic issue reporting; legacy mode is explicit and the CLI defaults to strict checks for paths passed by CI.
- [ ] **Step 4: Implement** the CLI with nonzero exit on any error-severity issue and concise file/field diagnostics.
- [ ] **Step 5: Run** focused tests and `go test ./cmd/feedcheck ./internal/publicfeed -count=1`.
- [ ] **Step 6: Commit** with message `feat(feed): validate public feed artifacts`.

### Task 2: Changed-artifact deployment gates

**Files:**
- Modify: `.github/workflows/site.yml`
- Modify: `internal/workflowconfig/site_workflow_test.go`
- Test: `internal/workflowconfig/site_workflow_test.go`

**Interfaces:**
- Consumes: `go run ./cmd/feedcheck` from Task 1.
- Produces: PR and production validation steps for changed briefs/STIX plus generated sitemap validation.

- [ ] **Step 1: Write failing workflow-structure tests** requiring a full-history checkout, a deterministic base SHA, changed artifact collection, feedcheck before Hugo deploy, and generated sitemap checking after build.
- [ ] **Step 2: Run** the focused workflowconfig tests and confirm failure.
- [ ] **Step 3: Add** the validation steps with empty-change handling and shell-safe path transport; unchanged legacy briefs are not passed to strict mode.
- [ ] **Step 4: Run** workflowconfig and full Go tests.
- [ ] **Step 5: Commit** with message `ci(site): gate changed feed artifacts`.

### Task 3: Full-corpus filter index and pure query engine

**Files:**
- Modify: `site/hugo.toml`
- Create: `site/content/briefs/_index.md`
- Create: `site/layouts/briefs/list.briefindex.json`
- Create: `site/assets/js/brief-filters.js`
- Create: `site/assets/js/brief-filters.test.js`
- Modify: `site/package.json`
- Test: `site/assets/js/brief-filters.test.js`

**Interfaces:**
- Produces: `/briefs/index.json`; `parseBriefQuery`, `serializeBriefQuery`, `filterBriefs`, `paginateBriefs`, and `canonicalBriefURL`.
- Index fields: canonical URL, title, summary, activity/published/modified timestamps, severity, type, flags, primary product/actor, capped display tags, and CVE/TTP/rule/IOC counts.

- [ ] **Step 1: Write failing Node tests** for canonical parsing/serialization, unknown values, a single build-time 24-hour boundary, combined filters, filtering-before-pagination, empty/out-of-range pages, and query-preserving pagination URLs.
- [ ] **Step 2: Run** `npm test -- --test-name-pattern='brief filters'` and confirm failures.
- [ ] **Step 3: Implement** the pure module with no DOM dependency and stable result ordering.
- [ ] **Step 4: Add** the compact Hugo output format and index layout without embedding rendered card HTML.
- [ ] **Step 5: Build** Hugo and assert the index item count equals the briefs section's canonical page count and JSON parses successfully.
- [ ] **Step 6: Commit** with message `feat(site): publish full brief filter index`.

### Task 4: Addressable accessible filter UI

**Files:**
- Modify: `site/assets/js/app.js`
- Modify: `site/assets/js/brief-filters.js`
- Modify: `site/assets/js/brief-filters.test.js`
- Modify: `site/layouts/briefs/list.html`
- Modify: `site/layouts/partials/briefs-pagination.html`
- Modify: `site/layouts/partials/brief-card.html` only for a reusable client-render contract or accessibility metadata
- Modify: `site/assets/css/main.css`
- Test: `site/assets/js/brief-filters.test.js`

**Interfaces:**
- Consumes: Task 3 query/index interfaces.
- Produces: committed URL state, `popstate` restoration, full filtered rendering, result summary/live region, and query-preserving pagination.

- [ ] **Step 1: Add failing tests** for control-state projection, Back/Forward state inputs, Last 24 hours returning all fixture matches across pages, and clean URL removal when all filters are cleared.
- [ ] **Step 2: Run** the focused Node tests and confirm failure.
- [ ] **Step 3: Replace** page-local filtering with lazy full-index retrieval and filter-before-pagination rendering; keep the unfiltered server-rendered page untouched until the first committed filter.
- [ ] **Step 4: Implement** `pushState`/`popstate`, canonical query pagination, loading/error/empty states, and a polite result-count live region.
- [ ] **Step 5: Add** `aria-expanded`, `aria-controls`, `aria-pressed`, Escape/focus return, visible focus, 44px targets, and reduced-motion behavior.
- [ ] **Step 6: Run** Node tests and a Hugo build; inspect generated `/briefs/?window=24h` controls and `/briefs/index.json` contract.
- [ ] **Step 7: Commit** with message `fix(site): make brief filters complete and shareable`.

### Task 5: Mobile triage facts and revision history

**Files:**
- Create: `site/layouts/partials/brief-triage.html`
- Modify: `site/layouts/briefs/single.html`
- Modify: `site/layouts/advisory/single.html`
- Modify: `site/layouts/threat/single.html`
- Modify: `site/layouts/rumour/single.html`
- Modify: `site/layouts/coverage/single.html`
- Modify: `site/assets/css/main.css`
- Test: generated Hugo detail fixtures

**Interfaces:**
- Consumes: new identity, revision, evidence, QA/source, priority, CVE, product, and rule frontmatter with safe fallbacks.
- Produces: first-screen mobile triage block and explicit append-only revision presentation.

- [ ] **Step 1: Add** a minimal Hugo fixture/assertion script that fails until triage labels and revision metadata are present in each single-page kind.
- [ ] **Step 2: Create** the shared partial with applicability, evidence, severity/priority, sources, freshness/revision, and detection facts; omit absent values.
- [ ] **Step 3: Include** it before long-form prose on mobile and reconcile the existing desktop sidebar/What's new block so information is not repeated excessively.
- [ ] **Step 4: Build** Hugo and inspect representative advisory, threat, coverage, rumour, and legacy pages at desktop/mobile widths when browser tooling is available.
- [ ] **Step 5: Commit** with message `feat(site): surface mobile triage and revisions`.

### Task 6: Truthful syndication and discovery contracts

**Files:**
- Modify: `site/hugo.toml`
- Modify: `site/content/api/_index.md`
- Modify: `site/content/about.md`
- Modify: `site/layouts/partials/footer.html`
- Modify: `site/layouts/partials/head.html`
- Create: `site/layouts/sitemap.xml`
- Create or modify: `site/layouts/robots.txt`
- Test: generated feed/API/sitemap assertions

**Interfaces:**
- Produces: JSON Feed 1.1 documentation, 2,000-item RSS retention, exact-high labels, canonical nonempty discovery links, validated STIX documentation, unique sitemap, and robots declaration.

- [ ] **Step 1: Add** generated-output assertions for JSON documentation keys, RSS item retention on a fixture, High only labels, alternate links, unique sitemap locations, and `Sitemap:` in robots.txt.
- [ ] **Step 2: Apply** copy/config/template changes and a unique canonical sitemap template.
- [ ] **Step 3: Run** Hugo + generated-output assertions and confirm the API page describes the actual live schema.
- [ ] **Step 4: Commit** with message `fix(site): align public feed contracts`.

### Task 7: Whole-repository verification

**Files:**
- Modify: documentation only if verification reveals a contract mismatch.

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: verified threat-feed branch ready for integration after regenerated STIX arrives from ti-bot.

- [ ] **Step 1: Run** `gofmt` on changed Go files, the Node test suite, `git diff --check`, and `go test ./... -count=1` with a writable `GOCACHE`.
- [ ] **Step 2: Run** `npm ci`, `npm test`, `hugo --gc --minify`, and Pagefind against the production output.
- [ ] **Step 3: Run** feedcheck on every changed brief/STIX artifact and the generated sitemap.
- [ ] **Step 4: Run** Impeccable detector once on changed site markup and resolve material findings in one bounded batch.
- [ ] **Step 5: Review** both repository diffs together against the two specs, including the cross-repo frontmatter/STIX interfaces.
