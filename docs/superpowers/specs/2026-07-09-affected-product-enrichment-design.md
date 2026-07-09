# Affected-Product Enrichment & STIX Exposure — Design

**Date:** 2026-07-09
**Status:** Approved (brainstorming), pending implementation plan
**Repos touched:** `ti-bot` (components 1–3), `threat-feed` (component 4 + regenerated artifacts)
**Spec location note:** kept in `threat-feed/docs/superpowers/specs/` because that is where this session runs and where prior specs live; the bulk of the code lands in `ti-bot`.

## Problem

A brief for Foxit (`CVE-2026-3779`, `site/content/briefs/2026-04-foxit-uaf.md`) is live on the site but does not appear when searching `/products/`. Investigation showed:

- `/products/` (and `/vendors/`) are **taxonomy term-filter** pages. The search box filters over declared *product term names* pulled from `index.json` — it is **not** a full-text search over brief bodies. A brief only appears if it declares the product in its `products:` frontmatter.
- The Foxit brief has **no `products:` and no `vendors:`** frontmatter — "Foxit" exists only as a `tag`. So there is no term to match. The page renders correctly; the data is missing.
- For CVE advisories, `products` = affected software and `vendors` = the vendor (confirmed against Webmin/Exim/Oracle/WordPress briefs). Both are populated from the brief's `affected_products` / `affected_vendors`, which come from `ti-bot`'s LLM extraction (`internal/pipeline/extraction.go`) over the **raw scraped source**, using a deliberately conservative prompt ("leave empty rather than guessing").
- The upstream CVE named only "an unspecified Foxit application", so the conservative extraction left both fields empty.
- `ti-bot` already classifies this case as unactionable: `isGenericCVEBundleBrief` (`internal/publisher/publisher_markdown.go`) suppresses CVE briefs with no vendor/product. The guard (added 2026-04-30) stops *new* ones and blocks *re-emission*, but does not delete already-published stragglers. Foxit is one such straggler.

Scope of the gap: **1,587 of 4,936 live briefs have no `products:`**; **1,130 of those mention a CVE** (exactly the "generic CVE" stragglers), concentrated in 2026-03 (401) and 2026-04 (767).

Two adjacent gaps surfaced during design:

- The public **STIX 2.1 feed** (`internal/publisher/stix.go`, served at `https://feed.craftedsignal.io/stix*`) carries indicators, attack-patterns, threat-actors and a report object — but **no affected vendor/product and no vulnerability objects**.
- The site **does not link or document the STIX feed anywhere**.

## Root cause

The finished brief carries enough signal to identify the vendor (title "Foxit Application", `foxit` tag, Foxit bulletin reference) and to *infer* the product (PDF page/form-object language → Foxit's PDF product line). The original extraction missed it because it ran over terser raw source with a no-inference prompt. A second, inference-permitting LLM pass over the brief recovers vendor and product.

## Goals

1. Foxit — and future CVE briefs like it — become findable in `/products/` and `/vendors/`.
2. Enrich **at the source** (the `BundleBrief` in the encrypted bundle) so every downstream consumer benefits: site markdown frontmatter, JSON/RSS feeds, the encrypted bundle consumed by the app/SDK/notifier, and STIX.
3. The public STIX feed carries affected vendor/product as first-class objects.
4. The STIX feed is documented and linked on the site.

## Non-goals

- Bulk-backfilling all ~1,130 stragglers now. The backfill tool (Component 2) is built to handle them, but this effort runs it only against the 2 Foxit briefs. Bulk run is a deferred follow-up.
- Changing the suppression policy (`isGenericCVEBundleBrief`) itself.
- Fetching external sources at backfill time. Inference works from the brief's own title/content/references.

## Decisions (from brainstorming)

| Question | Decision |
|---|---|
| What fills empty vendor/product? | A second **LLM pass** over the brief. |
| Product precision | **Infer** the likely product from context (grounded, no invented versions); fall back to vendor-name-as-product only when no product is identifiable. |
| Where does enriched data live? | **At the source** — written into the `BundleBrief`, not just the emitted markdown. |
| Scope now | Pipeline fallback (future briefs) + backfill the **2 Foxit briefs**. |
| STIX objects | **`software` SCO + `vulnerability` SDO** (plus relationships). |
| Packaging | **One spec, phased.** |

## Architecture

### Shared unit — `inferVendorProduct`

New file `ti-bot/internal/pipeline/vendor_infer.go`.

```
func inferVendorProduct(ctx context.Context, client llm.Client, title, content string)
    (vendors []string, products []string, err error)
```

- **Purpose:** given a brief's title + content, return the affected vendor(s) and product(s).
- **Prompt policy (distinct from the conservative `extractionSystemPrompt`):**
  - Use canonical vendor names, no version numbers.
  - *Infer* the specific product when the vendor's product line and the vulnerability context make it clear (e.g. Foxit + PDF page/form objects → "Foxit PDF Reader", "Foxit PDF Editor").
  - Never invent version numbers or unrelated products.
  - If a vendor is identifiable but no specific product is, return the vendor name as the product (so the brief is still findable in `/products/`).
  - Ground everything in the supplied text.
- **Output validation:** JSON `{affected_vendors:[], affected_products:[]}`; trim; drop entries failing `hasMeaningfulString` (empty / "unknown" / "n/a" / "tbd" / "none" / "null" / "na"); de-dup; cap list length (e.g. ≤ 8).
- **Consumed by:** Component 1 (pipeline) and Component 2 (backfill). One implementation, one prompt, one set of guardrails.

### Component 1 — Pipeline fallback (ti-bot)

- **Where:** `internal/pipeline/pipeline.go`, `processItem`, immediately after the existing `p.extractor.Extract(ctx, item)` (around line 650) and its post-extraction dedup, before the brief YAML is built.
- **Trigger:** `extraction != nil` **and** the item carries a CVE (using the pipeline package's own CVE regex, `cveRe`, over title/content — not the publisher's `genericCVERe`, which lives in a different package) **and** both `extraction.AffectedVendors` and `extraction.AffectedProducts` are empty (per a pipeline-local equivalent of `hasMeaningfulString`; that helper currently lives in the publisher package, so either duplicate the small check or share it). This keeps LLM calls minimal — it only fires for exactly the briefs the suppression guard would otherwise drop.
- **Action:** call `inferVendorProduct(ctx, p's LLM client, item.Title, item.Content)`; on success, set `extraction.AffectedVendors` / `extraction.AffectedProducts`. Brief build (`brief.go`) and the persisted draft then carry the values, which flow into the bundle and all emitted artifacts. The brief now passes `isGenericCVEBundleBrief`.
- **LLM client:** reuse the pipeline's existing extractor client (confirm the concrete field during planning).
- **Failure handling:** on error, log a warning and continue with empty fields (brief stays as-is → still suppressed if generic). Never block the pipeline.

### Component 2 — Foxit backfill subcommand (ti-bot)

- **New subcommand** under `cmd/ti-bot/` (e.g. `ti-bot enrich-vendors --slug <slug> [--slug <slug> ...]`), modeled on `Publisher.MigrateBundle` for the bundle read/modify/write dance.
- **Flow:**
  1. Fetch manifest; identify segment(s) containing the target briefs.
  2. Decrypt segment → for each target brief with empty vendor/product, run `inferVendorProduct(ctx, llm, brief.Title, brief.Content)`.
  3. Write `AffectedVendors` / `AffectedProducts` back onto the `BundleBrief`.
  4. Re-encrypt and push the segment (durable — the source of truth, not just markdown).
  5. Re-emit each brief's markdown via the existing `publishBriefMarkdown` path; enriched briefs now pass the guard.
- **Idempotent:** skips briefs that already have meaningful vendor/product; safe to re-run.
- **This run:** invoked with the two Foxit slugs (`2026-04-foxit-uaf`, `2026-04-untrusted-search-path`). Same command later takes the full straggler set for the deferred bulk backfill.
- **Guardrail:** the backfill has only the brief's own content to work from (no re-fetch of upstream sources), so results are as good as the brief text supports — expected outcome for Foxit: vendor "Foxit", product "Foxit PDF Reader" / "Foxit PDF Editor" (or "Foxit" if the model won't infer).

### Component 3 — STIX vendor/product + vulnerability (ti-bot `stix.go`)

Extend `ExportSTIX` so each brief additionally emits:

- **`software` SCO per affected product:** `{ type: "software", id: stixID("software", vendor+":"+product), name: product, vendor: <vendor>, cpe: <cpe if available from b.CPEs> }`. Added to the report's `object_refs`.
  - **Vendor↔product pairing:** `AffectedVendors` and `AffectedProducts` are independent lists. If exactly one vendor, apply it to all products; if multiple or none, emit the product with vendor omitted (or best-effort). Documented as a known simplification.
- **`vulnerability` SDO per CVE** (`b.CVEs`): `{ type: "vulnerability", name: <CVE-ID>, external_references: [{source_name:"cve", external_id:<CVE-ID>, url: nvd-url}] }`. Added to `object_refs`. (Closes the current gap where STIX emits no vulnerability objects at all.)
- **Relationships:** `software --has--> vulnerability` (custom `has` relationship type, allowed in STIX 2.1), and report→object relationships consistent with the existing pattern.
- **Determinism:** follow the existing `stixID`/`uuidV5` scheme so output stays byte-stable (there is a determinism test — `TestExportSTIX_Deterministic` — to keep green).
- **New struct types:** `stixSoftware`, `stixVulnerability` alongside the existing ones.

### Component 4 — STIX discoverability (threat-feed Hugo)

- **`content/api/_index.md`:** add a "STIX 2.1" section documenting the three URLs (`/stix.json` = last 30 days; `/stix/YYYY-MM.json` = monthly, 90-day window; `/stix/index.json` = manifest), the object types now present (report, indicator, attack-pattern, threat-actor, **software**, **vulnerability**), and the no-auth/static-CDN note. Retitle framing so the page covers RSS + JSON Feed + STIX.
- **`layouts/partials/footer.html`:** add a STIX link in the "Subscribe" column (e.g. `STIX 2.1 → /stix.json`).

## Data flow

```
raw source ──Extract (conservative)──► extraction (vendor/product often empty)
                                            │
                     C1: if CVE & empty ──► inferVendorProduct (LLM, inference-permitting)
                                            │
                                            ▼
                              brief YAML (affected_vendors/products)
                                            │
                                     draft ─┴─► bundle (BundleBrief)  ◄── C2 backfill writes here
                                            │
             ┌──────────────┬──────────────┼───────────────┬────────────────┐
             ▼              ▼              ▼               ▼                ▼
   site markdown     JSON/RSS feed   encrypted bundle   STIX (C3:          (all consumers
   products:/vendors:  products/       (app/SDK/          software+          consistent)
   → /products/ search  vendors        notifier)         vulnerability)
```

## Error handling

- **Pipeline (C1):** LLM error → warn + continue; never blocks item processing.
- **Backfill (C2):** per-brief failure → log, skip that brief, continue; non-zero summary of successes/failures. Bundle push failures surface as command errors.
- **LLM output:** validated (non-empty, non-boilerplate) before it is written anywhere.
- **STIX (C3):** software/vulnerability emission is additive; briefs without vendor/product/CVE simply emit none (no empty objects).

## Testing

- **`inferVendorProduct`:** unit test with a mock `llm.Client` — Foxit-shaped input yields vendor "Foxit" + a Foxit PDF product; boilerplate/empty input yields empty; validation drops junk values.
- **C1:** pipeline test that a CVE item with empty extracted vendor/product gets fields populated from the fallback (mock LLM), and that a non-CVE or already-populated item does **not** trigger the extra call.
- **C3:** extend `stix_test.go` — a brief with vendor/product/CVE emits deterministic `software` + `vulnerability` + relationship objects; empty brief unchanged; determinism test stays green.
- **C2:** test the backfill against an in-memory/mock bundle (enrich → fields written → markdown re-emitted).
- **Manual end-to-end verification:** run the backfill against the 2 Foxit slugs → rebuild the Hugo site → confirm `/products/` search for "foxit" returns the brief and `/vendors/foxit/` exists. (Use the `verify` skill.)

## Phasing (independently shippable)

1. **Phase 1 — Enrichment core:** `inferVendorProduct` + Component 1 pipeline hook + tests.
2. **Phase 2 — Backfill:** Component 2 subcommand + tests; run against the 2 Foxit briefs; verify end-to-end on the site.
3. **Phase 3 — STIX:** Component 3 software + vulnerability objects + tests.
4. **Phase 4 — Discoverability:** Component 4 `/api/` docs + footer link.

## Open items to confirm during planning

- Exact LLM client handle exposed on the `Pipeline` struct for reuse in C1.
- Whether the backfill re-emits STIX in the same run or relies on the next scheduled publish (STIX rebuilds from the bundle on publish; a manual `PublishSTIXBundle` call can be added to the subcommand).
- CPE→`software.cpe` population when `b.CPEs` is non-empty vs. absent.
