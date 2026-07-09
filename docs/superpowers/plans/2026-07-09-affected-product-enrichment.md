# Affected-Product Enrichment & STIX Exposure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CVE briefs that lack an affected vendor/product (e.g. Foxit CVE-2026-3779) findable in `/products/` and `/vendors/` by inferring the fields with an LLM at the source, expose affected vendor/product + vulnerability objects in the public STIX feed, and document/link the STIX feed on the site.

**Architecture:** A shared, inference-permitting LLM function `pipeline.InferVendorProduct` fills empty `affected_vendors`/`affected_products`. The pipeline calls it for new CVE briefs (bakes it into the draft → bundle → all feeds). A `ti-bot` backfill subcommand runs the same function over selected briefs already in the encrypted bundle and re-emits them. The STIX exporter gains `software` SCOs + `vulnerability` SDOs. The Hugo site documents and links the STIX feed.

**Tech Stack:** Go (ti-bot), Hugo/Markdown + Tailwind (threat-feed), STIX 2.1 JSON.

## Global Constraints

- `pipeline` is imported by `publisher` (not vice-versa). The shared inference function MUST live in package `pipeline` so both callers can reach it without an import cycle.
- LLM access is via `llm.Client`: `Generate(ctx, prompt, system) (string, error)` and `GenerateJSON(ctx, prompt, system string, out any) error`.
- Vendor/product "meaningful" filter drops (case-insensitive, trimmed): `""`, `unknown`, `n/a`, `tbd`, `none`, `null`, `na`, `unspecified`.
- Never invent version numbers or unrelated products in prompts.
- STIX output MUST stay deterministic (there is a `TestExportSTIX_Deterministic` test): iterate slices, never maps, when emitting objects.
- ti-bot code lives at `/Users/niels/Source/craftedsignal/ti-bot`; site code + the design docs live at `/Users/niels/Source/craftedsignal/threat-feed`.
- Foxit target slugs: `2026-04-foxit-uaf`, `2026-04-untrusted-search-path`.

## Branch setup (do once, before Phase 1)

- [ ] In ti-bot: `cd /Users/niels/Source/craftedsignal/ti-bot && git checkout -b feat/affected-product-enrichment`
- threat-feed already has branch `feat/affected-product-enrichment` (holds the spec). Phase 4 + the backfill run commit there.

---

## Phase 1 — Enrichment core (ti-bot)

### Task 1: `InferVendorProduct` shared function

**Files:**
- Create: `/Users/niels/Source/craftedsignal/ti-bot/internal/pipeline/vendor_infer.go`
- Test: `/Users/niels/Source/craftedsignal/ti-bot/internal/pipeline/vendor_infer_test.go`

**Interfaces:**
- Produces: `func InferVendorProduct(ctx context.Context, client llm.Client, title, content string) (vendors, products []string, err error)`; helpers `meaningful(string) bool`, `hasMeaningfulEntry([]string) bool`, `sanitizeEntries([]string) []string`.

- [ ] **Step 1: Write the failing test**

```go
package pipeline

import (
	"context"
	"encoding/json"
	"testing"
)

type inferMockLLM struct {
	resp string
	err  error
}

func (m *inferMockLLM) Generate(context.Context, string, string) (string, error) {
	return m.resp, m.err
}

func (m *inferMockLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	if m.err != nil {
		return m.err
	}
	return json.Unmarshal([]byte(m.resp), out)
}

func TestInferVendorProduct_Foxit(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader","Foxit PDF Editor"]}`}
	v, p, err := InferVendorProduct(context.Background(), m,
		"Foxit Application Use-After-Free (CVE-2026-3779)", "use-after-free in PDF page/form objects")
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v[0] != "Foxit" {
		t.Errorf("vendors = %v, want [Foxit]", v)
	}
	if len(p) != 2 {
		t.Errorf("products = %v, want 2", p)
	}
}

func TestInferVendorProduct_DropsJunk(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit","unknown",""],"affected_products":["unspecified"]}`}
	v, p, _ := InferVendorProduct(context.Background(), m, "t", "c")
	if len(v) != 1 || v[0] != "Foxit" {
		t.Errorf("vendors = %v, want [Foxit]", v)
	}
	if len(p) != 0 {
		t.Errorf("products = %v, want empty ('unspecified' dropped)", p)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/pipeline/ -run TestInferVendorProduct -v`
Expected: FAIL — `undefined: InferVendorProduct`.

- [ ] **Step 3: Write the implementation**

Create `internal/pipeline/vendor_infer.go`:

```go
package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/craftedsignal/ti-bot/internal/llm"
)

const vendorInferSystemPrompt = `You are a vulnerability analyst. From the threat brief, identify the AFFECTED vendor(s) and product(s) — the software or service that is vulnerable, not detection tools.

Rules:
- Use canonical vendor names, no version numbers (e.g. "Foxit", "Microsoft", "Cisco").
- Infer the specific affected product when the vendor's product line and the vulnerability context make it clear. Example: a Foxit vulnerability involving PDF page/form objects affects "Foxit PDF Reader" and "Foxit PDF Editor".
- Never invent version numbers, CVE-specific claims, or products unrelated to the brief.
- If you can identify the vendor but not a specific product, use the vendor name as the product.
- Ground every answer in the provided text. If no vendor is identifiable, return empty lists.

Respond ONLY with JSON: {"affected_vendors": [], "affected_products": []}`

const vendorInferPrompt = `Identify the affected vendor(s) and product(s):

Title: %s

Content:
%s`

type vendorProductResult struct {
	AffectedVendors  []string `json:"affected_vendors"`
	AffectedProducts []string `json:"affected_products"`
}

// InferVendorProduct asks the LLM to identify the affected vendor(s) and
// product(s) for a brief, permitting grounded inference of the product when the
// source did not name one. Returns sanitized, de-duplicated lists.
func InferVendorProduct(ctx context.Context, client llm.Client, title, content string) (vendors, products []string, err error) {
	c := content
	if len(c) > 12000 {
		c = c[:12000]
	}
	prompt := fmt.Sprintf(vendorInferPrompt, title, c)

	var res vendorProductResult
	if err := client.GenerateJSON(ctx, prompt, vendorInferSystemPrompt, &res); err != nil {
		return nil, nil, fmt.Errorf("vendor/product inference LLM call: %w", err)
	}
	return sanitizeEntries(res.AffectedVendors), sanitizeEntries(res.AffectedProducts), nil
}

// meaningful reports whether s is a real value rather than a placeholder.
func meaningful(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "unknown", "n/a", "tbd", "none", "null", "na", "unspecified":
		return false
	}
	return true
}

// hasMeaningfulEntry reports whether any entry in items is meaningful.
func hasMeaningfulEntry(items []string) bool {
	for _, s := range items {
		if meaningful(s) {
			return true
		}
	}
	return false
}

// sanitizeEntries trims, drops placeholders, de-duplicates (case-insensitive),
// and caps the list at 8 entries.
func sanitizeEntries(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range items {
		s = strings.TrimSpace(s)
		key := strings.ToLower(s)
		if !meaningful(s) || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
		if len(out) >= 8 {
			break
		}
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/pipeline/ -run TestInferVendorProduct -v`
Expected: PASS (both cases).

- [ ] **Step 5: Commit**

```bash
cd /Users/niels/Source/craftedsignal/ti-bot
git add internal/pipeline/vendor_infer.go internal/pipeline/vendor_infer_test.go
git commit -m "feat(pipeline): add InferVendorProduct LLM fallback

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `applyVendorProductFallback` trigger logic

**Files:**
- Modify: `/Users/niels/Source/craftedsignal/ti-bot/internal/pipeline/vendor_infer.go`
- Test: `/Users/niels/Source/craftedsignal/ti-bot/internal/pipeline/vendor_infer_test.go`

**Interfaces:**
- Consumes: `InferVendorProduct`, `hasMeaningfulEntry` (Task 1); `cveRe` (`internal/pipeline/verify_cve.go`, `regexp.MustCompile(\`CVE-\d{4}-\d{4,}\`)`); `scraper.RawItem` (`.SourceID`, `.Title`, `.Content`); `ExtractionResult` (`.AffectedVendors`, `.AffectedProducts`).
- Produces: `func applyVendorProductFallback(ctx context.Context, client llm.Client, logger *slog.Logger, item scraper.RawItem, extraction *ExtractionResult) bool`.

- [ ] **Step 1: Write the failing test**

Append to `internal/pipeline/vendor_infer_test.go`:

```go
func TestApplyFallback_FiresForGenericCVE(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader"]}`}
	ex := &ExtractionResult{}
	item := scraper.RawItem{SourceID: "x", Title: "CVE-2026-3779 Foxit UAF", Content: "pdf form objects"}
	if !applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Fatal("expected fallback to fire")
	}
	if len(ex.AffectedVendors) != 1 || ex.AffectedVendors[0] != "Foxit" {
		t.Errorf("vendors = %v", ex.AffectedVendors)
	}
	if len(ex.AffectedProducts) != 1 {
		t.Errorf("products = %v", ex.AffectedProducts)
	}
}

func TestApplyFallback_SkipsNoCVE(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader"]}`}
	ex := &ExtractionResult{}
	item := scraper.RawItem{Title: "Some malware campaign", Content: "no cve identifier here"}
	if applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Error("should not fire without a CVE")
	}
}

func TestApplyFallback_SkipsWhenPopulated(t *testing.T) {
	m := &inferMockLLM{resp: `{"affected_vendors":["Wrong"],"affected_products":["Wrong"]}`}
	ex := &ExtractionResult{AffectedVendors: []string{"Microsoft"}}
	item := scraper.RawItem{Title: "CVE-2026-0001 thing", Content: "c"}
	if applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Error("should not fire when vendor already present")
	}
	if ex.AffectedVendors[0] != "Microsoft" {
		t.Error("must not overwrite existing vendor")
	}
}

func TestApplyFallback_LLMErrorIsSafe(t *testing.T) {
	m := &inferMockLLM{err: errors.New("llm down")}
	ex := &ExtractionResult{}
	item := scraper.RawItem{Title: "CVE-2026-0002 thing", Content: "c"}
	if applyVendorProductFallback(context.Background(), m, slog.Default(), item, ex) {
		t.Error("must return false on LLM error")
	}
}
```

Add imports `errors`, `log/slog`, and `github.com/craftedsignal/ti-bot/internal/scraper` to the test file's import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/pipeline/ -run TestApplyFallback -v`
Expected: FAIL — `undefined: applyVendorProductFallback`.

- [ ] **Step 3: Write the implementation**

Append to `internal/pipeline/vendor_infer.go` (add `"log/slog"` and `"github.com/craftedsignal/ti-bot/internal/scraper"` to its imports):

```go
// applyVendorProductFallback fills empty affected vendor/product on a CVE brief
// by inferring them from the item. Returns true if it changed the extraction.
// Only fires for CVE-bearing items where both fields are empty — exactly the
// briefs isGenericCVEBundleBrief would otherwise suppress. Never blocks: any
// LLM error is logged and reported as "did not fire".
func applyVendorProductFallback(ctx context.Context, client llm.Client, logger *slog.Logger, item scraper.RawItem, extraction *ExtractionResult) bool {
	if client == nil || extraction == nil {
		return false
	}
	if !cveRe.MatchString(item.Title) && !cveRe.MatchString(item.Content) {
		return false
	}
	if hasMeaningfulEntry(extraction.AffectedVendors) || hasMeaningfulEntry(extraction.AffectedProducts) {
		return false
	}
	vendors, products, err := InferVendorProduct(ctx, client, item.Title, item.Content)
	if err != nil {
		logger.Warn("vendor/product inference failed", "source_id", item.SourceID, "error", err)
		return false
	}
	if len(vendors) == 0 && len(products) == 0 {
		return false
	}
	extraction.AffectedVendors = vendors
	extraction.AffectedProducts = products
	logger.Info("inferred vendor/product for generic CVE brief",
		"source_id", item.SourceID, "vendors", vendors, "products", products)
	return true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/pipeline/ -run TestApplyFallback -v`
Expected: PASS (all four cases).

- [ ] **Step 5: Commit**

```bash
cd /Users/niels/Source/craftedsignal/ti-bot
git add internal/pipeline/vendor_infer.go internal/pipeline/vendor_infer_test.go
git commit -m "feat(pipeline): add vendor/product fallback trigger for generic CVE briefs

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire the fallback into `processItem`

**Files:**
- Modify: `/Users/niels/Source/craftedsignal/ti-bot/internal/pipeline/pipeline.go` (struct ~line 31, `New` ~line 198, `processItem` ~line 654)

**Interfaces:**
- Consumes: `applyVendorProductFallback` (Task 2); `cfg.LLMClient` (already passed to `NewThreatExtractor`).

- [ ] **Step 1: Add an `llmClient` field to the Pipeline struct**

In the `type Pipeline struct { ... }` block, add after the `extractor` field:

```go
	llmClient             llm.Client
```

(Confirm `"github.com/craftedsignal/ti-bot/internal/llm"` is imported in pipeline.go; extraction.go already imports it in-package, but each file needs its own import — add it to pipeline.go's import block if absent.)

- [ ] **Step 2: Set the field in `New`**

In `func New(cfg Config) *Pipeline`, in the returned struct literal, alongside `extractor: NewThreatExtractor(cfg.LLMClient),` add:

```go
		llmClient:             cfg.LLMClient,
```

- [ ] **Step 3: Call the fallback after extraction in `processItem`**

Immediately after the extraction block that ends around line 654 (the `if item.SigmaRule == nil { extraction, extractErr = p.extractor.Extract(ctx, item) ... }` block), insert:

```go
	// Recover CVE briefs whose source never named an affected vendor/product
	// (they would otherwise be dropped by isGenericCVEBundleBrief). Infer the
	// fields from the item before the brief YAML is built so the value flows
	// into the draft, bundle, and every emitted feed.
	if extraction != nil {
		applyVendorProductFallback(ctx, p.llmClient, p.logger, item, extraction)
	}
```

- [ ] **Step 4: Build and run the full pipeline test suite**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go build ./... && go test ./internal/pipeline/ -v`
Expected: build succeeds; all tests PASS (no regressions).

- [ ] **Step 5: Commit**

```bash
cd /Users/niels/Source/craftedsignal/ti-bot
git add internal/pipeline/pipeline.go
git commit -m "feat(pipeline): infer vendor/product for generic CVE briefs during processing

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Phase 2 — Foxit backfill (ti-bot)

### Task 4: `enrichBriefsInSegment` pure core

**Files:**
- Create: `/Users/niels/Source/craftedsignal/ti-bot/internal/publisher/enrich_vendor_product.go`
- Test: `/Users/niels/Source/craftedsignal/ti-bot/internal/publisher/enrich_vendor_product_test.go`

**Interfaces:**
- Consumes: `pipeline.InferVendorProduct` (Task 1); `hasMeaningfulString` (`publisher_markdown.go`, same package); `BundleBrief` (`.Slug`, `.Title`, `.Content`, `.AffectedVendors`, `.AffectedProducts`).
- Produces: `func enrichBriefsInSegment(ctx context.Context, client llm.Client, briefs []BundleBrief, want map[string]bool, logger *slog.Logger) int`.

- [ ] **Step 1: Write the failing test**

```go
package publisher

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

type enrichMockLLM struct{ resp string }

func (m *enrichMockLLM) Generate(context.Context, string, string) (string, error) {
	return m.resp, nil
}
func (m *enrichMockLLM) GenerateJSON(ctx context.Context, prompt, system string, out any) error {
	return json.Unmarshal([]byte(m.resp), out)
}

func TestEnrichBriefsInSegment(t *testing.T) {
	briefs := []BundleBrief{
		{Slug: "foxit", Title: "CVE-2026-3779 Foxit UAF", Content: "pdf form objects"},
		{Slug: "other", Title: "X", AffectedVendors: []string{"Microsoft"}},
		{Slug: "not-wanted", Title: "CVE-2026-1 thing", Content: "c"},
	}
	m := &enrichMockLLM{resp: `{"affected_vendors":["Foxit"],"affected_products":["Foxit PDF Reader"]}`}

	n := enrichBriefsInSegment(context.Background(), m, briefs, map[string]bool{"foxit": true}, slog.Default())

	if n != 1 {
		t.Fatalf("changed = %d, want 1", n)
	}
	if len(briefs[0].AffectedProducts) != 1 || briefs[0].AffectedProducts[0] != "Foxit PDF Reader" {
		t.Errorf("foxit not enriched: %v", briefs[0].AffectedProducts)
	}
	if briefs[1].AffectedVendors[0] != "Microsoft" {
		t.Error("populated brief must be untouched")
	}
	if len(briefs[2].AffectedProducts) != 0 {
		t.Error("brief not in want-set must be skipped")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/publisher/ -run TestEnrichBriefsInSegment -v`
Expected: FAIL — `undefined: enrichBriefsInSegment`.

- [ ] **Step 3: Write the implementation**

Create `internal/publisher/enrich_vendor_product.go`:

```go
package publisher

import (
	"context"
	"log/slog"

	"github.com/craftedsignal/ti-bot/internal/llm"
	"github.com/craftedsignal/ti-bot/internal/pipeline"
)

// enrichBriefsInSegment infers affected vendor/product for briefs that lack
// both fields, restricted to slugs in want (empty want = all). Returns the
// number of briefs changed. Pure over the slice; callers persist the result.
func enrichBriefsInSegment(ctx context.Context, client llm.Client, briefs []BundleBrief, want map[string]bool, logger *slog.Logger) int {
	changed := 0
	for i := range briefs {
		b := &briefs[i]
		if len(want) > 0 && !want[b.Slug] {
			continue
		}
		if hasMeaningfulString(b.AffectedVendors) || hasMeaningfulString(b.AffectedProducts) {
			continue
		}
		vendors, products, err := pipeline.InferVendorProduct(ctx, client, b.Title, b.Content)
		if err != nil {
			logger.Warn("vendor/product inference failed", "slug", b.Slug, "error", err)
			continue
		}
		if len(vendors) == 0 && len(products) == 0 {
			continue
		}
		b.AffectedVendors = vendors
		b.AffectedProducts = products
		changed++
		logger.Info("enriched brief vendor/product", "slug", b.Slug, "vendors", vendors, "products", products)
	}
	return changed
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/publisher/ -run TestEnrichBriefsInSegment -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/niels/Source/craftedsignal/ti-bot
git add internal/publisher/enrich_vendor_product.go internal/publisher/enrich_vendor_product_test.go
git commit -m "feat(publisher): add enrichBriefsInSegment vendor/product core

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `Publisher.EnrichVendorProduct` I/O orchestration

**Files:**
- Modify: `/Users/niels/Source/craftedsignal/ti-bot/internal/publisher/enrich_vendor_product.go`

**Interfaces:**
- Consumes: `enrichBriefsInSegment` (Task 4); Publisher internals — `p.llmClient`, `p.logger`, `p.fetchManifest()`, `p.fetchSegment(path)` → `(*SegmentContent, sha, error)`, `EncryptSegment(content, version, publishedAt, publicKeyHex)`, `p.getFileSHA(path)`, `p.putFile(path, data, sha, msg)`, `p.publishBriefMarkdown(b BundleBrief)`, `p.PublishSTIXBundle()`, `bundleVersion()`, `bundleTimestamp()`, `p.publicKey`. Verify each name against `publisher.go`/`publisher_markdown.go`/`bundle.go` while implementing; adjust to the real signatures (they are all same-package, unexported).
- Produces: `func (p *Publisher) EnrichVendorProduct(ctx context.Context, slugs []string, dryRun bool) error`.

- [ ] **Step 1: Write the implementation**

Append to `internal/publisher/enrich_vendor_product.go` (add `"encoding/json"`, `"fmt"` to imports as needed):

```go
// EnrichVendorProduct infers affected vendor/product for briefs (restricted to
// slugs, empty = all) that lack both fields, writes the result back into the
// encrypted bundle, and re-emits the affected Markdown. With dryRun, it reports
// what it would change without writing anything.
func (p *Publisher) EnrichVendorProduct(ctx context.Context, slugs []string, dryRun bool) error {
	want := make(map[string]bool, len(slugs))
	for _, s := range slugs {
		want[s] = true
	}

	manifest, _, err := p.fetchManifest()
	if err != nil {
		return fmt.Errorf("fetching manifest: %w", err)
	}

	var enrichedBriefs []BundleBrief
	for _, seg := range manifest.Segments {
		segPath := "output/" + seg.Path
		content, sha, fetchErr := p.fetchSegment(segPath)
		if fetchErr != nil {
			p.logger.Warn("enrich: skipping unreadable segment", "path", segPath, "err", fetchErr)
			continue
		}
		changed := enrichBriefsInSegment(ctx, p.llmClient, content.Briefs, want, p.logger)
		if changed == 0 {
			continue
		}
		// Collect the briefs we changed so we can re-emit their Markdown.
		for i := range content.Briefs {
			b := content.Briefs[i]
			if len(want) > 0 && !want[b.Slug] {
				continue
			}
			if hasMeaningfulString(b.AffectedVendors) || hasMeaningfulString(b.AffectedProducts) {
				enrichedBriefs = append(enrichedBriefs, b)
			}
		}
		if dryRun {
			p.logger.Info("enrich (dry-run): would update segment", "path", segPath, "changed", changed)
			continue
		}
		encrypted, encErr := EncryptSegment(content, bundleVersion(), bundleTimestamp(), p.publicKey)
		if encErr != nil {
			return fmt.Errorf("encrypting segment %s: %w", segPath, encErr)
		}
		if err := p.putFile(segPath, encrypted, sha, fmt.Sprintf("chore: enrich vendor/product (%d briefs)", changed)); err != nil {
			return fmt.Errorf("pushing segment %s: %w", segPath, err)
		}
		p.logger.Info("enrich: segment updated", "path", segPath, "changed", changed)
	}

	if dryRun {
		p.logger.Info("enrich (dry-run) complete", "would_reemit", len(enrichedBriefs))
		return nil
	}

	for _, b := range enrichedBriefs {
		if err := p.publishBriefMarkdown(b); err != nil {
			p.logger.Warn("enrich: markdown re-emit failed", "slug", b.Slug, "err", err)
		}
	}
	if err := p.PublishSTIXBundle(); err != nil {
		p.logger.Warn("enrich: STIX republish failed", "err", err)
	}
	p.logger.Info("enrich complete", "reemitted", len(enrichedBriefs))
	return nil
}
```

> Implementation note: the exact `fetchManifest`/`fetchSegment`/`EncryptSegment`/`putFile`/`getFileSHA` names and return shapes come from `publisher.go` and `bundle.go` (`PublishSTIXBundle` and `MigrateBundle` use all of them). Mirror those call sites precisely; the pseudocode above is structurally correct but adjust argument order/return values to the real signatures as you wire it.

- [ ] **Step 2: Build**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go build ./... && go vet ./internal/publisher/`
Expected: build + vet clean. Fix any signature mismatches against the real helper functions.

- [ ] **Step 3: Run the publisher test suite (no regressions)**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/publisher/ -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/niels/Source/craftedsignal/ti-bot
git add internal/publisher/enrich_vendor_product.go
git commit -m "feat(publisher): add EnrichVendorProduct bundle backfill + re-emit

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `bundle enrich-vendors` subcommand

**Files:**
- Modify: `/Users/niels/Source/craftedsignal/ti-bot/cmd/ti-bot/main.go` (`runBundle`, and usage text)

**Interfaces:**
- Consumes: `EnrichVendorProduct` (Task 5); `loadConfig()`, `newGitHubTokenFn(cfg.GitHub, logger)`, `buildLLMClients(cfg.LLM, logger) (llmClientSet, error)` (fields `.Primary`, `.PrimaryModel`), `publisher.New(...)`, `publisher.WithLLMClient(...)`.

- [ ] **Step 1: Register the verb**

In `runBundle`, add `"enrich-vendors": true` to the `valid` map, and update the usage line to `Usage: ti-bot bundle migrate|repair-manifest|backfill-markdown|drift|enrich-vendors`.

- [ ] **Step 2: Add the case**

In the `switch args[0]` inside `runBundle`, add:

```go
	case "enrich-vendors":
		fs := flag.NewFlagSet("enrich-vendors", flag.ExitOnError)
		var slugList string
		var dryRun bool
		fs.StringVar(&slugList, "slug", "", "comma-separated brief slugs to enrich (empty = all missing)")
		fs.BoolVar(&dryRun, "dry-run", false, "report changes without writing")
		_ = fs.Parse(args[1:])

		clients, err := buildLLMClients(cfg.LLM, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error building LLM client: %v\n", err)
			os.Exit(1)
		}
		pubLLM := publisher.New(cfg.Publish.RepoSlug, cfg.Publish.FeedPublicKey, ghTokenFn, logger, publisher.WithLLMClient(clients.Primary))

		var slugs []string
		for _, s := range strings.Split(slugList, ",") {
			if s = strings.TrimSpace(s); s != "" {
				slugs = append(slugs, s)
			}
		}
		if err := pubLLM.EnrichVendorProduct(context.Background(), slugs, dryRun); err != nil {
			fmt.Fprintf(os.Stderr, "enrich failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Vendor/product enrichment complete.")
```

Ensure `"context"`, `"flag"`, `"strings"` are imported in main.go (add any missing).

- [ ] **Step 3: Build and check help**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go build ./... && go run ./cmd/ti-bot bundle 2>&1 | head`
Expected: build succeeds; usage line now lists `enrich-vendors`.

- [ ] **Step 4: Commit**

```bash
cd /Users/niels/Source/craftedsignal/ti-bot
git add cmd/ti-bot/main.go
git commit -m "feat(cli): add 'bundle enrich-vendors' subcommand

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Run the Foxit backfill and verify on the site (production-affecting)

> This step writes to the live `threat-feed` repo via the GitHub API (segment + Markdown + STIX). Dry-run first, inspect, then run for real. Requires ti-bot config with `publish.repo_slug`, `publish.feed_public_key`, GitHub auth, and LLM credentials.

- [ ] **Step 1: Dry-run for the two Foxit slugs**

Run:
```bash
cd /Users/niels/Source/craftedsignal/ti-bot
go run ./cmd/ti-bot bundle enrich-vendors --slug 2026-04-foxit-uaf,2026-04-untrusted-search-path --dry-run
```
Expected: logs show it *would* enrich both briefs with vendor `Foxit` and a Foxit PDF product; no writes.

- [ ] **Step 2: Run for real**

Run:
```bash
cd /Users/niels/Source/craftedsignal/ti-bot
go run ./cmd/ti-bot bundle enrich-vendors --slug 2026-04-foxit-uaf,2026-04-untrusted-search-path
```
Expected: segment updated, two Markdown files re-emitted, STIX republished.

- [ ] **Step 3: Verify the Markdown gained the fields**

Pull latest in threat-feed and inspect:
```bash
cd /Users/niels/Source/craftedsignal/threat-feed
git pull
grep -A2 '^vendors:' site/content/briefs/2026-04-foxit-uaf.md
grep -A2 '^products:' site/content/briefs/2026-04-foxit-uaf.md
```
Expected: `vendors:` includes `Foxit`; `products:` includes a Foxit PDF product.

- [ ] **Step 4: Verify site search end-to-end (use the `verify` skill)**

Build the Hugo site and confirm `/products/` filtering finds Foxit:
```bash
cd /Users/niels/Source/craftedsignal/threat-feed/site
hugo --gc --minify
grep -ri "foxit" public/products/index.json
```
Expected: a Foxit product term appears in `public/products/index.json` (the filter source). Optionally serve locally (`hugo server`) and type "foxit" in the `/products/` filter to confirm a match.

- [ ] **Step 5: No commit here** — the backfill already pushed via the API. Record the run in the PR description.

---

## Phase 3 — STIX vendor/product + vulnerability (ti-bot)

### Task 8: Emit `software` SCO + `vulnerability` SDO in STIX

**Files:**
- Modify: `/Users/niels/Source/craftedsignal/ti-bot/internal/publisher/stix.go`
- Test: `/Users/niels/Source/craftedsignal/ti-bot/internal/publisher/stix_test.go`

**Interfaces:**
- Consumes: `BundleBrief` (`.AffectedVendors`, `.AffectedProducts`, `.CVEs` → `BundleCVE.ID`, `.CPEs`); existing `stixID`, `stixRelationship`, `stixExternalRef`, `objectRefs`, `now`.
- Produces: `stixSoftware`, `stixVulnerability` structs; additional objects in `ExportSTIX`.

- [ ] **Step 1: Write the failing test**

Append to `internal/publisher/stix_test.go`:

```go
func TestExportSTIX_AffectedSoftware(t *testing.T) {
	briefs := []BundleBrief{{
		ID:               "b1",
		Slug:             "foxit-uaf",
		Title:            "Foxit UAF",
		Content:          "c",
		Severity:         "high",
		PublishedAt:      "2026-04-01T00:00:00Z",
		AffectedVendors:  []string{"Foxit"},
		AffectedProducts: []string{"Foxit PDF Reader", "Foxit PDF Editor"},
		CVEs:             []BundleCVE{{ID: "CVE-2026-3779"}},
	}}

	data, err := ExportSTIX(briefs)
	if err != nil {
		t.Fatalf("ExportSTIX failed: %v", err)
	}
	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	objects := bundle["objects"].([]interface{})
	counts := make(map[string]int)
	var vulnName, swVendor string
	for _, obj := range objects {
		m := obj.(map[string]interface{})
		counts[m["type"].(string)]++
		if m["type"] == "vulnerability" {
			vulnName = m["name"].(string)
		}
		if m["type"] == "software" {
			if v, ok := m["vendor"].(string); ok {
				swVendor = v
			}
		}
	}
	if counts["software"] != 2 {
		t.Errorf("software = %d, want 2", counts["software"])
	}
	if counts["vulnerability"] != 1 {
		t.Errorf("vulnerability = %d, want 1", counts["vulnerability"])
	}
	if counts["relationship"] != 2 { // 2 software --has--> 1 vulnerability
		t.Errorf("relationships = %d, want 2", counts["relationship"])
	}
	if vulnName != "CVE-2026-3779" {
		t.Errorf("vulnerability name = %q", vulnName)
	}
	if swVendor != "Foxit" {
		t.Errorf("software vendor = %q, want Foxit", swVendor)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/publisher/ -run TestExportSTIX_AffectedSoftware -v`
Expected: FAIL (0 software / 0 vulnerability objects).

- [ ] **Step 3: Add the struct types**

In `stix.go`, after `type stixThreatActor struct {...}`, add:

```go
type stixSoftware struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Vendor string `json:"vendor,omitempty"`
	CPE    string `json:"cpe,omitempty"`
}

type stixVulnerability struct {
	Type         string            `json:"type"`
	SpecVersion  string            `json:"spec_version"`
	ID           string            `json:"id"`
	Created      string            `json:"created"`
	Modified     string            `json:"modified"`
	Name         string            `json:"name"`
	ExternalRefs []stixExternalRef `json:"external_references,omitempty"`
}
```

- [ ] **Step 4: Emit the objects in `ExportSTIX`**

In the per-brief loop, after the Threat Actor block and before the `--- External references from brief ---` block, insert:

```go
		// --- Affected software (SCO) + vulnerabilities (SDO) ---
		var singleVendor string
		if len(b.AffectedVendors) == 1 {
			singleVendor = b.AffectedVendors[0]
		}
		var firstCPE string
		if len(b.CPEs) > 0 {
			firstCPE = b.CPEs[0]
		}
		var softwareIDs []string
		seenSoftware := make(map[string]bool)
		for _, product := range b.AffectedProducts {
			if strings.TrimSpace(product) == "" || seenSoftware[product] {
				continue
			}
			seenSoftware[product] = true
			swID := stixID("software", singleVendor+":"+product)
			softwareIDs = append(softwareIDs, swID)
			objectRefs = append(objectRefs, swID)
			objects = append(objects, stixSoftware{
				Type:   "software",
				ID:     swID,
				Name:   product,
				Vendor: singleVendor,
				CPE:    firstCPE,
			})
		}
		seenVuln := make(map[string]bool)
		for _, cve := range b.CVEs {
			if cve.ID == "" || seenVuln[cve.ID] {
				continue
			}
			seenVuln[cve.ID] = true
			vulnID := stixID("vulnerability", cve.ID)
			objectRefs = append(objectRefs, vulnID)
			objects = append(objects, stixVulnerability{
				Type:        "vulnerability",
				SpecVersion: "2.1",
				ID:          vulnID,
				Created:     now,
				Modified:    now,
				Name:        cve.ID,
				ExternalRefs: []stixExternalRef{{
					SourceName: "cve",
					ExternalID: cve.ID,
					URL:        "https://nvd.nist.gov/vuln/detail/" + cve.ID,
				}},
			})
			// software --has--> vulnerability, in stable (slice) order.
			for _, swID := range softwareIDs {
				relID := stixID("relationship", swID+":has:"+vulnID)
				objects = append(objects, stixRelationship{
					Type:             "relationship",
					SpecVersion:      "2.1",
					ID:               relID,
					Created:          now,
					Modified:         now,
					RelationshipType: "has",
					SourceRef:        swID,
					TargetRef:        vulnID,
				})
			}
		}
```

(`strings` is already imported in stix.go.)

- [ ] **Step 5: Run the STIX tests (new + existing)**

Run: `cd /Users/niels/Source/craftedsignal/ti-bot && go test ./internal/publisher/ -run TestExportSTIX -v`
Expected: `TestExportSTIX_AffectedSoftware` PASSES; `TestExportSTIX_Basic`, `_Deterministic`, `_Empty`, `_NoThreatActor` still PASS (Basic's brief has no vendor/product/CVE, so its counts are unchanged).

- [ ] **Step 6: Commit**

```bash
cd /Users/niels/Source/craftedsignal/ti-bot
git add internal/publisher/stix.go internal/publisher/stix_test.go
git commit -m "feat(stix): emit software + vulnerability objects for affected products

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Phase 4 — STIX discoverability (threat-feed)

### Task 9: Document + link the STIX feed on the site

**Files:**
- Modify: `/Users/niels/Source/craftedsignal/threat-feed/site/content/api/_index.md`
- Modify: `/Users/niels/Source/craftedsignal/threat-feed/site/layouts/partials/footer.html`

- [ ] **Step 1: Add a STIX section to the API page**

In `site/content/api/_index.md`, after the "Filtered feeds" section (before "## JSON shape"), insert:

```markdown
## STIX 2.1

Machine-readable [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) bundles of the last 90 days of briefs, for TIP / SOAR ingestion. No auth, served from the static CDN.

- Latest 30 days: `https://feed.craftedsignal.io/stix.json`
- Per month: `https://feed.craftedsignal.io/stix/YYYY-MM.json` (e.g. `/stix/2026-05.json`)
- Manifest of available months: `https://feed.craftedsignal.io/stix/index.json`

Each bundle contains `report` objects linked to `indicator` (IOCs), `attack-pattern` (MITRE ATT&CK), `threat-actor`, `software` (affected vendor/product), and `vulnerability` (CVE) objects.
```

- [ ] **Step 2: Add a footer link**

In `site/layouts/partials/footer.html`, inside the "Subscribe" `<nav>` block (after the "High+ (RSS)" link, before "How to subscribe"), add:

```html
            <a href="/stix.json" class="hover:text-text transition">STIX 2.1</a>
```

- [ ] **Step 3: Build the site to verify**

Run: `cd /Users/niels/Source/craftedsignal/threat-feed/site && hugo --gc --minify`
Expected: build succeeds. Confirm the API page renders the STIX section:
`grep -ri "STIX 2.1" public/api/index.html`
Expected: match found.

- [ ] **Step 4: Commit**

```bash
cd /Users/niels/Source/craftedsignal/threat-feed
git add site/content/api/_index.md site/layouts/partials/footer.html
git commit -m "docs(site): document and link the public STIX 2.1 feed

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Component 1 (pipeline fallback) → Tasks 1–3. ✓
- Component 2 (Foxit backfill) → Tasks 4–7. ✓
- Component 3 (STIX software + vulnerability) → Task 8. ✓
- Component 4 (site discoverability) → Task 9. ✓
- "Enrich at source" (bundle, not just markdown) → Task 5 writes the segment then re-emits. ✓
- "Infer product, vendor-name fallback" → Task 1 prompt. ✓
- Determinism constraint → Task 8 uses slice order + a determinism test stays green. ✓

**Type consistency:** `InferVendorProduct` signature identical in Tasks 1, 2, 4. `applyVendorProductFallback` identical in Tasks 2, 3. `enrichBriefsInSegment` / `EnrichVendorProduct` identical in Tasks 4, 5, 6. `stixSoftware`/`stixVulnerability` defined in Task 8 before use. ✓

**Placeholder scan:** Task 5 carries an explicit "adjust to real signatures" note because the publisher's I/O helpers are unexported and their exact shapes must be read at implementation time from `publisher.go`/`bundle.go`; the structure and call set are given. No `TODO`/`TBD` in requirements.

**Known risk:** Task 5's helper names (`fetchManifest`, `fetchSegment`, `EncryptSegment`, `putFile`, `getFileSHA`, `publishBriefMarkdown`) are taken from `PublishSTIXBundle`/`MigrateBundle` call sites; verify argument order/return values against those functions while implementing.
