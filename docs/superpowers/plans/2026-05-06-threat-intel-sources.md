# Threat Intel Sources — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 21 new threat intel RSS sources to ti-bot and fix missing confidence/authority scores for two existing sources (Securelist, Wiz) that are registered but silently downscored.

**Architecture:** Each source requires four changes: (1) an RSS constructor in `rss.go`, (2) a `SourceToggle` field in `config.go`, (3) a registration block in `main.go`/`countEnabledSources`, and (4) confidence + authority entries in `pipeline.go`/`dedup.go`. Task 1 is the highest-priority fix — it unblocks Securelist (including the daemon-tools article) immediately without any new code.

**Tech Stack:** Go 1.25, `github.com/mmcdole/gofeed` (RSS/Atom parsing), SQLite (dedup state), YAML config.

**Working directory for all tasks:** `/Users/niels/Source/craftedsignal/ti-bot`

---

### Task 1: Fix Securelist and Wiz confidence + authority scores

`securelist` and `wiz` are registered scrapers but are absent from `defaultSourceConfidence` (so they score at 50% of raw) and `sourceAuthority` (so they get authority level 0). This is why the Securelist daemon-tools article never published.

**Files:**
- Modify: `internal/pipeline/pipeline.go` (confidence map, lines ~80–128)
- Modify: `internal/pipeline/dedup.go` (authority map, lines ~75–122)

- [ ] **Step 1: Add securelist and wiz to the confidence map**

In `internal/pipeline/pipeline.go`, in `defaultSourceConfidence`, add two entries after the `"volexity"` line:

```go
"volexity":              0.90,
"securelist":            0.90,  // add this
"wiz":                   0.80,  // add this
"ncsc-uk":               0.90,
```

- [ ] **Step 2: Add securelist to the authority map**

In `internal/pipeline/dedup.go`, in `sourceAuthority`, add one entry in the vendor research block:

```go
"volexity":   3,
"wiz":        3,
"securelist": 3,  // add this
"google-project-zero": 3,
```

- [ ] **Step 3: Run existing tests**

```bash
go test ./internal/pipeline/... -run TestDedup -v
go test ./internal/pipeline/... -v
```

Expected: all tests pass (no logic changes, only map additions).

- [ ] **Step 4: Commit**

```bash
git add internal/pipeline/pipeline.go internal/pipeline/dedup.go
git commit -m "fix(pipeline): add confidence and authority scores for securelist and wiz"
```

---

### Task 2: Add 21 new RSS constructors (TDD)

**Files:**
- Modify: `internal/scraper/rss_test.go`
- Modify: `internal/scraper/rss.go`

- [ ] **Step 1: Add all 21 new sources to `TestAllRSSSources`**

In `internal/scraper/rss_test.go`, extend the `sources` map inside `TestAllRSSSources` with:

```go
"sentinelone-labs":         NewSentinelLabs(),
"bitdefender":              NewBitdefender(),
"fortiguard":               NewFortiGuard(),
"proofpoint":               NewProofpoint(),
"rapid7":                   NewRapid7(),
"red-canary":               NewRedCanary(),
"recorded-future":          NewRecordedFuture(),
"flashpoint":               NewFlashpoint(),
"intel471":                 NewIntel471(),
"greynoise":                NewGreyNoise(),
"cofense":                  NewCofense(),
"any-run":                  NewAnyRun(),
"qualys-threat-research":   NewQualysThreatResearch(),
"malware-traffic-analysis": NewMalwareTrafficAnalysis(),
"objective-see":            NewObjectiveSee(),
"attackiq":                 NewAttackIQ(),
"fbi-cyber":                NewFBICyber(),
"cccs":                     NewCCCS(),
"acsc":                     NewACSC(),
"ms-isac":                  NewMSISAC(),
"google-tag":               NewGoogleTAG(),
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scraper/... -run TestAllRSSSources -v
```

Expected: FAIL — `undefined: NewSentinelLabs` (and 20 more undefined errors).

- [ ] **Step 3: Add all 21 constructors to `rss.go`**

Append the following block after the `NewGoogleProjectZero` function in `internal/scraper/rss.go`:

```go
// Tier 1 — commercial threat research (creates new brief on novel campaign)

func NewSentinelLabs() *RSS {
	return NewRSS("sentinelone-labs", "https://www.sentinelone.com/labs/feed/")
}

// Tier 2 — commercial (enriches existing brief if campaign/actor matches)

func NewBitdefender() *RSS {
	return NewRSS("bitdefender", "https://www.bitdefender.com/blog/api/rss/labs/")
}

func NewFortiGuard() *RSS {
	return NewRSS("fortiguard", "https://feeds.fortinet.com/fortinet/blog/threat-research")
}

func NewProofpoint() *RSS {
	return NewRSS("proofpoint", "https://www.proofpoint.com/us/threat-insight-blog.xml")
}

func NewRapid7() *RSS {
	// Emergent Threat Response tag only — filters for actively-exploited CVE coverage.
	return NewRSS("rapid7", "https://www.rapid7.com/blog/tag/emergent-threat-response/rss/")
}

func NewRedCanary() *RSS {
	return NewRSS("red-canary", "https://redcanary.com/blog/feed/")
}

func NewRecordedFuture() *RSS {
	return NewRSS("recorded-future", "https://www.recordedfuture.com/feed")
}

func NewFlashpoint() *RSS {
	return NewRSS("flashpoint", "https://flashpoint.io/blog/feed/")
}

func NewIntel471() *RSS {
	return NewRSS("intel471", "https://www.intel471.com/blog/feed")
}

func NewGreyNoise() *RSS {
	return NewRSS("greynoise", "https://www.greynoise.io/blog/rss.xml")
}

func NewCofense() *RSS {
	return NewRSS("cofense", "https://cofense.com/feed/")
}

func NewAnyRun() *RSS {
	return NewRSS("any-run", "https://any.run/cybersecurity-blog/feed/")
}

func NewQualysThreatResearch() *RSS {
	// Threat-research category only — excludes general product/marketing posts.
	return NewRSS("qualys-threat-research", "https://blog.qualys.com/vulnerabilities-threat-research/feed")
}

func NewMalwareTrafficAnalysis() *RSS {
	return NewRSS("malware-traffic-analysis", "https://malware-traffic-analysis.net/blog-entries.rss")
}

func NewObjectiveSee() *RSS {
	// Patrick Wardle's macOS malware research — only dedicated high-signal macOS feed.
	return NewRSS("objective-see", "https://objective-see.org/rss.xml")
}

func NewAttackIQ() *RSS {
	return NewRSS("attackiq", "https://attackiq.com/blog/feed/")
}

// Government / CERT sources

func NewFBICyber() *RSS {
	return NewRSS("fbi-cyber", "https://www.ic3.gov/PSA/RSS")
}

func NewCCCS() *RSS {
	// Canadian Centre for Cyber Security — alerts and advisories.
	return NewRSS("cccs", "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en")
}

func NewACSC() *RSS {
	// Australian Signals Directorate / ACSC alerts feed.
	return NewRSS("acsc", "https://www.cyber.gov.au/rss/alerts")
}

func NewMSISAC() *RSS {
	// Multi-State ISAC advisories published via CIS.
	return NewRSS("ms-isac", "https://www.cisecurity.org/advisory/feed")
}

// Independent research

func NewGoogleTAG() *RSS {
	// Google Threat Analysis Group — government-backed attackers, 0-day in-the-wild.
	return NewRSS("google-tag", "https://blog.google/threat-analysis-group/rss/")
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/scraper/... -run TestAllRSSSources -v
```

Expected: PASS — all 21 new entries resolve and parse the mock feed correctly.

- [ ] **Step 5: Commit**

```bash
git add internal/scraper/rss.go internal/scraper/rss_test.go
git commit -m "feat(scraper): add 21 new threat intel RSS source constructors"
```

---

### Task 3: Add config fields for the 21 new sources

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add 21 new `SourceToggle` fields to `SourcesConfig`**

In `internal/config/config.go`, in the `SourcesConfig` struct, append the following block after the `GoogleProjectZero` field:

```go
// New threat intel sources — added 2026-05-06
// Tier 1 commercial
SentinelLabs         SourceToggle `yaml:"sentinel_labs"`
// Tier 2 commercial
Bitdefender          SourceToggle `yaml:"bitdefender"`
FortiGuard           SourceToggle `yaml:"fortiguard"`
Proofpoint           SourceToggle `yaml:"proofpoint"`
Rapid7               SourceToggle `yaml:"rapid7"`
RedCanary            SourceToggle `yaml:"red_canary"`
RecordedFuture       SourceToggle `yaml:"recorded_future"`
Flashpoint           SourceToggle `yaml:"flashpoint"`
Intel471             SourceToggle `yaml:"intel471"`
GreyNoise            SourceToggle `yaml:"greynoise"`
Cofense              SourceToggle `yaml:"cofense"`
AnyRun               SourceToggle `yaml:"any_run"`
QualysThreatResearch SourceToggle `yaml:"qualys_threat_research"`
MalwareTrafficAnalysis SourceToggle `yaml:"malware_traffic_analysis"`
ObjectiveSee         SourceToggle `yaml:"objective_see"`
AttackIQ             SourceToggle `yaml:"attackiq"`
// Government / CERT
FBICyber             SourceToggle `yaml:"fbi_cyber"`
CCCS                 SourceToggle `yaml:"cccs"`
ACSC                 SourceToggle `yaml:"acsc"`
MSISAC               SourceToggle `yaml:"ms_isac"`
// Independent research
GoogleTAG            SourceToggle `yaml:"google_tag"`
```

- [ ] **Step 2: Verify build**

```bash
go build ./...
```

Expected: builds cleanly — zero errors.

- [ ] **Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add SourcesConfig fields for 21 new threat intel sources"
```

---

### Task 4: Register new sources in `main.go` and `countEnabledSources`

**Files:**
- Modify: `cmd/ti-bot/main.go`

- [ ] **Step 1: Add 21 registration blocks**

In `cmd/ti-bot/main.go`, after the `if cfg.Sources.GoogleProjectZero.Enabled` block, add:

```go
if cfg.Sources.SentinelLabs.Enabled {
    runner.Register(scraper.NewSentinelLabs())
}
if cfg.Sources.Bitdefender.Enabled {
    runner.Register(scraper.NewBitdefender())
}
if cfg.Sources.FortiGuard.Enabled {
    runner.Register(scraper.NewFortiGuard())
}
if cfg.Sources.Proofpoint.Enabled {
    runner.Register(scraper.NewProofpoint())
}
if cfg.Sources.Rapid7.Enabled {
    runner.Register(scraper.NewRapid7())
}
if cfg.Sources.RedCanary.Enabled {
    runner.Register(scraper.NewRedCanary())
}
if cfg.Sources.RecordedFuture.Enabled {
    runner.Register(scraper.NewRecordedFuture())
}
if cfg.Sources.Flashpoint.Enabled {
    runner.Register(scraper.NewFlashpoint())
}
if cfg.Sources.Intel471.Enabled {
    runner.Register(scraper.NewIntel471())
}
if cfg.Sources.GreyNoise.Enabled {
    runner.Register(scraper.NewGreyNoise())
}
if cfg.Sources.Cofense.Enabled {
    runner.Register(scraper.NewCofense())
}
if cfg.Sources.AnyRun.Enabled {
    runner.Register(scraper.NewAnyRun())
}
if cfg.Sources.QualysThreatResearch.Enabled {
    runner.Register(scraper.NewQualysThreatResearch())
}
if cfg.Sources.MalwareTrafficAnalysis.Enabled {
    runner.Register(scraper.NewMalwareTrafficAnalysis())
}
if cfg.Sources.ObjectiveSee.Enabled {
    runner.Register(scraper.NewObjectiveSee())
}
if cfg.Sources.AttackIQ.Enabled {
    runner.Register(scraper.NewAttackIQ())
}
if cfg.Sources.FBICyber.Enabled {
    runner.Register(scraper.NewFBICyber())
}
if cfg.Sources.CCCS.Enabled {
    runner.Register(scraper.NewCCCS())
}
if cfg.Sources.ACSC.Enabled {
    runner.Register(scraper.NewACSC())
}
if cfg.Sources.MSISAC.Enabled {
    runner.Register(scraper.NewMSISAC())
}
if cfg.Sources.GoogleTAG.Enabled {
    runner.Register(scraper.NewGoogleTAG())
}
```

- [ ] **Step 2: Add the same 21 sources to `countEnabledSources`**

In `cmd/ti-bot/main.go`, at the end of the `countEnabledSources` function body, before the final `return count`, add:

```go
if cfg.Sources.SentinelLabs.Enabled {
    count++
}
if cfg.Sources.Bitdefender.Enabled {
    count++
}
if cfg.Sources.FortiGuard.Enabled {
    count++
}
if cfg.Sources.Proofpoint.Enabled {
    count++
}
if cfg.Sources.Rapid7.Enabled {
    count++
}
if cfg.Sources.RedCanary.Enabled {
    count++
}
if cfg.Sources.RecordedFuture.Enabled {
    count++
}
if cfg.Sources.Flashpoint.Enabled {
    count++
}
if cfg.Sources.Intel471.Enabled {
    count++
}
if cfg.Sources.GreyNoise.Enabled {
    count++
}
if cfg.Sources.Cofense.Enabled {
    count++
}
if cfg.Sources.AnyRun.Enabled {
    count++
}
if cfg.Sources.QualysThreatResearch.Enabled {
    count++
}
if cfg.Sources.MalwareTrafficAnalysis.Enabled {
    count++
}
if cfg.Sources.ObjectiveSee.Enabled {
    count++
}
if cfg.Sources.AttackIQ.Enabled {
    count++
}
if cfg.Sources.FBICyber.Enabled {
    count++
}
if cfg.Sources.CCCS.Enabled {
    count++
}
if cfg.Sources.ACSC.Enabled {
    count++
}
if cfg.Sources.MSISAC.Enabled {
    count++
}
if cfg.Sources.GoogleTAG.Enabled {
    count++
}
```

- [ ] **Step 3: Build and run tests**

```bash
go build ./...
go test ./cmd/... -v
```

Expected: builds cleanly, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add cmd/ti-bot/main.go
git commit -m "feat(main): register 21 new threat intel sources"
```

---

### Task 5: Add confidence scores and authority levels for all new sources

**Files:**
- Modify: `internal/pipeline/pipeline.go` (confidence map)
- Modify: `internal/pipeline/dedup.go` (authority map)

- [ ] **Step 1: Add confidence scores**

In `internal/pipeline/pipeline.go`, in `defaultSourceConfidence`, append the following after the `"google-project-zero"` entry:

```go
// Tier 1 commercial
"sentinelone-labs":         0.85,
// Tier 2 commercial
"bitdefender":              0.80,
"fortiguard":               0.80,
"proofpoint":               0.85,
"rapid7":                   0.80,
"red-canary":               0.80,
"recorded-future":          0.80,
"flashpoint":               0.75,
"intel471":                 0.80,
"greynoise":                0.75,
"cofense":                  0.75,
"any-run":                  0.70,
"qualys-threat-research":   0.75,
"malware-traffic-analysis": 0.75,
"objective-see":            0.85,
"attackiq":                 0.70,
// Government / CERT
"fbi-cyber":                0.90,
"cccs":                     0.85,
"acsc":                     0.85,
"ms-isac":                  0.80,
// Independent research
"google-tag":               0.90,
```

- [ ] **Step 2: Add authority levels**

In `internal/pipeline/dedup.go`, in `sourceAuthority`, append the following after the `"google-project-zero": 3` entry:

```go
// Tier 1 commercial — added 2026-05-06
"sentinelone-labs":         3,
// Tier 2 commercial
"bitdefender":              3,
"fortiguard":               3,
"proofpoint":               3,
"rapid7":                   3,
"red-canary":               3,
"recorded-future":          3,
"flashpoint":               3,
"intel471":                 3,
"greynoise":                3,
"cofense":                  3,
"any-run":                  2,
"qualys-threat-research":   3,
"malware-traffic-analysis": 3,
"objective-see":            3,
"attackiq":                 2,
// Government / CERT
"fbi-cyber":                4,
"cccs":                     4,
"acsc":                     4,
"ms-isac":                  4,
// Independent research
"google-tag":               3,
```

- [ ] **Step 3: Run all tests**

```bash
go test ./... -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add internal/pipeline/pipeline.go internal/pipeline/dedup.go
git commit -m "feat(pipeline): add confidence and authority scores for 21 new sources"
```

---

### Task 6: Enable new sources in the config YAML

The config YAML (path set by `TIBOT_CONFIG` env var, default `config.yaml`) needs entries for all 21 new sources. Without `enabled: true` they are registered but never polled.

**Files:**
- Modify: `config.yaml` (or wherever `TIBOT_CONFIG` points in your deployment)

- [ ] **Step 1: Add enabled entries**

Add the following block to the `sources:` section of `config.yaml`:

```yaml
# Tier 1 commercial — added 2026-05-06
sentinel_labs:
  enabled: true

# Tier 2 commercial
bitdefender:
  enabled: true
fortiguard:
  enabled: true
proofpoint:
  enabled: true
rapid7:
  enabled: true
red_canary:
  enabled: true
recorded_future:
  enabled: true
flashpoint:
  enabled: true
intel471:
  enabled: true
greynoise:
  enabled: true
cofense:
  enabled: true
any_run:
  enabled: true
qualys_threat_research:
  enabled: true
malware_traffic_analysis:
  enabled: true
objective_see:
  enabled: true
attackiq:
  enabled: true

# Government / CERT
fbi_cyber:
  enabled: true
cccs:
  enabled: true
acsc:
  enabled: true
ms_isac:
  enabled: true

# Independent research
google_tag:
  enabled: true
```

- [ ] **Step 2: Build and verify startup log**

```bash
go build -o /tmp/ti-bot-test ./cmd/ti-bot/
TIBOT_CONFIG=config.yaml /tmp/ti-bot-test --dry-run 2>&1 | grep "ti-bot starting"
```

Expected: log line includes `sources=N` where N is at least 21 higher than before.

- [ ] **Step 3: Commit**

```bash
git add config.yaml
git commit -m "feat(config): enable 21 new threat intel sources"
```

---

## Self-Review

**Spec coverage:**
- ✅ 21 new sources added (RSS constructors, config fields, registration, confidence, authority)
- ✅ Securelist confidence + authority fixed (unblocks daemon-tools article)
- ✅ Wiz confidence fixed
- ✅ Gov/CERT sources: FBI, CCCS, ACSC, MS-ISAC added
- ✅ Deduplication model is unchanged — existing `dedup.go` + `actor_aliases.go` handles the enrichment/30-day window logic already
- ✅ CISA KEV already has a dedicated scraper (`NewCISAKEV`); the CISA advisory RSS (`NewCISA`) may have broken when CISA discontinued their feed in May 2025 — that is a separate investigation outside this plan's scope

**Placeholder scan:** None found. All code blocks are complete.

**Type consistency:** `SourceToggle` YAML keys in config.go use snake_case (`sentinel_labs`); constructor names use PascalCase (`NewSentinelLabs`); source IDs use kebab-case (`sentinelone-labs`). This matches the existing pattern throughout the codebase.
