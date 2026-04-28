# CraftedSignal Threat Feed

Commercial threat intelligence feed for the CraftedSignal platform. Translates trending and novel threats into ready-to-use detection rules with tests, MITRE ATT&CK mappings, and IOCs.

## Structure

```
briefs/          YAML threat brief source files (cleartext, gitignored)
cmd/feedgen/     Compiler that builds encrypted feed bundles
cmd/notifier/    Cloud Run service: public alert subscriptions
internal/        Compiler internals (loader, encryption, types)
output/          Compiled bundle output (encrypted)
site/            Hugo source for feed.craftedsignal.io
```

## Brief format

Each YAML file in `briefs/` is a self-contained threat brief:

- **Metadata**: title, summary, severity, threat actor, tags, references
- **Content**: detailed write-up of the threat (Markdown)
- **Rules**: detection rules with platform-specific queries (SPL, KQL, FalconQL)
- **Tests**: positive and negative test cases per rule
- **TTPs**: MITRE ATT&CK tactic/technique mappings
- **IOCs**: indicators of compromise (IPs, domains, hashes)

## Outputs

Each brief is the source for two artifacts:

1. **Encrypted bundle** — the full brief, AES-256-GCM encrypted, consumed by the CraftedSignal platform.
2. **Public Markdown** — a redacted derivative published at [feed.craftedsignal.io](https://feed.craftedsignal.io). One Markdown file per brief, written by `ti-bot`'s publisher into `site/content/briefs/`. Hugo builds and deploys via the `Site Deploy` workflow.

### Public surface

The public derivative includes:

- `slug`, `title`, `description` (the summary), `published_at`
- `type` (threat / coverage / advisory / rumour) and `severity` (critical → low; rumour for unverified)
- `tags`, `references`
- `actors`, `vendors`, `products`, `affected_os`
- `exploited` (true when active exploitation observed)
- MITRE ATT&CK mappings (`mitre_ttps[]`)
- CVE references (`cves[]`: id, EPSS, CVSS, KEV)
- The full `content` body (rendered by Hugo)
- Per-rule metadata: title, description, platform, severity, MITRE tactics/techniques, data sources
- IOCs (type + value) and aggregate `ioc_counts`

The redacted fields — never included in the public output:

- Detection rule **queries** (the operational logic)
- Rule **tests** (real TTP samples)
- Internal **priority scoring** fields
- Anything outside the whitelisted set above

Brief authors should write `summary` and `content` assuming everything except the explicitly-withheld fields above is publicly indexable.

Subscribers can filter the public feed by any of the published fields and receive matching briefs by email, Slack, or Microsoft Teams via the [subscription form](https://feed.craftedsignal.io/subscribe/) (`cmd/notifier/`).

## Build

Compile briefs into an encrypted bundle:

```bash
go run ./cmd/feedgen -public-key <ed25519-hex> -briefs ./briefs -out ./output/bundle.json
```

Options:

| Flag | Description |
|------|-------------|
| `-public-key` | Ed25519 public key (64 hex chars). Also reads `PUBLIC_KEY` env var. |
| `-briefs` | Directory containing YAML brief files. Default: `briefs` |
| `-out` | Output path for encrypted bundle. Default: `output/bundle.json` |
| `-version` | Bundle version. Defaults to `YYYY.MM.DD.<git-sha>` |
| `-max-age-days` | Exclude briefs older than N days. Default: ~5 years |

## Adding a brief

1. Create a new YAML file in `briefs/` following the naming convention: `YYYY-MM-DD-<slug>.yaml`
2. Fill in metadata, content, rules (with tests), TTPs, and IOCs
3. Run `feedgen` to compile and verify
4. The platform fetches the updated bundle automatically
