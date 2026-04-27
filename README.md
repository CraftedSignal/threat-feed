# CraftedSignal Threat Feed

Commercial threat intelligence feed for the CraftedSignal platform. Translates trending and novel threats into ready-to-use detection rules with tests, MITRE ATT&CK mappings, and IOCs.

## Structure

```
briefs/          YAML threat brief source files
cmd/feedgen/     Compiler that builds encrypted feed bundles
internal/        Compiler internals (loader, encryption, types)
output/          Compiled bundle output
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
2. **Public summary** (planned) — a metadata-only derivative consumed by craftedsignal.io for browsing, RSS, and search.

### Public summary fields

The public summary includes:

- `slug`, `title`, `summary`, `severity`, `threat_actor`, `published_at`
- `tags`, `references`
- MITRE ATT&CK mappings (`ttps[]`)
- CVE references (`cves[]`: id, EPSS, CVSS, KEV)
- Affected vendors / products / operating systems
- The first paragraph of `content` (~500 characters)
- Per-rule metadata: title, description, platform, severity, MITRE tactics/techniques, data sources
- IOC counts by type

Detection rule queries, rule tests, IOC values, and the full body of `content` are not included in the public summary.

Brief authors should write `summary` and the opening of `content` assuming they will be publicly indexed.

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
