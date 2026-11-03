---
brief_id: brief-2026-11-03-elo-ruby-code-injection
event_id: brief-2026-11-03-elo-ruby-code-injection
revision: 2
activity_at: "2026-11-03T20:16:22Z"
revision_history:
  - revision: 2
    at: "2026-11-03T20:16:22Z"
    checksum: sha256:5551c45b7a19ad27cb82eb11e0cec76382a08d6a7eec6764531fa4ab7636509c
    summary: poc_available
    changed_fields:
      - affected_vendors
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-44266&utm_source=rss&utm_medium=rss
title: 'Elo: Ruby backend arbitrary code execution (CVE-2026-44266)'
slug: 2026-11-elo-ruby-code-injection
description: Elo versions prior to 1.0.1 are vulnerable to arbitrary code execution in the Ruby backend due to improper escaping of input within Ruby double-quoted strings.
date: "2026-11-03T20:02:10Z"
lastmod: "2026-11-03T20:15:41Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-44266&utm_source=rss&utm_medium=rss
vendors:
  - Enspirit
cves:
  - id: CVE-2026-44266
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44266
  - https://sploitus.com/exploit?id=CVE-2026-44266&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T20:15:41Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-44266&utm_source=rss&utm_medium=rss
---

Elo, a functional expression language, contains a vulnerability in its Ruby backend (src/compilers/ruby.ts). Attacker-controlled text is embedded into Ruby double-quoted strings without escaping '#', allowing Ruby interpolation to become executable. A failing labelled subtype constraint or an ordinary string literal can lead to Ruby code and shell command execution via backticks. Affected entry points include the /try playground (Ruby target), bin/eloc -t ruby -x, and defaultFormats.elo.parse() followed by Ruby emission. This issue is fixed in version 1.0.1.
