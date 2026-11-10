---
brief_id: brief-2026-11-10-whatstk-zip-exhaustion
event_id: brief-2026-11-10-whatstk-zip-exhaustion
revision: 1
activity_at: "2026-11-10T18:59:49Z"
title: 'whatstk: Unbounded ZIP decompression denial-of-service (CVE-2026-121691)'
slug: 2026-11-whatstk-zip-exhaustion
description: A vulnerability in whatstk before version 0.9.0 allows attackers to perform a denial-of-service attack via resource exhaustion by supplying a maliciously crafted ZIP-compressed WhatsApp chat export.
date: "2026-11-10T18:59:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of the application logic.
cpes:
  - cpe:2.3:a:whatstk_project:whatstk:*:*:*:*:*:*:*:*
products:
  - whatstk (< 0.9.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Improper Handling of Highly Compressed Data (CWE-409) in the ZIP loader of whatstk from 0.7.0 before 0.9.0 allows a party that supplies a chat export to exhaust the memory and the disk of the process that parses it.
    confidence_band: high
cves:
  - id: CVE-2026-121691
    kev_status: "false"
references:
  - https://github.com/lucasrodes/whatstk/releases/tag/v0.9.0
  - https://secur0.com/en/cna/cve-list/cve-2026-121691-whatstk-zip-decompression-bomb
  - https://sploitus.com/exploit?id=CVE-2026-121691
  - https://sploitus.com/exploit?id=CVE-2026-121691&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade whatstk to version 0.9.0 or later on all systems using the library for chat parsing
      owner: IT Operations
      due: 48h
      evidence: https://github.com/lucasrodes/whatstk/releases/tag/v0.9.0
  hunt_leads:
    - lead: Identify applications utilizing whatstk for file parsing and audit for memory/disk spikes during processing
      technique_id: T1499
      data_needed:
        - Application performance monitoring logs
        - System memory and disk usage metrics for processes calling whatstk functions
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The parser builds a list of regular expression matches and a DataFrame over it, so peak memory is a multiple of the decompressed text rather than of the archive.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to whatstk 0.9.0
      owner: IT Operations
      addresses: CVE-2026-121691
      evidence: https://github.com/lucasrodes/whatstk/releases/tag/v0.9.0
---

The whatstk library versions prior to 0.9.0 are vulnerable to CVE-2026-121691, an improper handling of highly compressed data (CWE-409). The `_str_from_file()` function within the parser uses `zip_ref.extractall()` without validating archive member sizes or compression ratios. An attacker providing a maliciously crafted ZIP file can trigger significant memory and disk exhaustion as the library extracts, reads, and processes the contents, eventually leading to a process crash.

## Impact

Successful exploitation results in a local denial-of-service (DoS) condition. An attacker-supplied archive can cause significant memory and disk usage during the processing of data via `WhatsAppChat.from_source()` or `df_from_whatsapp()`, potentially crashing the application or the hosting service.

## Recommendation

- Upgrade the `whatstk` library to version 0.9.0 or later immediately to resolve the vulnerable ZIP parsing logic.
- Audit services that utilize `whatstk` to process user-supplied ZIP files to identify potential exposure points.
