---
brief_id: brief-2026-11-10-fluxion-rce
event_id: brief-2026-11-10-fluxion-rce
revision: 2
activity_at: "2026-11-10T09:38:06Z"
revision_history:
  - revision: 2
    at: "2026-11-10T09:38:06Z"
    checksum: sha256:5d82fb8a7f101e461cc6e5181a9df1e7ada57a9e2ec4be004c878ecf03955385
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
      - https://sploitus.com/exploit?id=CEC802B9-223C-507F-A9B2-DA338AA89C93&utm_source=rss&utm_medium=rss
title: 'Fluxion: OS Command Injection via Malicious ESSID (CVE-2026-125399)'
slug: 2026-11-fluxion-rce
description: Fluxion versions before 6.39 contain an OS command injection vulnerability in the fluxion.sh target scanner, allowing attackers within Wi-Fi range to execute commands as root.
date: "2026-11-10T02:05:07Z"
lastmod: "2026-11-10T09:37:32Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CEC802B9-223C-507F-A9B2-DA338AA89C93&utm_source=rss&utm_medium=rss
vendors:
  - FluxionNetwork
cves:
  - id: CVE-2026-125399
    cvss: 8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125399
  - https://sploitus.com/exploit?id=CEC802B9-223C-507F-A9B2-DA338AA89C93&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-10T09:37:32Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CEC802B9-223C-507F-A9B2-DA338AA89C93&utm_source=rss&utm_medium=rss
---

Fluxion versions before 6.39 contain an OS command injection vulnerability in the fluxion.sh target scanner. The tool decodes access point ESSIDs with eval after only escaping single quotes. Attackers within Wi-Fi range can broadcast an access point with a crafted SSID to execute commands as root when the operator scans or selects it.
