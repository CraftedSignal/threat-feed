---
brief_id: brief-2026-10-25-warp-dcs-spoofing
event_id: brief-2026-10-25-warp-dcs-spoofing
revision: 1
activity_at: "2026-10-25T03:41:05Z"
title: 'Warp Terminal Emulator: DCS Lifecycle Hook Spoofing (CVE-2026-54686)'
slug: 2026-10-warp-dcs-spoofing
description: Warp terminal emulator is vulnerable to a DCS lifecycle hook spoofing issue. The application fails to verify the authenticity of state-mutating lifecycle hooks transmitted via the PTY stream, allowing an attacker to spoof Current Working Directory (CWD) and SSH session transport metadata if a user views attacker-controlled terminal output.
date: "2026-10-25T03:41:05Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:warp:warp:*:*:*:*:*:*:*:*
vendors:
  - Warp
products:
  - Warp (< 0.2026.05.06.15.42.stable_01)
cves:
  - id: CVE-2026-54686
    cvss: 4.3
    epss: 0.00404
    kev_status: "false"
references:
  - https://github.com/warpdotdev/warp/security/advisories/GHSA-9w2v-jhww-vm85
  - https://github.com/saku0512/cve-2026-54686-poc
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SAKU0512-CVE-2026-54686-POC
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SAKU0512-CVE-2026-54686-POC&utm_source=rss&utm_medium=rss
---
