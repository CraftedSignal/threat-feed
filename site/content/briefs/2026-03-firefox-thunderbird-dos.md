---
title: Mozilla Firefox and Thunderbird Web Codecs Denial-of-Service Vulnerability (CVE-2026-4697)
slug: 2026-03-firefox-thunderbird-dos
description: CVE-2026-4697 is a denial-of-service vulnerability due to incorrect boundary conditions in the Audio/Video Web Codecs component of Mozilla Firefox and Thunderbird, potentially leading to application crashes.
date: "2026-03-24T13:16:05Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-4697
  - denial-of-service
  - mozilla
  - firefox
  - thunderbird
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4697
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2020422
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
ioc_counts:
  email: 1
rules:
  - title: Detect Firefox/Thunderbird Crash Events
    description: Detects crash events related to Firefox or Thunderbird processes, which could indicate exploitation of CVE-2026-4697.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Firefox/Thunderbird Crash Module Loading
    description: Detects specific modules being loaded by Firefox/Thunderbird during a crash, indicative of exploit attempts related to CVE-2026-4697 (requires image load logging).
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - image_load
      - windows
rules_count: 2
---

CVE-2026-4697 is a vulnerability affecting Mozilla Firefox and Thunderbird due to incorrect boundary conditions within the Audio/Video: Web Codecs component. This flaw can be exploited by attackers to trigger a denial-of-service condition. The vulnerability affects Firefox versions prior to 149, Firefox ESR versions prior to 140.9, Thunderbird versions prior to 149, and Thunderbird ESR versions prior to 140.9. An attacker could potentially craft malicious web content that triggers the incorrect…
