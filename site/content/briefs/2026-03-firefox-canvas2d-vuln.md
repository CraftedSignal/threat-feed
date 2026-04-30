---
title: Mozilla Firefox Canvas2D Improper Boundary Condition Vulnerability (CVE-2026-4685)
slug: 2026-03-firefox-canvas2d-vuln
description: An improper boundary condition vulnerability in the Canvas2D component of Mozilla Firefox, Firefox ESR, and Thunderbird (CVE-2026-4685) could allow for a denial-of-service condition.
date: "2026-03-24T13:16:04Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-4685
  - firefox
  - thunderbird
  - denial-of-service
  - canvas2d
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1201
    technique_name: OS Component Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4685
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2016349
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-21/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Firefox Process Crashes
    description: Detects crashes of the Firefox process, potentially indicating exploitation of vulnerabilities like CVE-2026-4685.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - application
      - windows
  - title: Detect Thunderbird Process Crashes
    description: Detects crashes of the Thunderbird process, potentially indicating exploitation of vulnerabilities like CVE-2026-4685.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - application
      - windows
rules_count: 2
---

CVE-2026-4685 describes an incorrect boundary condition in the Graphics: Canvas2D component affecting Mozilla Firefox versions prior to 149, Firefox ESR versions prior to 115.34 and 140.9, and Thunderbird versions prior to 149 and 140.9. This vulnerability could be exploited by a remote attacker to cause a denial-of-service condition. Successful exploitation of this vulnerability could result in the application crashing or becoming unresponsive. The vulnerability was reported and patched by…
