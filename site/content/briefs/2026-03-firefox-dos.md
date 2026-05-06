---
title: Mozilla Firefox and Thunderbird Audio/Video Playback Denial-of-Service Vulnerability (CVE-2026-4693)
slug: 2026-03-firefox-dos
description: 'CVE-2026-4693 is a vulnerability due to incorrect boundary conditions in the Audio/Video: Playback component of Mozilla Firefox and Thunderbird, potentially leading to a denial-of-service condition.'
date: "2026-03-24T13:16:05Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve
  - denial-of-service
  - firefox
  - thunderbird
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4693
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2018102
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-21/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Firefox Crash
    description: Detects crashes of the Firefox process, potentially indicative of exploitation attempts like CVE-2026-4693.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
  - title: Detect Thunderbird Crash
    description: Detects crashes of the Thunderbird process, potentially indicative of exploitation attempts like CVE-2026-4693.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-4693 is a security vulnerability affecting the Audio/Video Playback component in Mozilla Firefox and Thunderbird. This flaw, stemming from incorrect boundary conditions, can be exploited by an unauthenticated attacker to cause a denial-of-service condition. The vulnerability affects Firefox versions prior to 149, Firefox ESR versions prior to 115.34 and 140.9, and Thunderbird versions prior to 149 and 140.9. Successful exploitation of this vulnerability results in the application…
