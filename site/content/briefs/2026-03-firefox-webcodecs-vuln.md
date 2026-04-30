---
title: Mozilla Firefox and Thunderbird WebCodecs Boundary Condition Vulnerability (CVE-2026-4695)
slug: 2026-03-firefox-webcodecs-vuln
description: An incorrect boundary condition in the Audio/Video Web Codecs component in Mozilla Firefox and Thunderbird (CVE-2026-4695) could lead to a denial-of-service (DoS) condition due to a vulnerability that affects Firefox < 149, Firefox ESR < 140.9, Thunderbird < 149, and Thunderbird < 140.9.
date: "2026-03-24T13:16:05Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-4695
  - firefox
  - thunderbird
  - webcodecs
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4695
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2020030
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Firefox Crash Due to WebCodecs
    description: Detects Firefox crashes potentially related to WebCodecs vulnerabilities by monitoring for crash reports with WebCodecs-related modules.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Thunderbird Crash Due to WebCodecs
    description: Detects Thunderbird crashes potentially related to WebCodecs vulnerabilities by monitoring for crash reports with WebCodecs-related modules.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-4695 describes a vulnerability affecting Mozilla Firefox and Thunderbird related to incorrect boundary conditions in the Audio/Video Web Codecs component. This flaw impacts Firefox versions prior to 149, Firefox ESR versions prior to 140.9, Thunderbird versions prior to 149, and Thunderbird ESR versions prior to 140.9. An attacker could potentially exploit this vulnerability to cause a denial-of-service condition, impacting the availability of the application. This vulnerability was…
