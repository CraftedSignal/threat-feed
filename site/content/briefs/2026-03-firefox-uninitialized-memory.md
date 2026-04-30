---
title: Uninitialized Memory Vulnerability in Firefox Canvas2D (CVE-2026-4715)
slug: 2026-03-firefox-uninitialized-memory
description: 'CVE-2026-4715 is a critical vulnerability involving uninitialized memory in the Graphics: Canvas2D component of Firefox, Firefox ESR, and Thunderbird, potentially leading to information disclosure or arbitrary code execution.'
date: "2026-03-24T13:16:07Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4715
  - firefox
  - thunderbird
  - uninitialized-memory
  - vulnerability
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4715
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2018405
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Firefox Process Launch with Version Less Than 149
    description: Detects the launch of Firefox with a version number less than 149, indicating a potentially vulnerable instance.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
  - title: Detect Thunderbird Process Launch with Version Less Than 149
    description: Detects the launch of Thunderbird with a version number less than 149, indicating a potentially vulnerable instance.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-4715 describes an uninitialized memory flaw within the Canvas2D graphics component of Mozilla Firefox, Firefox ESR, and Thunderbird. Discovered and reported in March 2026, this vulnerability affects Firefox versions prior to 149, Firefox ESR versions prior to 140.9, Thunderbird versions prior to 149, and Thunderbird ESR versions prior to 140.9. Successful exploitation of this issue could allow an attacker to read sensitive information from memory or potentially execute arbitrary code…
