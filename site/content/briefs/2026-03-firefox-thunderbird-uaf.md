---
title: Mozilla Firefox and Thunderbird Use-After-Free Vulnerability (CVE-2026-4723)
slug: 2026-03-firefox-thunderbird-uaf
description: A use-after-free vulnerability, CVE-2026-4723, in the JavaScript Engine of Mozilla Firefox and Thunderbird before version 149 could allow arbitrary code execution if successfully exploited by an attacker.
date: "2026-03-24T13:16:08Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - use-after-free
  - firefox
  - thunderbird
  - javascript
  - cve-2026-4723
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4723
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2013573
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
rules:
  - title: Detect JavaScript Use-After-Free Attempt
    description: Detects attempts to trigger a use-after-free vulnerability by monitoring JavaScript execution in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Network Connection from Firefox/Thunderbird Post JavaScript
    description: Detects outbound network connections initiated by Firefox or Thunderbird shortly after JavaScript execution, which might indicate code execution from a UAF vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-4723 is a critical use-after-free vulnerability affecting the JavaScript Engine component in Mozilla Firefox and Thunderbird. This flaw exists in versions prior to 149. A remote attacker could potentially exploit this vulnerability by crafting malicious JavaScript code that, when processed by a vulnerable browser or email client, triggers the use-after-free condition. The vulnerability was reported by Mozilla Corporation and assigned a CVSS v3.1 base score of 9.8, indicating a high…
