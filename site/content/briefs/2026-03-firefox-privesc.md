---
title: Firefox Netmonitor Privilege Escalation Vulnerability (CVE-2026-4717)
slug: 2026-03-firefox-privesc
description: CVE-2026-4717 is a critical privilege escalation vulnerability in the Netmonitor component of Firefox, Firefox ESR, and Thunderbird, potentially allowing an attacker to gain elevated privileges on a vulnerable system.
date: "2026-03-24T13:16:07Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - firefox
  - thunderbird
  - cve-2026-4717
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4717
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2021695
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Exploitation Attempts of CVE-2026-4717 via Web Logs
    description: Detects potential exploitation attempts of CVE-2026-4717 based on suspicious HTTP requests targeting Firefox, Firefox ESR, or Thunderbird.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Thunderbird Child Process Executing Suspicious Programs
    description: Detects Thunderbird spawning a child process running suspicious executables that may indicate exploitation
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-4717 is a critical vulnerability affecting Mozilla Firefox, Firefox ESR, and Thunderbird. The vulnerability lies within the Netmonitor component and can lead to privilege escalation. Specifically, Firefox versions prior to 149, Firefox ESR versions prior to 140.9, Thunderbird versions prior to 149, and Thunderbird ESR versions prior to 140.9 are affected. The vulnerability allows an attacker to potentially gain elevated privileges on the targeted system. This could allow for arbitrary…
