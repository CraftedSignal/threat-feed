---
title: Firefox and Thunderbird Memory Safety Vulnerability (CVE-2026-4720)
slug: 2026-03-firefox-memory-safety
description: A memory safety vulnerability (CVE-2026-4720) in Firefox ESR 140.8, Thunderbird ESR 140.8, Firefox 148 and Thunderbird 148 could lead to memory corruption and potential arbitrary code execution if successfully exploited.
date: "2026-03-25T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4720
  - firefox
  - thunderbird
  - memory-corruption
  - arbitrary-code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4720
  - https://bugzilla.mozilla.org/buglist.cgi?bug_id=2004652%2C2019372%2C2021922%2C2022567%2C2022733
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
ioc_counts:
  email: 1
rules:
  - title: Detect Firefox Thunderbird Memory Safety Exploitation
    description: Detects potential exploitation attempts of memory safety vulnerabilities in Firefox and Thunderbird by monitoring for unexpected child processes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Firefox Thunderbird Network Connection to Suspicious Domains
    description: Detects potential exploitation attempts of memory safety vulnerabilities in Firefox and Thunderbird by monitoring for connections to unusual TLDs.
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

A critical memory safety vulnerability, tracked as CVE-2026-4720, affects Mozilla Firefox and Thunderbird. Specifically, Firefox ESR 140.8, Thunderbird ESR 140.8, Firefox 148, and Thunderbird 148 are vulnerable. The identified memory safety bugs exhibit evidence of memory corruption, suggesting that with sufficient effort, attackers could exploit these vulnerabilities to execute arbitrary code on affected systems. Users of Firefox versions prior to 149, Firefox ESR versions prior to 140.9…
