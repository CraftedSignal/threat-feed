---
title: Firefox and Thunderbird JIT Miscompilation Vulnerability (CVE-2026-4698)
slug: 2026-03-firefox-jit-miscompilation
description: A critical JIT miscompilation vulnerability (CVE-2026-4698) in the JavaScript engine affects Firefox and Thunderbird, potentially leading to remote code execution.
date: "2026-03-24T13:16:05Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - firefox
  - thunderbird
  - jit
  - miscompilation
  - rce
  - cve-2026-4698
  - type-confusion
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4698
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2020906
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-21/
  - https://www.mozilla.org/security/advisories/mfsa2026-22/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
  - https://www.mozilla.org/security/advisories/mfsa2026-24/
rules:
  - title: Detect Firefox Crash Due To JIT Miscompilation
    description: Detects potential exploitation of JIT miscompilation vulnerabilities in Firefox by monitoring for crash events associated with the JIT compiler.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - application
      - windows
  - title: Detect Thunderbird Crash Due To JIT Miscompilation
    description: Detects potential exploitation of JIT miscompilation vulnerabilities in Thunderbird by monitoring for crash events associated with the JIT compiler.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - application
      - windows
rules_count: 2
---

CVE-2026-4698 describes a JIT miscompilation vulnerability within the JavaScript engine's JIT component in Mozilla Firefox and Thunderbird. Specifically, Firefox versions prior to 149, Firefox ESR versions less than 115.34 and 140.9, and Thunderbird versions before 149 and 140.9 are affected. This vulnerability stems from a type confusion issue (CWE-843) during JavaScript code compilation, which an attacker can exploit to potentially execute arbitrary code on a vulnerable system. Given the…
