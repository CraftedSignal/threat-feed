---
title: CVE-2026-4729 Memory Safety Vulnerabilities in Firefox and Thunderbird
slug: 2026-06-firefox-thunderbird-cve
description: Firefox 148 and Thunderbird 148 contain memory safety bugs that could potentially be exploited to execute arbitrary code, impacting versions prior to 149.
date: "2026-03-25T14:18:11Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4729
  - memory-corruption
  - firefox
  - thunderbird
  - rce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4729
  - https://bugzilla.mozilla.org/buglist.cgi?bug_id=1944033%2C1997282%2C2009213%2C2011412%2C2021925%2C2022034
  - https://www.mozilla.org/security/advisories/mfsa2026-20/
  - https://www.mozilla.org/security/advisories/mfsa2026-23/
rules:
  - title: Firefox Thunderbird User Agent Detected
    description: Detects HTTP requests with user agents indicating vulnerable Firefox or Thunderbird versions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Suspicious Email Client Process Creation
    description: Detects unusual processes spawned by Thunderbird, potentially indicating exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-4729 describes memory safety vulnerabilities present in Firefox 148 and Thunderbird 148. According to the NVD analysis, some of these bugs exhibit memory corruption, suggesting a potential for exploitation. It is presumed that attackers could potentially exploit these vulnerabilities to achieve arbitrary code execution. Successful exploitation would allow an attacker to perform unauthorized actions, potentially compromising the confidentiality, integrity, and availability of the…
