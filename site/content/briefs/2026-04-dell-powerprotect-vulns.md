---
title: Multiple Vulnerabilities in Dell PowerProtect Data Domain OS
slug: 2026-04-dell-powerprotect-vulns
description: Multiple vulnerabilities in Dell PowerProtect Data Domain OS allow an attacker to execute arbitrary code with root privileges, escalate privileges to administrator, bypass security measures, manipulate data, disclose sensitive information, or conduct unspecified attacks.
date: "2026-04-21T08:05:52Z"
severities:
  - critical
tags:
  - dell
  - powerprotect
  - datadomain
  - vulnerability
  - privilege-escalation
  - defense-evasion
  - credential-access
  - impact
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1118
rules:
  - title: Detect Web Request for Potential Dell PowerProtect Exploit
    description: Detects suspicious web requests targeting Dell PowerProtect Data Domain OS that may indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect System Command Execution From Unusual Processes
    description: Detects the execution of common system commands (e.g., bash, sh, cmd) from processes that are not typically associated with such activity, indicating potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Multiple vulnerabilities exist within Dell PowerProtect Data Domain OS, potentially enabling a malicious actor to compromise systems. Successful exploitation could lead to arbitrary code execution with root privileges, privilege escalation to administrator level, circumvention of security mechanisms, data manipulation, sensitive information disclosure, and the execution of other unspecified malicious activities. The vulnerabilities could be exploited to gain complete control over the affected…
