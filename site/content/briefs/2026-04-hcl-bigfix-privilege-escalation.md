---
title: HCL BigFix Platform Insecure Permissions Vulnerability (CVE-2026-21765)
slug: 2026-04-hcl-bigfix-privilege-escalation
description: HCL BigFix Platform is vulnerable to insecure permissions on private cryptographic keys, where keys on a Windows host may have overly permissive file system permissions, potentially leading to unauthorized access and privilege escalation.
date: "2026-04-02T00:16:23Z"
severities:
  - high
tags:
  - cve-2026-21765
  - privilege-escalation
  - windows
  - hcl-bigfix
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-21765
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21765
  - https://support.hcl-software.com/csm?id=kb_article&sysparm_article=KB0129906
rules:
  - title: Detect Suspicious Access to HCL BigFix Private Keys
    description: Detects suspicious processes accessing HCL BigFix private key files with insecure permissions, indicating potential exploitation of CVE-2026-21765.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Modification of HCL BigFix Private Key Permissions
    description: Detects suspicious modification of file permissions on HCL BigFix private key files.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

HCL BigFix Platform is affected by insecure permissions on private cryptographic keys. This vulnerability, identified as CVE-2026-21765, exists because private cryptographic keys located on Windows host machines may have overly permissive file system permissions. This could allow unauthorized users or processes to access sensitive cryptographic material, potentially leading to privilege escalation or other malicious activities within the BigFix environment. Successful exploitation of this…
