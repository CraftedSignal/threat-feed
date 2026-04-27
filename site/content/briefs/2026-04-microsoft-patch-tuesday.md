---
title: Microsoft April 2026 Patch Tuesday Addresses 163 Vulnerabilities
slug: 2026-04-microsoft-patch-tuesday
description: Microsoft's April 2026 Patch Tuesday addresses 163 vulnerabilities, including 8 critical ones, ranging from Tampering to Remote Code Execution and Privilege Escalation, affecting various Microsoft products; it is recommended to apply patches immediately.
date: "2026-04-16T10:00:00Z"
severities:
  - critical
exploited: true
tags:
  - patch-tuesday
  - vulnerability
  - remote-code-execution
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
cves:
  - id: CVE-2026-33826
    cvss: 8
  - id: CVE-2026-33825
    cvss: 7.8
    epss: 0.03818
  - id: CVE-2026-33824
    cvss: 9.8
  - id: CVE-2026-33827
    cvss: 8.1
  - id: CVE-2026-27913
    cvss: 7.7
  - id: CVE-2026-26151
    cvss: 7.1
references:
  - https://ccb.belgium.be/advisories/warning-microsoft-patch-tuesday-april-2026-patches-163-vulnerabilities-8-critical-154
  - https://msrc.microsoft.com/update-guide/releaseNote/2026-Apr
  - https://thehackernews.com/2026/04/microsoft-issues-patches-for-sharepoint.html
  - https://www.tenable.com/blog/microsofts-april-2026-patch-tuesday-addresses-163-cves-cve-2026-32201
  - https://www.zerodayinitiative.com/blog/2026/4/14/the-april-2026-security-update-review
rules:
  - title: Detect Suspicious RPC Calls to Active Directory
    description: Detects suspicious RPC calls indicative of potential CVE-2026-33826 exploitation in Windows Active Directory environments.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Exploitation Attempts CVE-2026-33824 (Windows IKE Service Extensions)
    description: Detects suspicious network traffic to IKE service extensions, potentially indicating exploitation attempts related to CVE-2026-33824.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Microsoft's April 2026 Patch Tuesday addresses 163 vulnerabilities across its product range, with 8 rated as critical. This update includes fixes for actively exploited zero-day vulnerabilities. The vulnerabilities span multiple categories, including remote code execution (RCE), elevation of privilege, and spoofing. Specifically, CVE-2026-32201 is a zero-day actively exploited in Microsoft SharePoint, and CVE-2026-33826 poses a critical RCE risk in Windows Active Directory environments. Given…
