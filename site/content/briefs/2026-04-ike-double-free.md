---
title: 'CVE-2026-33824: Windows IKE Extension Double Free Vulnerability'
slug: 2026-04-ike-double-free
description: A double free vulnerability in the Windows IKE Extension, tracked as CVE-2026-33824, allows an unauthenticated remote attacker to execute arbitrary code over the network.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-33824
  - windows
  - ike
  - double-free
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33824
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33824
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33824
ioc_counts:
  email: 1
rules:
  - title: Detect IKE Service Spawning Suspicious Processes
    description: Detects the IKE service (IKEEXT.DLL) spawning processes, which could indicate exploitation of CVE-2026-33824.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connections to IKE Service on Standard Port
    description: Detects network connections to the IKE service on the standard UDP port 500, which could indicate exploitation of CVE-2026-33824.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - network
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-33824 is a critical vulnerability affecting the Windows Internet Key Exchange (IKE) Extension. This double-free vulnerability enables an unauthenticated attacker to execute arbitrary code on a vulnerable system remotely. The vulnerability stems from improper memory management within the IKE service. Successful exploitation could lead to complete system compromise, making it a high-priority concern for defenders. Microsoft has assigned a CVSS v3.1 score of 9.8 to this vulnerability…
