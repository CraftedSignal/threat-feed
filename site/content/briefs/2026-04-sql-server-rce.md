---
title: SQL Server Untrusted Pointer Dereference Vulnerability (CVE-2026-33120)
slug: 2026-04-sql-server-rce
description: CVE-2026-33120 is an untrusted pointer dereference vulnerability in Microsoft SQL Server that allows an authenticated attacker to achieve remote code execution over a network.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - sql-server
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-33120
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33120
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33120
ioc_counts:
  email: 2
rules:
  - title: Detect Suspicious SQL Server Process Creation
    description: Detects suspicious process creation events originating from SQL Server processes, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect SQL Server Network Activity on Non-Standard Ports
    description: Detects network connections to SQL Server processes on ports other than the default port 1433, which could indicate malicious activity or misconfiguration.
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

CVE-2026-33120 is a critical vulnerability affecting Microsoft SQL Server. This vulnerability, classified as an untrusted pointer dereference, allows an authorized attacker to execute arbitrary code on the targeted system remotely. Successful exploitation requires the attacker to be authenticated to the SQL Server instance, reducing the attack surface but still posing a significant threat to internal networks. The vulnerability was reported by Microsoft and assigned a CVSS v3.1 score of 8.8…
