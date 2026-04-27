---
title: AIRBUS PSS TETRA Connectivity Server Privilege Escalation via Incorrect Permissions
slug: 2026-04-airbus-tetra-privesc
description: AIRBUS PSS TETRA Connectivity Server version 7.0 on Windows Server is vulnerable to incorrect default permissions, allowing local privilege escalation to SYSTEM by placing a malicious file in a specific directory.
date: "2026-04-03T08:16:17Z"
severities:
  - high
tags:
  - cve-2025-7024
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-7024
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-7024
rules:
  - title: Detect Suspicious File Creation in Vulnerable Directory
    description: Detects the creation of new files in directories associated with AIRBUS PSS TETRA Connectivity Server, indicating potential exploitation of CVE-2025-7024.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Executables Started from Unusual Locations
    description: This rule detects processes being executed from unusual directories which might indicate an exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

AIRBUS PSS TETRA Connectivity Server version 7.0 running on Windows Server operating systems is susceptible to a privilege escalation vulnerability (CVE-2025-7024) due to incorrect default permissions. An attacker, with low privileges, can exploit this vulnerability to execute arbitrary code with SYSTEM privileges. The attack requires a user to be tricked or directed into placing a crafted file into a specific, vulnerable directory within the TETRA Connectivity Server installation. A fix is…
