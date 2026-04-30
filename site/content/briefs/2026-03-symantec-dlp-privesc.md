---
title: Symantec DLP Windows Endpoint Elevation of Privilege Vulnerability (CVE-2026-3991)
slug: 2026-03-symantec-dlp-privesc
description: CVE-2026-3991 is an elevation of privilege vulnerability in Symantec Data Loss Prevention (DLP) Windows Endpoint that could allow a local attacker to gain elevated access to resources.
date: "2026-03-30T19:16:27Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - vulnerability
  - privilege-escalation
  - symantec
  - dlp
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3991
  - https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/37306
rules:
  - title: Detect Suspicious Symantec DLP Process Creation
    description: Detects suspicious process creation events related to Symantec DLP EndpointAgent.exe that may indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Symantec DLP Process with Suspicious Parent
    description: Detects Symantec DLP processes being spawned by unusual parent processes, indicative of potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-3991 is an elevation of privilege vulnerability affecting Symantec Data Loss Prevention (DLP) Windows Endpoint versions prior to 25.1 MP1, 16.1 MP2, 16.0 RU2 HF9, 16.0 RU1 MP1 HF12, and 16.0 MP2 HF15. A local attacker could exploit this vulnerability to gain elevated privileges on the system. This could allow them to bypass DLP policies and access sensitive data normally protected by the application. The vulnerability was reported on March 30, 2026, and affects Windows endpoints…
