---
title: Critical Unauthenticated RCE Vulnerability Exploited in Microsoft SharePoint
slug: 2026-03-sharepoint-rce
description: A remote code execution vulnerability in Microsoft SharePoint (CVE not specified) is being actively exploited by unauthenticated attackers, prompting urgent patching recommendations for internet-facing servers.
date: "2026-03-25T08:51:39Z"
severities:
  - critical
tags:
  - sharepoint
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://cert.europa.eu/publications/security-advisories/2026-004/
rules:
  - title: SharePoint Suspicious Process Creation
    description: Detects suspicious processes spawned by the SharePoint application pool account, indicating potential RCE exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: SharePoint Unauthenticated RCE Attempt
    description: Detects potential unauthenticated RCE attempts against SharePoint based on HTTP request patterns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

On March 17, 2026, Microsoft revised a January 2026 security advisory concerning a remote code execution (RCE) vulnerability in Microsoft SharePoint. The update included a heightened CVSS score and a clarification indicating that the vulnerability could be exploited by unauthenticated attackers. This exploitability led to its inclusion in CISA's Known Exploited Vulnerabilities (KEV) catalog on March 18, 2026. The advisory also mentions that three additional RCE vulnerabilities in Microsoft…
