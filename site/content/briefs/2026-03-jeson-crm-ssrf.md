---
title: DefaultFuction Jeson-Customer-Relationship-Management-System Server-Side Request Forgery Vulnerability
slug: 2026-03-jeson-crm-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in the DefaultFuction Jeson-Customer-Relationship-Management-System's API Module, specifically affecting the /api/System.php file, allowing remote attackers to manipulate the 'url' argument and potentially access internal resources.
date: "2026-03-24T03:16:06Z"
severities:
  - high
tags:
  - ssrf
  - cve-2026-4623
  - jeson-crm
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Remote File Copy
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4623
rules:
  - title: Detect Jeson CRM System.php SSRF Attempt
    description: Detects attempts to exploit the SSRF vulnerability (CVE-2026-4623) in the /api/System.php endpoint by monitoring for suspicious URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Jeson CRM System.php POST SSRF Attempt
    description: Detects POST requests to exploit the SSRF vulnerability (CVE-2026-4623) in the /api/System.php endpoint by monitoring for suspicious URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-4623, has been discovered in DefaultFuction Jeson-Customer-Relationship-Management-System up to version 1b4679c4d06b90d31dd521c2b000bfdec5a36e00. The vulnerability resides within the API Module, specifically in the /api/System.php file. An attacker can remotely manipulate the 'url' argument, causing the server to make requests to unintended locations. Due to the product's continuous delivery with rolling releases…
