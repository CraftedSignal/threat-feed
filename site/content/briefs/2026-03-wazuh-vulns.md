---
title: Multiple Vulnerabilities in Wazuh Leading to Code Execution and Data Manipulation
slug: 2026-03-wazuh-vulns
description: Multiple vulnerabilities in Wazuh allow an attacker to perform denial-of-service attacks, execute arbitrary code, manipulate data, and disclose sensitive information, potentially leading to significant data breaches and system compromise.
date: "2026-03-30T11:24:10Z"
severities:
  - critical
tags:
  - wazuh
  - vulnerability
  - code-execution
  - data-manipulation
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Manipulation
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0908
rules:
  - title: Detect Possible Wazuh Code Execution via Web Request
    description: Detects suspicious HTTP requests potentially leading to code execution on Wazuh servers.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Possible Data Manipulation on Wazuh Server
    description: Detects suspicious file modifications within Wazuh directories that may indicate data manipulation.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Wazuh, a widely used open-source security information and event management (SIEM) system, is susceptible to multiple vulnerabilities that could have severe consequences for organizations relying on it for security monitoring. These vulnerabilities, if exploited, could allow attackers to perform a denial-of-service (DoS) attack, execute arbitrary code, manipulate sensitive data, and expose confidential information. The specifics of these vulnerabilities are not detailed in this brief, but the…
