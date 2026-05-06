---
title: Palo Alto Networks PAN-OS Out-of-bounds Write Vulnerability Added to CISA KEV Catalog
slug: 2026-05-panos-oob-write
description: CVE-2026-0300, a Palo Alto Networks PAN-OS out-of-bounds write vulnerability, has been added to CISA's Known Exploited Vulnerabilities Catalog due to evidence of active exploitation.
date: "2026-05-06T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - cve-2026-0300
  - kev
  - out-of-bounds write
  - pan-os
  - active exploitation
vendors:
  - Palo Alto Networks
products:
  - PAN-OS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.cisa.gov/news-events/alerts/2026/05/06/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-0300
rules:
  - title: Detect Potential CVE-2026-0300 Exploitation Attempts
    description: Detects potential attempts to exploit the PAN-OS out-of-bounds write vulnerability (CVE-2026-0300) based on suspicious HTTP requests. This rule requires web server logs from PAN-OS.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PAN-OS Suspicious Process Execution
    description: Detects suspicious processes spawned by PAN-OS services that could indicate exploitation. This rule requires process creation logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CISA added CVE-2026-0300, an out-of-bounds write vulnerability in Palo Alto Networks PAN-OS, to its Known Exploited Vulnerabilities (KEV) Catalog on May 6, 2026, indicating active exploitation in the wild. The vulnerability poses a significant risk, especially to federal enterprises, and CISA has urged all organizations to prioritize its remediation. An out-of-bounds write vulnerability allows an attacker to write data outside the intended memory boundaries, which can lead to arbitrary code execution, denial of service, or information disclosure. Successful exploitation could enable attackers to gain unauthorized access to systems and networks protected by PAN-OS. Given its inclusion in the KEV catalog, prompt action is required to mitigate this risk.

## Attack Chain

While the specifics of the exploitation are not detailed in the source material, a typical attack chain involving an out-of-bounds write vulnerability could involve the following steps:

1.  **Reconnaissance:** The attacker identifies a vulnerable PAN-OS instance exposed to the internet.
2.  **Vulnerability Trigger:** The attacker sends a specially crafted request to the PAN-OS device, exploiting the out-of-bounds write vulnerability (CVE-2026-0300). This crafted request could target a specific service or feature within PAN-OS.
3.  **Memory Corruption:** The malicious request causes the PAN-OS device to write data outside of the intended memory buffer.
4.  **Code Injection:** The attacker overwrites critical data or injects malicious code into memory.
5.  **Privilege Escalation:** The injected code is executed with elevated privileges, allowing the attacker to gain control of the system.
6.  **Lateral Movement:** The attacker uses their newly acquired access to move laterally within the network, compromising additional systems.
7.  **Data Exfiltration/Ransomware Deployment:** The attacker exfiltrates sensitive data or deploys ransomware to encrypt data and demand a ransom payment.

## Impact

Successful exploitation of CVE-2026-0300 could lead to complete compromise of the PAN-OS device, providing attackers with access to internal networks and sensitive data. This could result in data breaches, financial losses, and reputational damage. Given CISA's inclusion of this vulnerability in the KEV catalog, it is likely that exploitation has been observed in multiple organizations, potentially across various sectors.

## Recommendation

*   Immediately patch Palo Alto Networks PAN-OS instances to address CVE-2026-0300, as indicated by CISA's KEV catalog entry.
*   Deploy the Sigma rule provided below to detect potential exploitation attempts targeting CVE-2026-0300.
*   Monitor network traffic for suspicious patterns indicative of out-of-bounds write exploitation, specifically focusing on traffic to and from PAN-OS devices.
*   Review PAN-OS access logs for any unusual or unauthorized activity following the patch deployment.
