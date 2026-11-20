---
brief_id: brief-2024-01-19-cisco-sdwan-info-disclosure
event_id: brief-2024-01-19-cisco-sdwan-info-disclosure
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:3866fa90aa2d14b89c38636c2cd92eabf64683432f8647edc5e88c784cd5939f
    summary: exploited:true; KEV CVE-2026-20133
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Cisco Catalyst SD-WAN Manager Information Disclosure Vulnerability (CVE-2026-20133)
slug: 2024-01-cisco-sdwan-info-disclosure
description: Cisco Catalyst SD-WAN Manager contains an information disclosure vulnerability (CVE-2026-20133) that could allow remote attackers to view sensitive information on affected systems, requiring immediate patching or mitigation.
date: "2024-01-19T12:00:00Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-04-20T00:00:00Z"
  confidence: high
tags:
  - cve
  - vulnerability
  - cisco
  - sd-wan
vendors:
  - Cisco
products:
  - Catalyst SD-WAN Manager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-20133
    cvss: 6.5
    epss: 0.0112
    kev: true
    kev_status: "true"
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-20133
  - https://www.cisa.gov/news-events/directives/ed-26-03-mitigate-vulnerabilities-cisco-sd-wan-systems
  - https://www.cisa.gov/news-events/directives/supplemental-direction-ed-26-03-hunt-and-hardening-guidance-cisco-sd-wan-systems
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20133
rules:
  - title: Detect Suspicious SD-WAN Manager HTTP Request
    description: Detects suspicious HTTP requests potentially exploiting vulnerabilities in Cisco SD-WAN Manager, such as CVE-2026-20133, based on URI patterns.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SD-WAN Manager HTTP Error Codes
    description: Detects potential exploitation attempts on Cisco SD-WAN Manager based on unusual server response codes, suggesting possible unauthorized access attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-20133
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Cisco Catalyst SD-WAN Manager is susceptible to an information disclosure vulnerability, identified as CVE-2026-20133. The vulnerability allows unauthorized remote attackers to potentially gain access to sensitive information residing on affected systems. While the exact nature of the disclosed information isn't specified in the advisory, it could encompass configuration details, user credentials, or other sensitive data critical for the secure operation of the SD-WAN environment. CISA has issued Emergency Directive 26-03 and associated guidance, highlighting the severity and urging immediate action. The directive impacts organizations utilizing Cisco SD-WAN devices and emphasizes the need for thorough risk assessment and implementation of provided mitigation strategies.

## Attack Chain

1.  **Vulnerability Discovery:** An attacker identifies a publicly accessible endpoint or API within the Cisco Catalyst SD-WAN Manager that is vulnerable to CVE-2026-20133.
2.  **Unauthorized Request:** The attacker crafts a malicious HTTP request targeting the vulnerable endpoint, exploiting the lack of proper authorization checks or input validation.
3.  **Information Exposure:** The SD-WAN Manager processes the request and, due to the vulnerability, inadvertently discloses sensitive information. This could be in the form of a file, database content, or API response.
4.  **Data Extraction:** The attacker captures the exposed data from the response, potentially including configuration files, usernames, passwords, or other sensitive credentials.
5.  **Credential Compromise:** The attacker uses the extracted credentials to gain unauthorized access to other systems within the SD-WAN environment or the broader network.
6.  **Lateral Movement:** Leveraging compromised credentials, the attacker moves laterally across the network, targeting critical systems and data.
7.  **Data Exfiltration / System Compromise:** The attacker exfiltrates sensitive data or achieves complete system compromise, depending on the attacker's objectives.

## Impact

Successful exploitation of CVE-2026-20133 can lead to significant consequences, including the compromise of sensitive data, unauthorized access to critical systems, and potential disruption of network operations. Given the central role of SD-WAN managers in controlling network traffic and security policies, a successful attack can have a wide-ranging impact. The number of potentially affected organizations is substantial due to the widespread adoption of Cisco SD-WAN solutions. The impact can include data breaches, financial loss, reputational damage, and regulatory penalties.

## Recommendation

*   Immediately assess your exposure to CVE-2026-20133 by following CISA’s Emergency Directive 26-03 mitigation instructions.
*   Apply the necessary patches or workarounds provided by Cisco to remediate the vulnerability as outlined in Cisco's security advisory.
*   If patches are unavailable or cannot be immediately applied, implement the hardening guidance provided in CISA’s “Hunt & Hardening Guidance for Cisco SD-WAN Devices”.
*   For cloud-based deployments, adhere to the applicable BOD 22-01 guidance for cloud services or discontinue use of the product if mitigations are not available.
*   Deploy the following Sigma rule to detect suspicious HTTP requests targeting potential vulnerable endpoints of the Cisco Catalyst SD-WAN Manager.
