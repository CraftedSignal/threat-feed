---
title: Stored XSS Vulnerability in Johnson Controls Metasys
slug: 2026-08-metasys-xss
description: A stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-34491) in Johnson Controls Metasys allows low-privileged users to execute arbitrary scripts in the context of other users' sessions, potentially leading to session hijacking.
date: "2026-08-13T16:52:17Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - industrial-control-systems
  - xss
  - web-vulnerability
vendors:
  - Johnson Controls
products:
  - Metasys
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A low-privilege user can inject a malicious XSS payload into the Metasys UI via a crafted URL.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-14
  - https://www.cve.org/CVERecord?id=CVE-2026-34491
rules:
  - title: Detect CVE-2026-34491 - Potential XSS Payload in URL
    description: Detects potential XSS injection attempts in HTTP requests targeting the Metasys UI via URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Metasys instances to version 16.0
      owner: IT Operations
      due: 72h
      evidence: Remediation guidance in ICSA-26-225-14
  enrichment_needed:
    - item: CVE-2026-34491
      owner: CTI
      reason: Monitor for emerging PoC code
      evidence: Source advisory
  hunt_leads:
    - lead: Search logs for unusual javascript payloads in URL parameters
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: XSS exploitation vector described in advisory
  mitigation_plan:
    - priority: immediate
      action: Isolate Metasys UI from internet access
      owner: Network Security
      addresses: CVE-2026-34491
      evidence: Mitigation guidance in ICSA-26-225-14
  gaps:
    - Lack of visibility into successful XSS storage within the application database
---

Johnson Controls Metasys versions 12, 13, 14, and 15 contain a critical Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-34491. This vulnerability exists because the Metasys UI fails to properly neutralize input during web page generation. An attacker with low-level user privileges can inject a persistent malicious payload via a crafted URL. This payload is stored and subsequently executed within the browser context of any user who views the manipulated URL, including administrative accounts. Successful exploitation could allow an attacker to hijack user sessions, perform unauthorized actions within the building automation system, or gain administrative-level access to the management interface. This flaw poses a significant risk to critical infrastructure sectors, including energy, government services, and transportation, where Metasys is deployed worldwide.

## Impact

Successful exploitation of this vulnerability enables attackers to perform actions on behalf of authenticated administrators, leading to unauthorized control of facility management systems. Given the nature of these building automation systems, compromise could lead to operational disruption, loss of monitoring, or access to sensitive environmental controls. There are currently no reports of this vulnerability being exploited in the wild, but the high CVSS score (8.0/8.6) necessitates immediate attention for systems exposed to internal or external networks.

## Recommendation

* Apply the latest available patches provided by Johnson Controls: Upgrade to Metasys 16.0, or patch to version 15.0.1 or 14.1.5 (when available).
* Restrict access to the Metasys UI by enforcing network segmentation, ensuring the interface is not exposed to the internet, and limiting access to trusted networks and users.
* Implement Content Security Policy (CSP) headers at the proxy or WAF level to mitigate the impact of injected scripts.
* Monitor Metasys UI access logs for suspicious URL patterns or unexpected script-based payloads.
* Enforce the principle of least privilege to minimize the potential impact if a standard user account is compromised.
