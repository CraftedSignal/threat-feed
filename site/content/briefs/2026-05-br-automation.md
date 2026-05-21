---
title: ABB B&R Automation Runtime Multiple Vulnerabilities
slug: 2026-05-br-automation
description: ABB B&R Automation Runtime versions before 6.4 are vulnerable to predictable number generation (CVE-2025-3449), reflected XSS (CVE-2025-3448), and CSV injection (CVE-2025-11498), potentially allowing attackers to hijack sessions or execute arbitrary code in a user's browser context.
date: "2026-05-21T16:10:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - xss
  - session hijacking
  - csv injection
  - cve-2025-3449
  - cve-2025-3448
  - cve-2025-11498
vendors:
  - ABB
  - B&R
products:
  - Automation Runtime
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-3449
    cvss: 4.2
    epss: 0.00029
  - id: CVE-2025-3448
    cvss: 6.1
    epss: 0.00031
  - id: CVE-2025-11498
    cvss: 6.1
    epss: 0.00033
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04
  - https://www.cve.org/CVERecord?id=CVE-2025-3449
  - https://www.cve.org/CVERecord?id=CVE-2025-3448
  - https://www.cve.org/CVERecord?id=CVE-2025-11498
rules:
  - title: Detect ABB B&R Automation Runtime CVE-2025-3448 XSS Attempt
    description: Detects CVE-2025-3448 exploitation — Reflected XSS attempts targeting ABB B&R Automation Runtime System Diagnostics Manager (SDM) via suspicious URL parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect ABB B&R Automation Runtime CVE-2025-11498 CSV Injection Attempt
    description: Detects CVE-2025-11498 exploitation — formula injection attempt within the CSV file downloaded.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - windows
rules_count: 2
---

ABB B&R Automation Runtime versions before 6.4 are affected by multiple vulnerabilities within the System Diagnostics Manager (SDM) component. These vulnerabilities include predictable number generation (CVE-2025-3449), reflected cross-site scripting (XSS) (CVE-2025-3448), and improper neutralization of formula elements in a CSV file (CVE-2025-11498). Successful exploitation of these vulnerabilities could allow an unauthenticated, network-based attacker to take over an already established session or execute arbitrary JavaScript code within the context of a user's browser. The SDM is disabled by default but if enabled, is not intended to be enabled on active systems outside secured production networks. This impacts the Energy sector globally.

## Attack Chain

1.  Attacker identifies a vulnerable ABB B&R Automation Runtime instance running a version prior to 6.4 with SDM enabled.
2.  For CVE-2025-3449, the attacker exploits the predictable number generation vulnerability in the SDM component to predict session identifiers.
3.  The attacker uses the predicted session identifier to hijack an existing, valid session, gaining unauthorized access to the SDM interface.
4.  For CVE-2025-3448, the attacker crafts a malicious URL containing a reflected XSS payload targeting the SDM component.
5.  The attacker lures a legitimate user into clicking the malicious URL, potentially through phishing or social engineering.
6.  The user's browser executes the attacker-controlled JavaScript code within the context of the SDM web application.
7.  The attacker can perform actions on behalf of the user or steal sensitive information accessible through the SDM interface.
8.  For CVE-2025-11498, the attacker crafts a malicious link.
9. The user clicks the link, a CSV file is downloaded and the user would need to manually open it.
10. The attacker can inject formula data into a generated CSV file.

## Impact

Successful exploitation of these vulnerabilities could allow attackers to hijack existing sessions or execute arbitrary JavaScript code within a user's browser. This could lead to information disclosure, unauthorized control of the Automation Runtime system, and potential disruption of industrial processes. While the SDM is disabled by default, systems with SDM enabled are at risk. There is no mention of number of victims. This impacts the Energy sector.

## Recommendation

*   Upgrade ABB B&R Automation Runtime to version 6.4 or later to remediate CVE-2025-3449, CVE-2025-3448, and CVE-2025-11498.
*   If upgrading is not immediately feasible, ensure the System Diagnostic Manager (SDM) is disabled.
*   Implement network segmentation and access controls to limit exposure of Automation Runtime systems.
*   Monitor web server logs for suspicious URL patterns indicative of XSS attempts targeting the SDM, using a rule similar to the "Detect ABB B&R Automation Runtime CVE-2025-3448 XSS Attempt" Sigma rule.
*   Train users to recognize and avoid suspicious links to mitigate CVE-2025-11498.
