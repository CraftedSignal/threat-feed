---
title: Multiple Vulnerabilities in GLPI
slug: 2026-07-multiple-glpi-vulnerabilities
description: Multiple vulnerabilities have been discovered in GLPI, including SQL injection, cross-site scripting (XSS), and privilege escalation, which could allow an attacker to compromise data integrity, bypass security policies, and elevate their privileges within the system.
date: "2026-07-27T12:39:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web-application
  - sql-injection
  - xss
  - privilege-escalation
vendors:
  - GLPI Project
products:
  - GLPI (< 11.0.8)
  - GLPI (< 10.0.26)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: De multiples vulnérabilités ont été découvertes dans GLPI. Certaines d'entre elles permettent à un attaquant de provoquer une élévation de privilèges, une atteinte à l'intégrité des données et une injection SQL (SQLi).
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer une élévation de privilèges
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Atteinte à l'intégrité des données, Contournement de la politique de sécurité, Injection SQL (SQLi)
    confidence_band: med
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0935/
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-76v9-ch69-g67r
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-7v5q-w6f3-2v8p
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-8v8p-w8mq-wqcg
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-94rp-v9f2-5rj7
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-cpcj-x335-5cmh
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-hgr8-qvp5-mhch
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-v774-5g3p-vxg2
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-x5r8-r6vj-79cw
  - https://www.cve.org/CVERecord?id=CVE-2026-47678
  - https://www.cve.org/CVERecord?id=CVE-2026-47679
  - https://www.cve.org/CVERecord?id=CVE-2026-52848
  - https://www.cve.org/CVERecord?id=CVE-2026-53610
  - https://www.cve.org/CVERecord?id=CVE-2026-53625
  - https://www.cve.org/CVERecord?id=CVE-2026-53629
  - https://www.cve.org/CVERecord?id=CVE-2026-55214
  - https://www.cve.org/CVERecord?id=CVE-2026-57152
iocs:
  - type: url
    value: https://github.com/glpi-project/glpi/security/advisories/GHSA-7v5q-w6f3-2v8p
  - type: url
    value: https://github.com/glpi-project/glpi/security/advisories/GHSA-8v8p-w8mq-wqcg
  - type: url
    value: https://github.com/glpi-project/glpi/security/advisories/GHSA-94rp-v9f2-5rj7
  - type: url
    value: https://github.com/glpi-project/glpi/security/advisories/GHSA-cpcj-x335-5cmh
  - type: url
    value: https://github.com/glpi-project/glpi/security/advisories/GHSA-hgr8-qvp5-mhch
  - type: url
    value: https://github.com/glpi-project/glpi/security/advisories/GHSA-v774-5g3p-vxg2
  - type: url
    value: https://github.com/glpi-project/glpi/security/advisories/GHSA-x5r8-r6vj-79cw
ioc_counts:
  url: 7
---

Multiple critical vulnerabilities have been identified in GLPI versions 11.0.x prior to 11.0.8 and versions prior to 10.0.26. These vulnerabilities, detailed across several GLPI security advisories (GHSAs) and CVEs, include SQL injection (SQLi), cross-site scripting (XSS), and privilege escalation flaws. If exploited, these weaknesses could allow an attacker to gain unauthorized access to sensitive data, tamper with existing information, circumvent established security controls, or escalate their privileges within the GLPI application. The advisory, issued by CERT-FR on July 27, 2026, urges users to apply immediate patches to prevent potential compromise of their GLPI instances. These vulnerabilities pose a significant risk to the integrity and confidentiality of information managed by GLPI.

## Attack Chain

1. **Vulnerability Discovery**: An attacker identifies an internet-facing or internally accessible GLPI instance running a vulnerable version (e.g., glpi versions 11.0.x earlier than 11.0.8 or versions earlier than 10.0.26).
2. **Malicious Request Crafting**: The attacker crafts and sends specially malformed HTTP requests targeting identified vulnerabilities, such as parameters susceptible to SQL injection or input fields allowing cross-site scripting (XSS).
3. **SQL Injection Exploitation**: If successful, the attacker's crafted input executes unauthorized SQL queries against the GLPI database, leading to unauthorized data retrieval, modification, or deletion, potentially extracting sensitive information or altering application behavior.
4. **XSS Exploitation**: Alternatively, successful XSS exploitation injects malicious client-side scripts into web pages served by GLPI. When a legitimate user accesses the affected page, the script executes in their browser, potentially leading to session hijacking, credential theft, or redirection to attacker-controlled sites.
5. **Privilege Escalation**: Utilizing a specific vulnerability, the attacker exploits their existing access to gain higher-level permissions within the GLPI application, or potentially on the underlying operating system.
6. **Data Integrity Compromise / Policy Bypass**: With elevated privileges or successful data manipulation via SQLi, the attacker can bypass security policies, compromise the integrity of data stored or managed by GLPI, or achieve full administrative control over the application.

## Impact

Successful exploitation of these vulnerabilities could lead to severe consequences for organizations utilizing GLPI. Attackers could achieve complete data integrity compromise, leading to unauthorized modification or deletion of critical IT asset management and helpdesk data. The ability to bypass security policies could grant attackers unfettered access to sensitive configurations or user accounts. Privilege escalation allows attackers to gain administrative control, enabling them to disrupt services, exfiltrate confidential information, or deploy further malicious payloads. The scope of impact is potentially high for any organization using affected GLPI versions, as these systems often manage critical operational data and access.

## Recommendation

* Patch all affected GLPI installations immediately by upgrading to GLPI version 11.0.8 or newer, or GLPI version 10.0.26 or newer, as detailed in the GLPI security advisories referenced.
* Review web server logs for suspicious HTTP requests targeting GLPI endpoints, especially those containing common SQL injection or XSS payloads as indicators of attempted exploitation of CVE-2026-47678, CVE-2026-47679, CVE-2026-52848, CVE-2026-53610, CVE-2026-53625, CVE-2026-53629, CVE-2026-55214, and CVE-2026-57152.
* Implement a Web Application Firewall (WAF) to detect and block common SQL injection and XSS patterns, which can help mitigate exploitation attempts against the vulnerabilities described in this brief.
* Monitor network traffic for unusual outbound connections from your GLPI server, which could indicate post-exploitation activity after a successful privilege escalation.
