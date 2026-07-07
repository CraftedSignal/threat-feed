---
title: 'CVE-2026-14746: SQL Injection in code-projects Real State Services'
slug: 2026-07-code-projects-real-state-services-sql-injection
description: A high-severity SQL injection vulnerability (CVE-2026-14746) exists in code-projects Real State Services 1.0, specifically in the `/addprojectrent.php` file, where the `amen` argument can be manipulated to execute arbitrary SQL commands, enabling remote attackers to achieve unauthorized data access or modification, with public exploit disclosure increasing the risk of active exploitation.
date: "2026-07-05T12:21:44Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - web-vulnerability
  - cve
  - webserver
  - public-exploit
vendors:
  - code-projects
products:
  - Real State Services 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely. The exploit has been disclosed publicly and may be used.
    confidence_band: high
cves:
  - id: CVE-2026-14746
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14746
  - https://code-projects.org/
  - https://github.com/6Justdododo6/CVE/issues/25
  - https://vuldb.com/cve/CVE-2026-14746
  - https://vuldb.com/submit/849284
  - https://vuldb.com/vuln/376332
  - https://vuldb.com/vuln/376332/cti
rules:
  - title: Detects CVE-2026-14746 Exploitation — SQL Injection in Real State Services
    description: Detects CVE-2026-14746 exploitation attempts against code-projects Real State Services 1.0 via SQL injection in the 'amen' argument of '/addprojectrent.php'.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A high-severity SQL injection vulnerability, identified as CVE-2026-14746, has been discovered in version 1.0 of the code-projects Real State Services application. This flaw specifically affects the `/addprojectrent.php` endpoint, where an attacker can manipulate the `amen` argument to inject and execute arbitrary SQL commands. The vulnerability is remotely exploitable and does not require authentication, making it a critical threat. Public disclosure of the exploit increases the likelihood of active exploitation in the wild. This vulnerability could lead to unauthorized access to sensitive data, modification of database contents, or potentially complete compromise of the affected web application's data. Organizations running this specific application version are strongly advised to take immediate remediation steps.

## Attack Chain

1.  An unauthenticated attacker identifies an internet-facing instance of code-projects Real State Services 1.0.
2.  The attacker crafts a malicious HTTP POST request targeting the `/addprojectrent.php` endpoint.
3.  Within the POST request, the attacker injects SQL payloads into the `amen` argument.
4.  The vulnerable application processes the `amen` argument without adequate input validation or sanitization.
5.  The malicious SQL payload is then executed directly within the application's backend database.
6.  This successful injection allows the attacker to read, modify, or delete sensitive data within the database.
7.  The attacker may also be able to gain unauthorized administrative access or exfiltrate confidential information, leading to data breaches.

## Impact

Successful exploitation of CVE-2026-14746 can lead to severe consequences for organizations utilizing code-projects Real State Services 1.0. Attackers can gain full control over the application's database, allowing them to steal sensitive user data, property listings, or financial information. They could also manipulate or deface the website, insert malicious content, or compromise the integrity of the real estate listings. Given that the exploit has been publicly disclosed, organizations running this application are at an elevated risk of immediate data breaches, reputational damage, and operational disruption.

## Recommendation

*   Immediately apply any available patches or updates provided by code-projects for Real State Services 1.0 to address CVE-2026-14746.
*   Implement robust input validation and sanitization for all user-supplied data, specifically focusing on the `amen` argument in `/addprojectrent.php`, to prevent SQL injection attacks.
*   Deploy a Web Application Firewall (WAF) to detect and block malicious HTTP requests containing SQL injection payloads, protecting against CVE-2026-14746.
*   Deploy the Sigma rule "Detects CVE-2026-14746 Exploitation — SQL Injection in Real State Services" to your SIEM and tune for your environment to identify attempted exploitation.
