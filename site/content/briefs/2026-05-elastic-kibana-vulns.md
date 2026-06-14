---
title: Multiple Vulnerabilities in Elastic Kibana
slug: 2026-05-elastic-kibana-vulns
description: Multiple vulnerabilities in Elastic Kibana allow for privilege escalation, remote denial of service, data breach, server-side request forgery (SSRF), and cross-site scripting (XSS).
date: "2026-05-29T14:40:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kibana
  - vulnerability
  - privilege escalation
  - denial of service
  - data breach
  - SSRF
  - XSS
vendors:
  - Elastic
products:
  - Kibana (8.x)
  - Kibana (9.x)
  - Kibana
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-42398
    cvss: 7.7
    epss: 0.00028
  - id: CVE-2026-49093
    cvss: 6.3
    epss: 0.00028
  - id: CVE-2026-33463
    cvss: 5.3
    epss: 0.0003
  - id: CVE-2026-42399
    cvss: 6.5
    epss: 0.00039
  - id: CVE-2026-49095
    cvss: 6.5
    epss: 0.00042
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0661/
  - https://discuss.elastic.co/t/kibana-8-19-16-and-9-3-5-security-update-esa-2026-30/386545
  - https://discuss.elastic.co/t/kibana-8-19-16-9-3-5-9-4-1-security-update-esa-2026-32/386548
  - https://discuss.elastic.co/t/8-19-16-9-3-5-security-update-esa-2026-33/386551
  - https://discuss.elastic.co/t/kibana-8-19-16-9-3-5-security-update-esa-2026-34/386552
  - https://discuss.elastic.co/t/kibana-8-19-16-9-3-5-9-4-2-security-update-esa-2026-35/386554
  - https://discuss.elastic.co/t/kibana-8-19-16-and-9-3-5-security-update-esa-2026-36/386556
  - https://discuss.elastic.co/t/kibana-9-2-8-and-9-3-2-security-update-esa-2026-37/386557
  - https://discuss.elastic.co/t/kibana-fleet-8-19-16-9-3-5-and-9-4-2-security-update-esa-2026-38/386559
  - https://discuss.elastic.co/t/kibana-8-19-16-security-update-esa-2026-39/386561
  - https://discuss.elastic.co/t/kibana-9-3-3-security-update-esa-2026-40/386562
  - https://www.cve.org/CVERecord?id=CVE-2026-33462
  - https://www.cve.org/CVERecord?id=CVE-2026-33463
  - https://www.cve.org/CVERecord?id=CVE-2026-33464
  - https://www.cve.org/CVERecord?id=CVE-2026-42398
  - https://www.cve.org/CVERecord?id=CVE-2026-42399
  - https://www.cve.org/CVERecord?id=CVE-2026-42400
  - https://www.cve.org/CVERecord?id=CVE-2026-42401
  - https://www.cve.org/CVERecord?id=CVE-2026-49093
  - https://www.cve.org/CVERecord?id=CVE-2026-49094
  - https://www.cve.org/CVERecord?id=CVE-2026-49095
rules:
  - title: Detects CVE-2026-42398 exploitation attempt - Suspicious Kibana request with SSRF characters
    description: Detects CVE-2026-42398 exploitation attempt - Detects potential Server-Side Request Forgery (SSRF) attempts in Kibana by identifying suspicious characters in the request URI.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-49093 exploitation attempt - Suspicious Kibana request with XSS characters
    description: Detects CVE-2026-49093 exploitation attempt - Detects potential Cross-Site Scripting (XSS) attempts in Kibana by identifying suspicious characters in the request URI.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been discovered in Elastic Kibana, potentially leading to significant security risks. The vulnerabilities can allow an attacker to perform actions such as privilege escalation, remote denial of service (DoS), data breaches, server-side request forgery (SSRF), and cross-site scripting (XSS). These flaws affect Kibana versions 8.x prior to 8.19.16, versions 9.x prior to 9.3.5, and versions 9.4.x prior to 9.4.2. Successful exploitation of these vulnerabilities could allow attackers to gain unauthorized access, disrupt services, or steal sensitive information. Elastic published security bulletins on May 28, 2026, addressing these issues and providing guidance for patching.

## Attack Chain

1.  An attacker identifies a vulnerable Kibana instance running a version prior to 8.19.16, 9.3.5, or 9.4.2.
2.  The attacker exploits CVE-2026-42398 (or another applicable vulnerability) to perform a SSRF attack.
3.  Using the SSRF vulnerability, the attacker bypasses security policies.
4.  The attacker exploits CVE-2026-49093 (or another applicable vulnerability) to inject malicious JavaScript code via XSS.
5.  A legitimate user interacts with the compromised Kibana interface, triggering the XSS payload.
6.  The injected JavaScript steals the user's session cookies or other sensitive information.
7.  The attacker uses the stolen credentials to elevate their privileges within the Kibana application.
8.  The attacker gains unauthorized access to sensitive data or disrupts Kibana services, leading to a denial of service.

## Impact

Successful exploitation of these vulnerabilities could lead to significant damage. An attacker could gain unauthorized access to sensitive data, leading to data breaches and compliance violations. Remote denial-of-service attacks could disrupt critical services and impact business operations. Privilege escalation could allow attackers to gain full control over the Kibana instance, potentially compromising the entire Elastic Stack environment. These vulnerabilities impact Kibana versions 8.x before 8.19.16, 9.x before 9.3.5, and 9.4.x before 9.4.2.

## Recommendation

*   Upgrade Kibana to version 8.19.16, 9.3.5, or 9.4.2 or later to patch the vulnerabilities mentioned in Elastic's security bulletins (Bulletin de sécurité Elastic 386545, 386548, 386551, 386552, 386554, 386556, 386557, 386559, 386561, 386562).
*   Deploy web application firewall (WAF) rules to detect and block exploitation attempts targeting the vulnerabilities, specifically focusing on SSRF and XSS payloads.
*   Monitor web server logs for suspicious activity, such as unusual requests or attempts to access sensitive endpoints, to identify potential exploitation attempts (webserver category).
*   Deploy the provided Sigma rules to detect potential exploitation attempts in your SIEM environment and tune them for your specific environment.
