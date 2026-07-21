---
title: Multiple SQL Injection Vulnerabilities in Tenable Nessus (CVE-2026-57587, CVE-2026-57588)
slug: 2026-06-tenable-nessus-sqli-vulnerabilities
description: Multiple SQL injection vulnerabilities, CVE-2026-57587 and CVE-2026-57588, have been discovered in Tenable Nessus versions prior to 10.12.0, allowing an attacker to perform unauthorized access to or manipulation of the underlying database through specially crafted input.
date: "2026-06-26T14:36:12Z"
lastmod: "2026-07-21T19:01:16Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:tenable:nessus:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CED3868D-4B65-5480-8F14-8B2C62A3A12F&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - sqli
  - tenable
  - nessus
  - exploitation
vendors:
  - Tenable
products:
  - Nessus (< 10.12.0)
  - Nessus < 10.12.1
affected_os:
  - Linux
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: De multiples vulnérabilités ont été découvertes dans Tenable Nessus. Elles permettent à un attaquant de provoquer une injection SQL (SQLi).
    confidence_band: high
cves:
  - id: CVE-2026-57587
    cvss: 5.3
    epss: 0.00339
  - id: CVE-2026-57588
    cvss: 3.3
    epss: 0.00304
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0804/
  - https://www.tenable.com/security/tns-2026-17
  - https://www.cve.org/CVERecord?id=CVE-2026-57587
  - https://www.cve.org/CVERecord?id=CVE-2026-57588
  - https://www.exploit-db.com/exploits/52620
  - https://sploitus.com/exploit?id=CED3868D-4B65-5480-8F14-8B2C62A3A12F&utm_source=rss&utm_medium=rss
iocs:
  - type: domain
    value: poc-target.example.com
  - type: file_name
    value: malicious.nessus
  - type: file_name
    value: cve-2026-57588-poc.nessus
  - type: file_path
    value: /etc/passwd
  - type: url
    value: https://github.com/mbanyamer
  - type: url
    value: https://banyamersecurity.com/blog/
  - type: url
    value: https://www.tenable.com
  - type: url
    value: https://www.tenable.com/downloads/nessus
  - type: handle
    value: '@banyamer_security'
  - type: url
    value: https://sploitus.com/exploit?id=CED3868D-4B65-5480-8F14-8B2C62A3A12F
ioc_counts:
  domain: 1
  file_name: 2
  file_path: 1
  handle: 1
  url: 5
updates:
  - at: "2026-07-07T13:25:49Z"
    level: L1
    summary: OS linux; OS windows
    sources:
      - exploit-db
  - at: "2026-07-21T19:01:16Z"
    level: L2
    summary: poc_available; added CVE-2026-57587 +1
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CED3868D-4B65-5480-8F14-8B2C62A3A12F&utm_source=rss&utm_medium=rss
---

CERT-FR has issued an advisory regarding multiple SQL injection (SQLi) vulnerabilities, identified as CVE-2026-57587 and CVE-2026-57588, affecting Tenable Nessus versions prior to 10.12.0. These vulnerabilities, detailed in Tenable security bulletin tns-2026-17, enable an unauthenticated or authenticated attacker to inject malicious SQL queries into the application's database. While the advisory does not specify observed in-the-wild exploitation, the nature of SQL injection can lead to severe consequences, including data exfiltration, unauthorized modification of database content, and potentially remote code execution depending on the database configuration. Nessus, being a critical vulnerability scanning solution, makes its compromise particularly impactful for organizations relying on it for security assessments.

## Attack Chain

1.  An attacker identifies a vulnerable Tenable Nessus instance (version prior to 10.12.0) that is exposed and accessible.
2.  The attacker crafts malicious input containing SQL metacharacters and queries, targeting specific application input fields, HTTP parameters, or API endpoints.
3.  The Nessus application processes the malformed input without proper sanitization or parameterization.
4.  The malicious SQL query is executed by the underlying database, allowing the attacker to bypass authentication, retrieve sensitive data from the database, or manipulate existing data.
5.  Depending on the database and application configuration, the attacker might gain access to Nessus's configuration, scan results, user credentials, or even achieve remote code execution on the server hosting Nessus.
6.  The attacker achieves their objective, which could range from unauthorized access to sensitive vulnerability data to full control over the Nessus instance and potentially internal network reconnaissance.

## Impact

The successful exploitation of these SQL injection vulnerabilities in Tenable Nessus could lead to significant data breaches and operational disruption. An attacker could exfiltrate sensitive scan data, including details about an organization's vulnerabilities, configurations, and network topology, which could then be used for further targeted attacks. Compromise of the Nessus instance itself could also allow an attacker to launch scans against internal networks, effectively weaponizing the organization's own security tools. Given Nessus's role in security, a breach could undermine trust, compromise sensitive assets, and incur substantial regulatory fines and reputational damage.

## Recommendation

*   Prioritize patching Tenable Nessus to version 10.12.0 or higher immediately, as recommended by Tenable's security bulletin tns-2026-17.
*   Review network segmentation and access controls for Tenable Nessus instances to ensure they are not unnecessarily exposed.
*   Monitor logs for unusual activity on systems hosting Tenable Nessus, specifically looking for abnormal database queries or application errors that might indicate attempted exploitation of CVE-2026-57587 and CVE-2026-57588.
