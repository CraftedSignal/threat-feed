---
title: Multiple Vulnerabilities in PHP Language
slug: 2026-07-php-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-17543, CVE-2026-17544, CVE-2026-7260, and CVE-2026-9672, have been identified in PHP, potentially enabling SQL injection and denial-of-service attacks.
date: "2026-07-31T15:28:32Z"
lastmod: "2026-08-04T13:42:48Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=9CEF7320-4DEE-5D43-A7B1-379396FC9CE7&utm_source=rss&utm_medium=rss
vendors:
  - PHP
  - PHP Group
products:
  - PHP 8.2
  - PHP 8.3
  - PHP 8.4
  - PHP 8.5
  - PHP (8.2.x < 8.2.33, 8.3.x < 8.3.30, 8.4.x < 8.4.24)
cves:
  - id: CVE-2026-17543
    epss: 0.00386
  - id: CVE-2026-17544
    epss: 0.00428
  - id: CVE-2026-7260
    epss: 0.00168
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0952/
  - https://www.php.net/ChangeLog-8.php#8.2.33
  - https://www.php.net/ChangeLog-8.php#8.3.33
  - https://www.php.net/ChangeLog-8.php#8.4.24
  - https://www.php.net/ChangeLog-8.php#8.5.9
  - https://www.cve.org/CVERecord?id=CVE-2026-17543
  - https://www.cve.org/CVERecord?id=CVE-2026-17544
  - https://www.cve.org/CVERecord?id=CVE-2026-7260
  - https://www.cve.org/CVERecord?id=CVE-2026-9672
  - https://sploitus.com/exploit?id=9CEF7320-4DEE-5D43-A7B1-379396FC9CE7&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=9CEF7320-4DEE-5D43-A7B1-379396FC9CE7
ioc_counts:
  url: 1
updates:
  - at: "2026-08-04T13:42:48Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=9CEF7320-4DEE-5D43-A7B1-379396FC9CE7&utm_source=rss&utm_medium=rss
---

The PHP development team has released security updates for multiple active branches of the PHP scripting language to address several critical vulnerabilities. The flaws affect PHP versions prior to 8.2.33, 8.3.33, 8.4.24, and 8.5.9. These vulnerabilities, tracked under CVE-2026-17543, CVE-2026-17544, CVE-2026-7260, and CVE-2026-9672, include issues that could allow a remote attacker to perform SQL injection attacks, induce denial-of-service (DoS) conditions, or exploit other unspecified security weaknesses within web applications relying on the vulnerable PHP versions. Organizations running web servers utilizing these PHP versions are advised to upgrade to the latest versions (8.2.33, 8.3.33, 8.4.24, or 8.5.9) immediately to mitigate potential exploitation.

## Impact

Successful exploitation of these vulnerabilities can lead to unauthorized database access and manipulation via SQL injection, or the degradation of service availability through DoS attacks. These flaws represent a significant risk to any environment hosting web applications or services written in PHP, potentially resulting in data exfiltration or service outages.

## Recommendation

- Upgrade all PHP installations to versions 8.2.33, 8.3.33, 8.4.24, or 8.5.9 to remediate CVE-2026-17543, CVE-2026-17544, CVE-2026-7260, and CVE-2026-9672.
- Review web application logs for suspicious patterns associated with SQL injection attempts (e.g., unexpected union statements, tautology strings, or database command syntax).
- Prioritize patching for internet-facing applications utilizing affected PHP branches.
