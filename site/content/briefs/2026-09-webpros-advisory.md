---
title: Security Advisories for cPanel WHM and ConfigServer Security & Firewall
slug: 2026-09-webpros-advisory
description: WebPros has released patches for multiple critical vulnerabilities in cPanel & WebHost Manager and ConfigServer Security & Firewall, including an SQL injection flaw in the EmailTrack component.
date: "2026-09-10T18:56:38Z"
lastmod: "2026-09-17T08:06:02Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=574F8F2F-A5CA-5A4A-B086-124A41A509EB&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - web-application
  - cpanel
  - sql-injection
vendors:
  - WebPros
products:
  - cPanel & WebHost Manager (< 11.110.0.143, < 11.134.0.55, < 11.136.0.39, < 11.138.0.4, < 11.138.1.9)
  - ConfigServer Security & Firewall (14.00-16.29, 2.15-16.29)
cves:
  - id: CVE-2026-67401
    cvss: 9.9
    epss: 0.0104
  - id: CVE-2026-65638
    epss: 0.03199
  - id: CVE-2026-65639
    epss: 0.01611
references:
  - https://cyber.gc.ca/en/alerts-advisories/webpros-security-advisory-av26-908
  - https://support.cpanel.net/hc/en-us/articles/43187903921559-Security-CVE-2026-67401-SQL-Injection-Vulnerability-in-cPanel-s-EmailTrack-Functionality-September-8-2026
  - https://support.cpanel.net/hc/en-us/articles/43387915588375-Security-CVE-2026-65638-CSF-Security-Release
  - https://support.cpanel.net/hc/en-us/articles/43387923160343-Security-CVE-2026-65639-CSF-Security-Release
  - https://sploitus.com/exploit?id=574F8F2F-A5CA-5A4A-B086-124A41A509EB&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade cPanel & WHM to 11.110.0.143, 11.134.0.55, 11.136.0.39, 11.138.0.4, or 11.138.1.9 and CSF to > 16.29
      owner: IT Operations
      addresses: CVE-2026-67401, CVE-2026-65638, CVE-2026-65639
      evidence: WebPros security advisory (AV26-908) provided versions.
updates:
  - at: "2026-09-17T08:06:02Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=574F8F2F-A5CA-5A4A-B086-124A41A509EB&utm_source=rss&utm_medium=rss
---

WebPros has issued a security advisory (AV26-908) regarding multiple vulnerabilities impacting cPanel & WebHost Manager (WHM) and ConfigServer Security & Firewall (CSF). The most notable vulnerability, tracked as CVE-2026-67401, is a SQL injection flaw identified within the cPanel EmailTrack functionality. Additionally, two vulnerabilities, CVE-2026-65638 and CVE-2026-65639, have been identified in CSF, necessitating immediate patching. Organizations utilizing these products are at risk of unauthorized database access or potential security feature bypass if left unpatched. Defenders should prioritize updating cPanel & WHM to version 11.110.0.143, 11.134.0.55, 11.136.0.39, 11.138.0.4, or 11.138.1.9 (WP2) respectively, and updating CSF to the latest available version beyond 16.29.

## Impact

Successful exploitation of CVE-2026-67401 could allow unauthenticated or authenticated attackers to perform SQL injection attacks against the cPanel EmailTrack module, potentially leading to unauthorized data exfiltration or manipulation of the backend database. CSF vulnerabilities CVE-2026-65638 and CVE-2026-65639 impact the security infrastructure of the hosting environment, potentially allowing for the circumvention of firewall rules. These flaws impact a broad range of web hosting environments globally.

## Recommendation

- Patch cPanel & WebHost Manager immediately to the specified versions (11.110.0.143, 11.134.0.55, 11.136.0.39, 11.138.0.4, or 11.138.1.9) as documented in the WebPros advisory.
- Update ConfigServer Security & Firewall (CSF) to versions beyond 16.29 to remediate CVE-2026-65638 and CVE-2026-65639.
- Audit logs for web requests targeting `/scripts/emailtrack` or similar endpoints associated with the vulnerable EmailTrack functionality.
- Monitor for anomalous database queries or unusual error patterns in web server logs that may indicate SQL injection attempts.
