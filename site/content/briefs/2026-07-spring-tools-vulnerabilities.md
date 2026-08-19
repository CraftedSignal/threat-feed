---
title: Critical Vulnerabilities in Spring Tools IDE Extensions
slug: 2026-07-spring-tools-vulnerabilities
description: Multiple vulnerabilities in Spring Tools for Eclipse and VSCode/Cursor/Theia allow for remote code execution, unauthorized service access, credential exposure, and cross-site scripting.
date: "2026-07-30T15:30:50Z"
lastmod: "2026-08-19T12:36:05Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0D49B6FD-25E2-5EF6-85A7-1E2D3014BD5A&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - ide
  - rce
  - spring-framework
vendors:
  - VMware
products:
  - Spring Tools for Eclipse
  - Spring Tools for VSCode
  - Spring Tools for Cursor
  - Spring Tools for Theia
cves:
  - id: CVE-2026-47858
    cvss: 8
    epss: 0.00197
  - id: CVE-2026-47873
    cvss: 8
    epss: 0.00184
  - id: CVE-2026-47882
    cvss: 8.3
    epss: 0.00174
  - id: CVE-2026-59326
    cvss: 3.3
    epss: 0.00095
  - id: CVE-2026-59327
    cvss: 4.4
    epss: 0.00085
references:
  - https://cyber.gc.ca/en/alerts-advisories/spring-security-advisory-av26-759
  - https://spring.io/security/cve-2026-47858/
  - https://spring.io/security/cve-2026-47873/
  - https://spring.io/security/cve-2026-47882/
  - https://spring.io/security/cve-2026-59326/
  - https://spring.io/security/cve-2026-59327/
  - https://spring.io/security/cve-2026-59328/
  - https://sploitus.com/exploit?id=0D49B6FD-25E2-5EF6-85A7-1E2D3014BD5A&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-08-19T12:36:05Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0D49B6FD-25E2-5EF6-85A7-1E2D3014BD5A&utm_source=rss&utm_medium=rss
---

VMware has released a security advisory (AV26-759) detailing six vulnerabilities affecting Spring Tools for Eclipse (versions <= 5.2.0) and Spring Tools for VSCode, Cursor, and Theia (versions <= 2.2.0). The vulnerabilities range from critical Remote Code Execution (RCE) flaws to information disclosure and Cross-Site Scripting (XSS). 

The most severe issue, CVE-2026-47858, allows for RCE via live information startup mode. Additionally, CVE-2026-47873 exposes JDWP and JMX ports on all network interfaces, providing a pathway for unauthenticated remote access to debugging and management interfaces. Other identified issues include the use of a non-cryptographic PRNG for DevTools remote secrets (CVE-2026-47882), plaintext logging of HTTP proxy credentials (CVE-2026-59326), insecure local storage of secrets in Eclipse launch configurations (CVE-2026-59327), and XSS in dependency tooltips (CVE-2026-59328). Organizations using these developer tools should prioritize updating to the latest versions to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise, unauthorized access to developer environments, theft of sensitive credentials (proxy and remote secrets), and potential for lateral movement within a development network. These flaws directly impact the integrity and confidentiality of developer workstations and the software build pipelines they support.

## Recommendation

- Update Spring Tools for Eclipse to the latest version immediately to remediate CVE-2026-47858, CVE-2026-47873, CVE-2026-47882, CVE-2026-59326, CVE-2026-59327, and CVE-2026-59328.
- Update Spring Tools for VSCode, Cursor, and Theia to the latest version to address these vulnerabilities.
- Audit developer workstations for insecure IDE configurations, particularly regarding exposed JDWP/JMX ports.
- Rotate any credentials that may have been logged in plaintext or stored insecurely due to CVE-2026-59326 and CVE-2026-59327.
