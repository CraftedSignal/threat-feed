---
title: Adobe Security Updates - October 2026
slug: 2026-10-adobe-security-updates
description: Roundup of Adobe security advisories published in October 2026.
date: "2026-10-13T20:38:10Z"
lastmod: "2026-10-13T20:43:30Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Adobe
cves:
  - id: CVE-2026-100133
    product: Adobe Commerce
    cvss: 9.3
  - id: CVE-2026-91013
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105895
updates:
  - at: "2026-10-13T20:38:10Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100133
  - at: "2026-10-13T20:38:24Z"
    level: L2
    summary: added CVE-2026-103849
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103849
  - at: "2026-10-13T20:40:59Z"
    level: L2
    summary: added CVE-2026-91013
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-91013
  - at: "2026-10-13T20:43:30Z"
    level: L2
    summary: added CVE-2026-91013
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-105895
---

This roundup covers 6 Adobe security vulnerabilities. All have a CVSS base score of 9.3. None are reported as actively exploited at the time of release. The issues affect Adobe Commerce, Commerce, Experience Manager.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-100133](#cve-2026-100133) | Adobe Commerce | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100133) (authoritative) |
| [CVE-2026-103849](#cve-2026-103849) | Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103849) (authoritative) |
| [CVE-2026-91013](#cve-2026-91013) | Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-91013) (authoritative) |
| [CVE-2026-92464](#cve-2026-92464) | Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92464) (authoritative) |
| [CVE-2026-92909](#cve-2026-92909) | Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92909) (authoritative) |
| [CVE-2026-103848](#cve-2026-103848) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103848) (authoritative) |


## CVE-2026-100133

Adobe Commerce contains a stored Cross-Site Scripting (XSS) vulnerability allowing attackers to inject malicious JavaScript into form fields. When a victim accesses the affected page, the script executes within the victim's session, enabling potential account takeover or unauthorized actions due to the elevated privileges or scope changes associated with the session.

Affected products:
- Adobe Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100133

## CVE-2026-103849

Adobe Commerce contains an improper neutralization of special elements vulnerability in its template engine, allowing a remote, unauthenticated attacker to achieve arbitrary code execution. The vulnerability permits attackers to gain elevated access or control over user sessions without requiring user interaction.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103849




Related in this roundup: [CVE-2026-91013](#cve-2026-91013), [CVE-2026-92464](#cve-2026-92464), [CVE-2026-92909](#cve-2026-92909).

## CVE-2026-91013

Adobe Commerce contains a stored Cross-Site Scripting (XSS) vulnerability that allows attackers to inject malicious JavaScript into form fields. When a victim accesses the affected page, the script executes in their browser, potentially leading to unauthorized account access or session hijacking.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-91013




Related in this roundup: [CVE-2026-103849](#cve-2026-103849), [CVE-2026-92464](#cve-2026-92464), [CVE-2026-92909](#cve-2026-92909).

## CVE-2026-92464

Adobe Commerce contains an improper input validation vulnerability that allows a high-privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and carries a high impact on the integrity and availability of the affected system.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-92464



Related in this roundup: [CVE-2026-103849](#cve-2026-103849), [CVE-2026-91013](#cve-2026-91013), [CVE-2026-92909](#cve-2026-92909).

## CVE-2026-92909

CVE-2026-92909 describes an incorrect authorization vulnerability in Adobe Commerce that allows a remote, unauthenticated attacker to achieve arbitrary code execution. The flaw does not require user interaction, making it a high-severity remote code execution risk for e-commerce environments.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-92909


Related in this roundup: [CVE-2026-103849](#cve-2026-103849), [CVE-2026-91013](#cve-2026-91013), [CVE-2026-92464](#cve-2026-92464).

## CVE-2026-103848

Adobe Experience Manager contains an OS command injection vulnerability, classified under CWE-78, that allows an unauthenticated or low-privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the scope of the affected application, posing a critical risk to environment integrity.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103848
