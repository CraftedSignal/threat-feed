---
title: Adobe Security Updates - October 2026
slug: 2026-10-adobe-security-updates
description: Roundup of Adobe security advisories published in October 2026.
date: "2026-10-13T20:38:10Z"
lastmod: "2026-10-13T20:40:59Z"
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
  - id: CVE-2026-103849
    product: Commerce
  - id: CVE-2026-91013
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91013
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
---

This roundup covers 2 Adobe security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Adobe Commerce, Commerce.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-100133](#cve-2026-100133) | Adobe Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100133) (authoritative) |
| [CVE-2026-103849](#cve-2026-103849) | Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103849) (authoritative) |


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
