---
title: Adobe Security Updates — August 2026
slug: 2026-08-adobe-security-updates
description: Roundup of Adobe security advisories published in August 2026.
date: "2026-08-03T23:42:20Z"
lastmod: "2026-08-11T18:38:14Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:adobe:campaign:*:*:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:campaign:7.4.3:9394:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:campaign:7.4.3:9396:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:campaign:7.4.3:9397:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:campaign:7.4.3:9398:*:*:classic:*:*:*
tags:
  - roundup
vendors:
  - Adobe
cves:
  - id: CVE-2026-48362
    product: ColdFusion 2025 (<= 2025.0.11)
    cvss: 10
  - id: CVE-2026-71384
    cvss: 9.6
  - id: CVE-2026-21273
    product: ColdFusion 2025 (<= 2025.0.11)
    cvss: 8.7
  - id: CVE-2026-21279
    cvss: 8.2
  - id: CVE-2026-25652
    cvss: 7.8
  - id: CVE-2026-34635
    cvss: 8.4
  - id: CVE-2026-48385
    cvss: 7.7
  - id: CVE-2026-48317
    cvss: 9.6
    epss: 0.00486
  - id: CVE-2026-48331
    cvss: 10
    epss: 0.00473
  - id: CVE-2026-48386
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48386
updates:
  - at: "2026-08-11T18:36:12Z"
    level: L2
    summary: added CVE-2026-21273, CVE-2026-21279, CVE-2026-71384
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71384
      - https://nvd.nist.gov/vuln/detail/CVE-2026-21273
      - https://nvd.nist.gov/vuln/detail/CVE-2026-25652
  - at: "2026-08-11T18:38:11Z"
    level: L2
    summary: added CVE-2026-25652
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48385
  - at: "2026-08-11T18:38:14Z"
    level: L2
    summary: added CVE-2026-34635 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48386
---

This roundup covers 7 Adobe security vulnerabilities. CVSS base scores range from 7.8 to 10.0. None are reported as actively exploited at the time of release. The issues affect ColdFusion, ColdFusion 2025.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-48362](#cve-2026-48362) | ColdFusion 2025 (<= 2025.0.11) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48362) (authoritative) |
| [CVE-2026-71384](#cve-2026-71384) | n/a | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71384) (authoritative) |
| [CVE-2026-21273](#cve-2026-21273) | ColdFusion 2025 (<= 2025.0.11) | High | 8.7 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21273) (authoritative) |
| [CVE-2026-21279](#cve-2026-21279) | n/a | High | 8.2 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21279) (authoritative) |
| [CVE-2026-25652](#cve-2026-25652) | n/a | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25652) (authoritative) |
| [CVE-2026-34635](#cve-2026-34635) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-34635) (authoritative) |
| [CVE-2026-48385](#cve-2026-48385) | ColdFusion (<= 2025.0.11) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48385) (authoritative) |


## CVE-2026-48362

CVE-2026-48362 is a critical OS command injection vulnerability in Adobe ColdFusion 2023 and 2025 that allows unauthenticated, remote attackers to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the scope of the application, posing a significant risk to affected environments.

Affected products:
- ColdFusion 2025 (<= 2025.0.11)
- ColdFusion 2023 (<= 2023.0.22)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48362





Related in this roundup: [CVE-2026-21273](#cve-2026-21273).

## CVE-2026-71384

CVE-2026-71384 is an incorrect authorization vulnerability in Adobe ColdFusion 2023 and 2025. The flaw allows an unauthenticated, adjacent attacker to bypass security features, resulting in unauthorized read and write access, and potentially a denial-of-service condition. Although the vulnerable component is restricted to an administrative network zone by default, successful exploitation does not require user interaction.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-71384

## CVE-2026-21273

CVE-2026-21273 describes an improper input validation vulnerability in Adobe ColdFusion 2025 and 2023. A low-privileged attacker can exploit this flaw by enticing a user to open a malicious file, leading to unauthorized read and write access and privilege escalation on the affected system.

Affected products:
- ColdFusion 2025 (<= 2025.0.11)
- ColdFusion 2023 (<= 2023.0.22)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-21273





Related in this roundup: [CVE-2026-48362](#cve-2026-48362).

## CVE-2026-21279

Adobe ColdFusion versions 2025 (<= 2025.0.11) and 2023 (<= 2023.0.22) are vulnerable to an improper input validation flaw that allows for a security feature bypass. An unauthenticated remote attacker can exploit this vulnerability to gain unauthorized read and limited write access to the affected system without requiring user interaction.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-21279

## CVE-2026-25652

CVE-2026-25652 is an Incorrect Authorization vulnerability in Adobe ColdFusion 2025 and 2023 versions. A low-privileged attacker can exploit this flaw to escalate privileges and gain unauthorized read and write access to the system. Exploitation is local and does not require user interaction.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-25652

## CVE-2026-34635

Adobe ColdFusion versions 2025 (<= 2025.0.11) and 2023 (<= 2023.0.22) contain a Use of Hard-coded Cryptographic Key vulnerability. A low-privileged attacker can exploit this issue to bypass security features and obtain unauthorized read and write access without user interaction. The vulnerability results in a scope change, potentially allowing for cross-security-domain impact.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-34635

## CVE-2026-48385

Adobe ColdFusion is vulnerable to an OS command injection flaw (CVE-2026-48385) that allows low-privileged, remote attackers to bypass security features and gain unauthorized write access to the system. The vulnerability does not require user interaction and impacts the system scope.

Affected products:
- ColdFusion (<= 2025.0.11)
- ColdFusion (<= 2023.0.22)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48385
