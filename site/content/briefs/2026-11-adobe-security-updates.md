---
brief_id: brief-2026-11-adobe-security-updates
event_id: brief-2026-11-adobe-security-updates
revision: 1
activity_at: "2026-11-11T02:08:25Z"
title: Adobe Security Updates - November 2026
slug: 2026-11-adobe-security-updates
description: Roundup of Adobe security advisories published in November 2026.
date: "2026-11-11T02:08:25Z"
lastmod: "2026-11-11T05:59:37Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - roundup
vendors:
  - Adobe
cves:
  - id: CVE-2026-113579
    product: Experience Manager
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-113580
    product: Experience Manager
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-114371
    product: Experience Manager
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-119017
    product: Experience Manager
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-121349
    product: Connect
    cvss: 9.6
    kev_status: "false"
  - id: CVE-2026-121351
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-121352
    product: Connect
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-121353
    product: Connect
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-121354
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-121896
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-121904
    cvss: 9.6
    kev_status: "false"
  - id: CVE-2026-121908
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-121356
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-121889
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-121906
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-121355
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-110091
    kev_status: unknown
  - id: CVE-2026-113557
    kev_status: unknown
  - id: CVE-2026-121350
    kev_status: unknown
  - id: CVE-2026-121887
    kev_status: unknown
  - id: CVE-2026-121890
    kev_status: unknown
  - id: CVE-2026-121892
    kev_status: unknown
  - id: CVE-2026-121894
    kev_status: unknown
  - id: CVE-2026-121898
    kev_status: unknown
  - id: CVE-2026-121902
    kev_status: unknown
  - id: CVE-2026-122102
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122102
updates:
  - at: "2026-11-11T02:08:40Z"
    level: L2
    summary: added CVE-2026-121353, CVE-2026-121354
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121353
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121355
  - at: "2026-11-11T05:59:33Z"
    level: L2
    summary: added CVE-2026-121896 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110091
  - at: "2026-11-11T05:59:35Z"
    level: L2
    summary: added CVE-2026-121356 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121350
  - at: "2026-11-11T05:59:37Z"
    level: L2
    summary: added CVE-2026-121355
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121890
---

This roundup covers 26 Adobe security vulnerabilities. CVSS base scores range from 9.1 to 10.0. None are reported as actively exploited at the time of release. The issues affect Adobe Connect, Audition, Connect, Experience Manager, Premiere Pro.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-113579](#cve-2026-113579) | Experience Manager | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-113579) (authoritative) |
| [CVE-2026-113580](#cve-2026-113580) | Experience Manager | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-113580) (authoritative) |
| [CVE-2026-114371](#cve-2026-114371) | Experience Manager | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-114371) (authoritative) |
| [CVE-2026-119017](#cve-2026-119017) | Experience Manager | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-119017) (authoritative) |
| [CVE-2026-121349](#cve-2026-121349) | Connect | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121349) (authoritative) |
| [CVE-2026-121351](#cve-2026-121351) | Connect | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121351) (authoritative) |
| [CVE-2026-121352](#cve-2026-121352) | Connect | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121352) (authoritative) |
| [CVE-2026-121353](#cve-2026-121353) | Connect | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121353) (authoritative) |
| [CVE-2026-121354](#cve-2026-121354) | Connect | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121354) (authoritative) |
| [CVE-2026-121355](#cve-2026-121355) | Connect | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121355) (authoritative) |
| [CVE-2026-121356](#cve-2026-121356) | Connect | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121356) (authoritative) |
| [CVE-2026-121887](#cve-2026-121887) | Connect |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121887) (authoritative) |
| [CVE-2026-121889](#cve-2026-121889) | Connect | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121889) (authoritative) |
| [CVE-2026-121892](#cve-2026-121892) | Connect |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121892) (authoritative) |
| [CVE-2026-121894](#cve-2026-121894) | Connect |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121894) (authoritative) |
| [CVE-2026-121896](#cve-2026-121896) | Connect | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121896) (authoritative) |
| [CVE-2026-121898](#cve-2026-121898) | Connect |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121898) (authoritative) |
| [CVE-2026-121902](#cve-2026-121902) | Connect |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121902) (authoritative) |
| [CVE-2026-121904](#cve-2026-121904) | Adobe Connect | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121904) (authoritative) |
| [CVE-2026-121906](#cve-2026-121906) | Connect | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121906) (authoritative) |
| [CVE-2026-121908](#cve-2026-121908) | Connect | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121908) (authoritative) |
| [CVE-2026-110091](#cve-2026-110091) | Premiere Pro |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-110091) (authoritative) |
| [CVE-2026-113557](#cve-2026-113557) | Audition |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-113557) (authoritative) |
| [CVE-2026-121350](#cve-2026-121350) | Connect |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121350) (authoritative) |
| [CVE-2026-121890](#cve-2026-121890) | Connect |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-121890) (authoritative) |
| [CVE-2026-122102](#cve-2026-122102) | Adobe Connect |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-122102) (authoritative) |


## CVE-2026-113579

Adobe Experience Manager is vulnerable to a code injection vulnerability that allows low-privileged attackers to execute arbitrary code without user interaction. The vulnerability has a CVSS v3.1 base score of 9.9, indicating high severity due to the potential for remote code execution and the lack of required interaction.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-113579

























Related in this roundup: [CVE-2026-113580](#cve-2026-113580), [CVE-2026-114371](#cve-2026-114371), [CVE-2026-119017](#cve-2026-119017).

## CVE-2026-113580

Adobe Experience Manager is vulnerable to an improper control of generation of code, which may allow a low-privileged, unauthenticated attacker to achieve arbitrary code execution. The vulnerability does not require user interaction, and successful exploitation results in a scope change, allowing the attacker to execute code within the context of the current user session.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-113580

























Related in this roundup: [CVE-2026-113579](#cve-2026-113579), [CVE-2026-114371](#cve-2026-114371), [CVE-2026-119017](#cve-2026-119017).

## CVE-2026-114371

Adobe Experience Manager is vulnerable to an incorrect authorization issue that allows a low-privileged, unauthenticated attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the system scope, making it a critical security risk for deployments of the platform.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-114371
























Related in this roundup: [CVE-2026-113579](#cve-2026-113579), [CVE-2026-113580](#cve-2026-113580), [CVE-2026-119017](#cve-2026-119017).

## CVE-2026-119017

Adobe Experience Manager is vulnerable to an incorrect authorization issue that allows a low-privileged attacker to achieve arbitrary code execution without user interaction. The vulnerability results in a changed scope and carries a CVSS base score of 9.9.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-119017























Related in this roundup: [CVE-2026-113579](#cve-2026-113579), [CVE-2026-113580](#cve-2026-113580), [CVE-2026-114371](#cve-2026-114371).

## CVE-2026-121349

Adobe Connect is vulnerable to a path traversal vulnerability (CWE-22) which allows an unauthenticated or low-privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and can lead to session takeover or privilege escalation.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121349





















Related in this roundup: [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121351

Adobe Connect is vulnerable to a path traversal vulnerability (CWE-22) allowing unauthorized arbitrary file system read access. The vulnerability does not require user interaction and impacts the integrity and confidentiality of the host system, evidenced by a CVSS v3.1 base score of 10.0.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121351





















Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121352

Adobe Connect is vulnerable to an incorrect authorization issue that allows for privilege escalation. The vulnerability does not require user interaction and can be exploited to gain unauthorized access to sensitive resources.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121352




















Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121353

Adobe Connect is vulnerable to CRLF injection, which could be leveraged to achieve remote code execution in the context of the current user. The vulnerability does not require user interaction, has a scope of change, and carries a maximum CVSS score of 10.0.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121353



















Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121354

Adobe Connect is vulnerable to a path traversal vulnerability that allows unauthenticated, remote attackers to read arbitrary files from the file system. The vulnerability exists due to improper limitation of a pathname to a restricted directory, allowing attackers to escape the intended access scope. This vulnerability is rated as critical with a CVSS v3.1 score of 9.9 and does not require user interaction to exploit.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121354


















Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121355

Adobe Connect is vulnerable to an incorrect authorization flaw allowing unauthenticated privilege escalation. The vulnerability does not require user interaction and can be exploited to gain unauthorized access to sensitive data or functionality.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121355

















Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121356

Adobe Connect is vulnerable to Server-Side Request Forgery (SSRF) which can lead to privilege escalation. The vulnerability is remotely exploitable without user interaction and involves a change in scope, as indicated by a CVSS v3.1 base score of 10.0.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121356
















Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121887

Adobe Connect is vulnerable to an XML External Entity (XXE) injection flaw that allows a low-privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the application with a changed scope, carrying a CVSS base score of 9.9.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121887















Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121889

Adobe Connect contains a Server-Side Request Forgery (SSRF) vulnerability that allows for privilege escalation. The vulnerability does not require user interaction for exploitation and results in a change of security scope, warranting a CVSS base score of 10.0.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121889














Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121892

Adobe Connect is vulnerable to an Improper Control of Generation of Code (Code Injection) flaw that allows a low-privileged, unauthenticated attacker to execute arbitrary code without user interaction. The vulnerability results in a change of scope and carries a critical severity rating.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121892













Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121894

Adobe Connect is vulnerable to SQL injection, which allows a low-privileged attacker to execute arbitrary SQL commands. This flaw can be leveraged for elevated access or control over user sessions, and because it does not require user interaction and involves a scope change, it carries a high risk of arbitrary code execution.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121894












Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121896

Adobe Connect is vulnerable to a SQL injection vulnerability that allows low-privileged attackers to execute arbitrary code in the context of the current user without requiring user interaction. The vulnerability, classified as CWE-89, results in a scope change and carries a high CVSS severity score.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121896











Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121898

Adobe Connect is vulnerable to an SQL injection flaw that allows low-privileged attackers to achieve arbitrary code execution without user interaction. The vulnerability is categorized under improper neutralization of special elements used in an SQL command and carries a high CVSS base score, indicating a significant risk to the integrity and availability of the application environment.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121898










Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121902

Adobe Connect contains a SQL injection vulnerability that can be leveraged by an unauthenticated attacker to execute arbitrary SQL commands, which may lead to arbitrary code execution on the underlying server without requiring user interaction.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121902









Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121904

Adobe Connect is vulnerable to a stored Cross-Site Scripting (XSS) vulnerability that allows a low-privileged attacker to inject malicious JavaScript into form fields. This script executes within the context of a victim's browser session, potentially leading to unauthorized account access or session hijacking.

Affected products:
- Adobe Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121904

Related in this roundup: [CVE-2026-122102](#cve-2026-122102).

## CVE-2026-121906

Adobe Connect is vulnerable to a path traversal vulnerability (CWE-22) that allows unauthenticated, remote attackers to perform arbitrary file reads on the underlying filesystem, potentially exposing sensitive configuration or system files.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121906







Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121908

Adobe Connect is vulnerable to a SQL injection vulnerability that allows low-privileged attackers to execute arbitrary code without user interaction. The vulnerability, classified as improper neutralization of special elements in an SQL command, leads to a change in scope and impacts the current user's context.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121908






Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121350](#cve-2026-121350), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-110091

Adobe Premiere Pro contains a missing authentication for critical function vulnerability, allowing an unauthenticated attacker to bypass security features and obtain unauthorized write access to the application's environment. The vulnerability is exploitable without user interaction and involves a change in scope.

Affected products:
- Premiere Pro

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-110091

## CVE-2026-113557

Adobe Audition is vulnerable to an improper input validation flaw that allows for arbitrary code execution. The vulnerability is triggered when a user is convinced to open a specially crafted malicious file, leading to potential system compromise under the context of the current user.

Affected products:
- Audition

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-113557

## CVE-2026-121350

Adobe Connect contains an SQL injection vulnerability that allows a low-privileged attacker to disclose sensitive information from memory without requiring user interaction. The vulnerability has a CVSS v3.1 base score of 7.7 and involves a scope change, indicating potential impact beyond the vulnerable application context.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121350



Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121890](#cve-2026-121890).

## CVE-2026-121890

Adobe Connect is vulnerable to an XML External Entity (XXE) injection flaw, allowing an authenticated, low-privileged attacker to perform arbitrary file system reads. The vulnerability allows for unauthorized access to files and directories outside of the application's intended scope without requiring user interaction.

Affected products:
- Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-121890


Related in this roundup: [CVE-2026-121349](#cve-2026-121349), [CVE-2026-121351](#cve-2026-121351), [CVE-2026-121352](#cve-2026-121352), [CVE-2026-121353](#cve-2026-121353), [CVE-2026-121354](#cve-2026-121354), [CVE-2026-121355](#cve-2026-121355), [CVE-2026-121356](#cve-2026-121356), [CVE-2026-121887](#cve-2026-121887), [CVE-2026-121889](#cve-2026-121889), [CVE-2026-121892](#cve-2026-121892), [CVE-2026-121894](#cve-2026-121894), [CVE-2026-121896](#cve-2026-121896), [CVE-2026-121898](#cve-2026-121898), [CVE-2026-121902](#cve-2026-121902), [CVE-2026-121906](#cve-2026-121906), [CVE-2026-121908](#cve-2026-121908), [CVE-2026-121350](#cve-2026-121350).

## CVE-2026-122102

Adobe Connect is vulnerable to a stored Cross-Site Scripting (XSS) vulnerability allowing low-privileged attackers to inject malicious JavaScript into form fields. When a victim accesses the affected page, the script executes, potentially leading to unauthorized session access or account compromise.

Affected products:
- Adobe Connect

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-122102

Related in this roundup: [CVE-2026-121904](#cve-2026-121904).
