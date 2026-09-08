---
title: Adobe Security Updates - September 2026
slug: 2026-09-adobe-security-updates
description: Roundup of Adobe security advisories published in September 2026.
date: "2026-09-03T19:22:39Z"
lastmod: "2026-09-08T22:21:15Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:adobe:commerce:*:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:-:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p1:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p10:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p11:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p12:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p13:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p14:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p15:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p16:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p17:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p18:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p2:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p3:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p4:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p5:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p6:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p7:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p8:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p9:*:*:*:*:*:*
tags:
  - roundup
vendors:
  - Adobe
cves:
  - id: CVE-2026-75650
    product: Adobe Commerce
    cvss: 10
    epss: 0.00676
  - id: CVE-2026-76201
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75746
updates:
  - at: "2026-09-03T19:22:39Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83959
  - at: "2026-09-07T21:36:29Z"
    level: L2
    summary: added CVE-2026-75650
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75650
  - at: "2026-09-08T22:21:15Z"
    level: L2
    summary: added CVE-2026-76201
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75746
---

This roundup covers 7 Adobe security vulnerabilities. All have a CVSS base score of 10.0. None are reported as actively exploited at the time of release. The issues affect Adobe Commerce, Campaign Classic, ColdFusion, Commerce, Experience Manager, Substance 3D Sampler.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-83959](#cve-2026-83959) | Substance 3D Sampler |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83959) (authoritative) |
| [CVE-2026-75650](#cve-2026-75650) | Adobe Commerce | Critical | 10.0 | 0.68% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-75650) (authoritative) |
| [CVE-2026-76200](#cve-2026-76200) | Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76200) (authoritative) |
| [CVE-2026-76201](#cve-2026-76201) | Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76201) (authoritative) |
| [CVE-2026-82004](#cve-2026-82004) | Campaign Classic |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-82004) (authoritative) |
| [CVE-2026-19232](#cve-2026-19232) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19232) (authoritative) |
| [CVE-2026-48273](#cve-2026-48273) | ColdFusion |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48273) (authoritative) |


## CVE-2026-83959

Adobe Substance 3D Sampler contains a heap-based buffer overflow vulnerability triggered by opening a malicious file. Successful exploitation allows an attacker to achieve arbitrary code execution in the context of the current user, requiring user interaction to open the crafted file.

Affected products:
- Substance 3D Sampler

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83959

## CVE-2026-75650

Adobe Commerce contains a vulnerability involving improper neutralization of special elements used in a template engine, which allows an unauthenticated attacker to execute arbitrary code. The vulnerability is categorized as remote code execution, does not require user interaction, and impacts the integrity and availability of the system.

Affected products:
- Adobe Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-75650

## CVE-2026-76200

Adobe Commerce contains a stored Cross-Site Scripting (XSS) vulnerability allowing attackers to inject malicious JavaScript into form fields. When a victim accesses the affected page, the script executes within the victim's session, potentially leading to unauthorized account access or session hijacking.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76200




Related in this roundup: [CVE-2026-76201](#cve-2026-76201).

## CVE-2026-76201

Adobe Commerce contains a stored Cross-Site Scripting (XSS) vulnerability allowing an attacker to inject malicious scripts into form fields. When a victim accesses the affected page, the script executes in their browser, potentially leading to session hijacking or unauthorized account access.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76201




Related in this roundup: [CVE-2026-76200](#cve-2026-76200).

## CVE-2026-82004

Adobe Campaign Classic (ACC) is vulnerable to an OS command injection flaw (CVE-2026-82004) that allows unauthenticated attackers to achieve remote code execution in the context of the current user without requiring user interaction. The vulnerability has a CVSS v3.1 base score of 10.0 and involves a changed scope, indicating potential impact beyond the affected service.

Affected products:
- Campaign Classic

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-82004

## CVE-2026-19232

Adobe Experience Manager is vulnerable to an incorrect authorization flaw that allows a low-privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and can result in the attacker gaining elevated access or control over a victim's session, leading to a full compromise of the affected account scope.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-19232

## CVE-2026-48273

Adobe ColdFusion is vulnerable to an improper neutralization of directives in dynamically evaluated code (Eval Injection), which allows a low-privileged attacker to achieve remote code execution without user interaction. The vulnerability results in a change of scope, significantly increasing the impact of successful exploitation.

Affected products:
- ColdFusion

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48273
