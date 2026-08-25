---
title: Adobe Security Updates — August 2026
slug: 2026-08-adobe-security-updates
description: Roundup of Adobe security advisories published in August 2026.
date: "2026-08-03T23:42:20Z"
lastmod: "2026-08-25T18:53:18Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:adobe:coldfusion:2023:-:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update1:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update10:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update11:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update12:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update13:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update14:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update15:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update16:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update17:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update18:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update19:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update2:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update20:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update21:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update22:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update3:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update4:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update5:*:*:*:*:*:*
  - cpe:2.3:a:adobe:coldfusion:2023:update6:*:*:*:*:*:*
  - cpe:2.3:a:adobe:c2pa:*:*:*:*:*:rust:*:*
  - cpe:2.3:a:adobe:c2pa-web:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:adobe:c2patool:*:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:campaign:*:*:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:lightroom:*:*:*:*:classic:*:*:*
tags:
  - roundup
vendors:
  - Adobe
cves:
  - id: CVE-2026-48362
    product: ColdFusion 2025 (<= 2025.0.11)
    cvss: 10
    epss: 0.04312
  - id: CVE-2026-71384
    cvss: 9.6
    epss: 0.00367
  - id: CVE-2026-21279
    cvss: 8.2
    epss: 0.00475
  - id: CVE-2026-25652
    cvss: 7.8
    epss: 0.00138
  - id: CVE-2026-34635
    cvss: 8.4
    epss: 0.00185
  - id: CVE-2026-48439
    cvss: 7.5
    epss: 0.00508
  - id: CVE-2026-48440
    cvss: 8.1
    epss: 0.00554
  - id: CVE-2026-48442
    cvss: 7.1
    epss: 0.00242
  - id: CVE-2026-71362
    cvss: 9.1
    epss: 0.25136
  - id: CVE-2026-71398
    cvss: 10
    epss: 0.00794
  - id: CVE-2026-48408
    cvss: 7.8
    epss: 0.00158
  - id: CVE-2026-48410
    cvss: 7.8
    epss: 0.00158
  - id: CVE-2026-48415
    cvss: 7.6
    epss: 0.00349
  - id: CVE-2026-48416
    cvss: 7.5
    epss: 0.00495
  - id: CVE-2026-76193
    product: Adobe Campaign Classic (<= 7.4.4 build 9400)
    cvss: 10
  - id: CVE-2026-76195
    cvss: 10
  - id: CVE-2026-48419
    cvss: 7.8
  - id: CVE-2026-48421
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48426
updates:
  - at: "2026-08-25T18:52:59Z"
    level: L2
    summary: added CVE-2026-21279 +3
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48418
  - at: "2026-08-25T18:53:02Z"
    level: L2
    summary: added CVE-2026-48416 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48419
  - at: "2026-08-25T18:53:05Z"
    level: L2
    summary: added CVE-2026-48440 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48420
  - at: "2026-08-25T18:53:09Z"
    level: L2
    summary: added CVE-2026-48419, CVE-2026-48421
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48421
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48426
---

This roundup covers 34 Adobe security vulnerabilities. CVSS base scores range from 7.1 to 10.0. None are reported as actively exploited at the time of release. The issues affect Adobe Campaign Classic, Adobe Commerce, Adobe Substance 3D Sampler, ColdFusion, ColdFusion 2025, Content Credentials Rust SDK, Lightroom Classic, Substance 3D Sampler.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-48362](#cve-2026-48362) | ColdFusion 2025 (<= 2025.0.11) | Critical | 10.0 | 4.31% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48362) (authoritative) |
| [CVE-2026-71384](#cve-2026-71384) | n/a | Critical | 9.6 | 0.37% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71384) (authoritative) |
| [CVE-2026-21273](#cve-2026-21273) | ColdFusion 2025 (<= 2025.0.11) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21273) (authoritative) |
| [CVE-2026-21279](#cve-2026-21279) | n/a | High | 8.2 | 0.47% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21279) (authoritative) |
| [CVE-2026-25652](#cve-2026-25652) | n/a | High | 7.8 | 0.14% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25652) (authoritative) |
| [CVE-2026-34635](#cve-2026-34635) | n/a | High | 8.4 | 0.18% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-34635) (authoritative) |
| [CVE-2026-48385](#cve-2026-48385) | ColdFusion (<= 2025.0.11) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48385) (authoritative) |
| [CVE-2026-48386](#cve-2026-48386) | ColdFusion 2025 (<= 2025.0.11) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48386) (authoritative) |
| [CVE-2026-48439](#cve-2026-48439) | Content Credentials Rust SDK (<= c2pa-v0.90.5) | High | 7.5 | 0.51% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48439) (authoritative) |
| [CVE-2026-48440](#cve-2026-48440) | n/a | High | 8.1 | 0.55% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48440) (authoritative) |
| [CVE-2026-48442](#cve-2026-48442) | Content Credentials Rust SDK (<= c2pa-v0.90.5) | High | 7.1 | 0.24% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48442) (authoritative) |
| [CVE-2026-27302](#cve-2026-27302) | Adobe Campaign Classic (<= 7.4.3 build 9399) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-27302) (authoritative) |
| [CVE-2026-71362](#cve-2026-71362) | n/a | Critical | 9.1 | 25.14% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71362) (authoritative) |
| [CVE-2026-71398](#cve-2026-71398) | Adobe Campaign Classic (<= 7.4.3 build 9399) | Critical | 10.0 | 0.79% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71398) (authoritative) |
| [CVE-2026-47940](#cve-2026-47940) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-47940) (authoritative) |
| [CVE-2026-48397](#cve-2026-48397) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48397) (authoritative) |
| [CVE-2026-48405](#cve-2026-48405) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48405) (authoritative) |
| [CVE-2026-48406](#cve-2026-48406) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48406) (authoritative) |
| [CVE-2026-48407](#cve-2026-48407) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48407) (authoritative) |
| [CVE-2026-48408](#cve-2026-48408) | Lightroom Classic (<= 15.4) | High | 7.8 | 0.16% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48408) (authoritative) |
| [CVE-2026-48410](#cve-2026-48410) | n/a | High | 7.8 | 0.16% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48410) (authoritative) |
| [CVE-2026-48413](#cve-2026-48413) | Adobe Commerce (<= 2026-07-31) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48413) (authoritative) |
| [CVE-2026-48415](#cve-2026-48415) | n/a | High | 7.6 | 0.35% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48415) (authoritative) |
| [CVE-2026-48416](#cve-2026-48416) | n/a | High | 7.5 | 0.50% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48416) (authoritative) |
| [CVE-2026-48447](#cve-2026-48447) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48447) (authoritative) |
| [CVE-2026-76193](#cve-2026-76193) | Adobe Campaign Classic (<= 7.4.4 build 9400) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76193) (authoritative) |
| [CVE-2026-76195](#cve-2026-76195) | Adobe Campaign Classic (<= 7.4.4 build 9400) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76195) (authoritative) |
| [CVE-2026-76197](#cve-2026-76197) | Adobe Campaign Classic (<= 7.4.4 build 9400) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76197) (authoritative) |
| [CVE-2026-48417](#cve-2026-48417) | Substance 3D Sampler (<= 6.0.1) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48417) (authoritative) |
| [CVE-2026-48418](#cve-2026-48418) | Adobe Substance 3D Sampler (<= 6.0.1) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48418) (authoritative) |
| [CVE-2026-48419](#cve-2026-48419) | Substance 3D Sampler (<= 6.0.1) | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48419) (authoritative) |
| [CVE-2026-48420](#cve-2026-48420) | Adobe Substance 3D Sampler (<= 6.0.1) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48420) (authoritative) |
| [CVE-2026-48421](#cve-2026-48421) | Substance 3D Sampler (<= 6.0.1) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48421) (authoritative) |
| [CVE-2026-48424](#cve-2026-48424) | Adobe Substance 3D Sampler (<= 6.0.1) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48424) (authoritative) |


## CVE-2026-48362

CVE-2026-48362 is a critical OS command injection vulnerability in Adobe ColdFusion 2023 and 2025 that allows unauthenticated, remote attackers to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the scope of the application, posing a significant risk to affected environments.

Affected products:
- ColdFusion 2025 (<= 2025.0.11)
- ColdFusion 2023 (<= 2023.0.22)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48362
































Related in this roundup: [CVE-2026-21273](#cve-2026-21273), [CVE-2026-48386](#cve-2026-48386).

## CVE-2026-71384

CVE-2026-71384 is an incorrect authorization vulnerability in Adobe ColdFusion 2023 and 2025. The flaw allows an unauthenticated, adjacent attacker to bypass security features, resulting in unauthorized read and write access, and potentially a denial-of-service condition. Although the vulnerable component is restricted to an administrative network zone by default, successful exploitation does not require user interaction.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-71384

## CVE-2026-21273

CVE-2026-21273 describes an improper input validation vulnerability in Adobe ColdFusion 2025 and 2023. A low-privileged attacker can exploit this flaw by enticing a user to open a malicious file, leading to unauthorized read and write access and privilege escalation on the affected system.

Affected products:
- ColdFusion 2025 (<= 2025.0.11)
- ColdFusion 2023 (<= 2023.0.22)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-21273
































Related in this roundup: [CVE-2026-48362](#cve-2026-48362), [CVE-2026-48386](#cve-2026-48386).

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

## CVE-2026-48386

Adobe ColdFusion is vulnerable to a broken or risky cryptographic algorithm (CWE-327), which can be exploited by a remote, unauthenticated attacker to disclose sensitive memory contents. Successful exploitation allows for the unauthorized access to sensitive information without requiring user interaction.

Affected products:
- ColdFusion 2025 (<= 2025.0.11)
- ColdFusion 2023 (<= 2023.0.22)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48386



























Related in this roundup: [CVE-2026-48362](#cve-2026-48362), [CVE-2026-21273](#cve-2026-21273).

## CVE-2026-48439

The CAI Content Credentials SDKs and command-line tool are vulnerable to an uncontrolled resource consumption issue (CWE-400). A remote, unauthenticated attacker can exploit this vulnerability to exhaust system resources, leading to a denial-of-service (DoS) condition. No user interaction is required for successful exploitation.

Affected products:
- Content Credentials Rust SDK (<= c2pa-v0.90.5)
- Content Credentials Command-Line Tool (<= c2patool-v0.27.5)
- Content Credentials JS SDK (<= @contentauth/c2pa@0.14.2)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48439
























Related in this roundup: [CVE-2026-48442](#cve-2026-48442).

## CVE-2026-48440

Adobe ColdFusion versions 2025 (<= 2025.0.11) and 2023 (<= 2023.0.22) are vulnerable to a heap-based buffer overflow. This vulnerability allows an unauthenticated, remote attacker to execute arbitrary code in the context of the current user without requiring user interaction. The exploitation process is non-deterministic, relying on specific environmental conditions.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48440

## CVE-2026-48442

The Adobe Content Credentials SDK and associated tooling are vulnerable to a path traversal vulnerability (CWE-22) which allows an attacker to perform arbitrary file system reads. The vulnerability does not require user interaction and impacts multiple language-specific SDKs and the CLI tool.

Affected products:
- Content Credentials Rust SDK (<= c2pa-v0.90.5)
- Content Credentials Command-Line Tool (<= c2patool-v0.27.5)
- Content Credentials JS SDK (<= @contentauth/c2pa-v0.27.5)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48442
























Related in this roundup: [CVE-2026-48439](#cve-2026-48439).

## CVE-2026-27302

Adobe Campaign Classic is vulnerable to an incorrect authorization flaw (CWE-863) that allows an unauthenticated remote attacker to execute arbitrary code. The vulnerability has a CVSS v3.1 base score of 10.0 and does not require user interaction to exploit.

Affected products:
- Adobe Campaign Classic (<= 7.4.3 build 9399)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-27302





















Related in this roundup: [CVE-2026-71398](#cve-2026-71398), [CVE-2026-76193](#cve-2026-76193), [CVE-2026-76195](#cve-2026-76195), [CVE-2026-76197](#cve-2026-76197).

## CVE-2026-71362

Adobe Commerce and Magento Open Source are vulnerable to an Incorrect Authorization flaw (CWE-863) that allows an unauthenticated, remote attacker to perform privilege escalation. The vulnerability does not require user interaction and can be exploited to gain unauthorized access to sensitive resources.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-71362

## CVE-2026-71398

Adobe Campaign Classic (ACC) is vulnerable to an incorrect authorization flaw (CWE-863) that allows an unauthenticated remote attacker to execute arbitrary code. The vulnerability has a CVSS base score of 10.0 and does not require user interaction for exploitation.

Affected products:
- Adobe Campaign Classic (<= 7.4.3 build 9399)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-71398





















Related in this roundup: [CVE-2026-27302](#cve-2026-27302), [CVE-2026-76193](#cve-2026-76193), [CVE-2026-76195](#cve-2026-76195), [CVE-2026-76197](#cve-2026-76197).

## CVE-2026-47940

Adobe Lightroom Classic is vulnerable to an integer overflow or wraparound condition that can lead to arbitrary code execution. The vulnerability is triggered when a user is enticed to open a maliciously crafted file, allowing an attacker to execute code within the context of the current user session.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-47940

## CVE-2026-48397

Adobe Lightroom Classic is vulnerable to a deserialization of untrusted data issue that allows an attacker to achieve arbitrary code execution. The vulnerability requires user interaction, specifically the opening of a malicious file by the victim, which triggers the flaw within the application context.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48397

## CVE-2026-48405

Adobe Lightroom Classic is vulnerable to an out-of-bounds write (CWE-787) flaw that allows an attacker to achieve arbitrary code execution. Successful exploitation requires a user to open a specially crafted malicious file, which triggers the memory corruption within the application context.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48405

## CVE-2026-48406

Adobe Lightroom Classic is vulnerable to an out-of-bounds write (CWE-787) that allows for arbitrary code execution. A local attacker can exploit this by convincing a user to open a specially crafted malicious file within the application.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48406

## CVE-2026-48407

Adobe Lightroom Classic is susceptible to an out-of-bounds write vulnerability that can be exploited by an attacker to achieve arbitrary code execution. Successful exploitation requires a user to open a specially crafted malicious file, which triggers the memory corruption issue within the application's process context.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48407

## CVE-2026-48408

Adobe Lightroom Classic is vulnerable to an out-of-bounds write (CWE-787) that allows for arbitrary code execution. Successful exploitation requires a user to open a specially crafted malicious file, which triggers the vulnerability in the context of the logged-in user.

Affected products:
- Lightroom Classic (<= 15.4)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48408

## CVE-2026-48410

Adobe Lightroom Classic is vulnerable to an out-of-bounds write, which can be exploited by an attacker to achieve arbitrary code execution. Successful exploitation requires the user to open a malicious file, making it a client-side execution risk.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48410

## CVE-2026-48413

Adobe Commerce and Magento Open Source are vulnerable to a stored Cross-Site Scripting (XSS) attack via malicious input in form fields. A low-privileged attacker can inject scripts that execute in a victim's browser, potentially leading to unauthorized account or session control. This vulnerability involves a change in security scope.

Affected products:
- Adobe Commerce (<= 2026-07-31)
- Adobe Commerce B2B (<= 2026-07-31)
- Magento Open Source (<= 2026-07-31)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48413

## CVE-2026-48415

Adobe Commerce and Magento Open Source are vulnerable to an Incorrect Authorization flaw (CWE-863) that allows a low-privileged, remote attacker to bypass security controls. Successful exploitation grants unauthorized read and write access without requiring user interaction, potentially impacting data integrity and availability.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48415

## CVE-2026-48416

CVE-2026-48416 is an incorrect authorization vulnerability in Adobe Commerce and Magento Open Source that allows remote, unauthenticated attackers to bypass security measures and gain unauthorized read access to sensitive data. The vulnerability does not require user interaction and is exploitable over the network.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48416

## CVE-2026-48447

Adobe Lightroom Classic is vulnerable to an incorrect authorization flaw (CWE-863) that can be exploited to achieve arbitrary code execution. The vulnerability is triggered when a user opens a maliciously crafted file. Successful exploitation requires user interaction and specific conditions beyond the attacker's control.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48447

## CVE-2026-76193

Adobe Campaign Classic (ACC) is vulnerable to a Server-Side Request Forgery (SSRF) flaw, identified as CVE-2026-76193. An unauthenticated, remote attacker can leverage this vulnerability to execute arbitrary code within the context of the service user without any interaction required. The vulnerability carries a critical CVSS v3.1 score of 10.0.

Affected products:
- Adobe Campaign Classic (<= 7.4.4 build 9400)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76193









Related in this roundup: [CVE-2026-27302](#cve-2026-27302), [CVE-2026-71398](#cve-2026-71398), [CVE-2026-76195](#cve-2026-76195), [CVE-2026-76197](#cve-2026-76197).

## CVE-2026-76195

Adobe Campaign Classic (ACC) versions up to and including 7.4.4 build 9400 are vulnerable to an OS command injection flaw. An unauthenticated remote attacker can exploit this vulnerability to execute arbitrary code on the underlying system with the privileges of the application process. This vulnerability features a changed scope and does not require user interaction for successful exploitation.

Affected products:
- Adobe Campaign Classic (<= 7.4.4 build 9400)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76195








Related in this roundup: [CVE-2026-27302](#cve-2026-27302), [CVE-2026-71398](#cve-2026-71398), [CVE-2026-76193](#cve-2026-76193), [CVE-2026-76197](#cve-2026-76197).

## CVE-2026-76197

Adobe Campaign Classic is vulnerable to an OS command injection flaw due to improper neutralization of special elements in user-supplied input. An unauthenticated remote attacker can exploit this vulnerability without user interaction to execute arbitrary code on the affected system with the privileges of the application process. This vulnerability is classified as a critical RCE.

Affected products:
- Adobe Campaign Classic (<= 7.4.4 build 9400)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76197







Related in this roundup: [CVE-2026-27302](#cve-2026-27302), [CVE-2026-71398](#cve-2026-71398), [CVE-2026-76193](#cve-2026-76193), [CVE-2026-76195](#cve-2026-76195).

## CVE-2026-48417

Adobe Substance 3D Sampler is susceptible to a stack-based buffer overflow vulnerability that can be triggered when a user opens a specially crafted malicious file. Successful exploitation allows an attacker to achieve arbitrary code execution within the security context of the logged-in user, requiring user interaction to execute.

Affected products:
- Substance 3D Sampler (<= 6.0.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48417




Related in this roundup: [CVE-2026-48419](#cve-2026-48419), [CVE-2026-48421](#cve-2026-48421).

## CVE-2026-48418

Adobe Substance 3D Sampler is vulnerable to an out-of-bounds write flaw, tracked as CVE-2026-48418. A remote attacker can exploit this by tricking a user into opening a specially crafted malicious file, which may result in arbitrary code execution within the context of the currently logged-in user.

Affected products:
- Adobe Substance 3D Sampler (<= 6.0.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48418



Related in this roundup: [CVE-2026-48420](#cve-2026-48420), [CVE-2026-48424](#cve-2026-48424).

## CVE-2026-48419

Adobe Substance 3D Sampler is vulnerable to an out-of-bounds write flaw, identified as CVE-2026-48419. This vulnerability allows an attacker to execute arbitrary code in the context of the current user if the user is tricked into opening a specially crafted, malicious file. Successful exploitation requires user interaction.

Affected products:
- Substance 3D Sampler (<= 6.0.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48419




Related in this roundup: [CVE-2026-48417](#cve-2026-48417), [CVE-2026-48421](#cve-2026-48421).

## CVE-2026-48420

Adobe Substance 3D Sampler versions 6.0.1 and earlier are vulnerable to an out-of-bounds write vulnerability. A remote attacker could exploit this by tricking a user into opening a maliciously crafted file, leading to arbitrary code execution in the context of the current user.

Affected products:
- Adobe Substance 3D Sampler (<= 6.0.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48420



Related in this roundup: [CVE-2026-48418](#cve-2026-48418), [CVE-2026-48424](#cve-2026-48424).

## CVE-2026-48421

Adobe Substance 3D Sampler versions 6.0.1 and earlier are vulnerable to an out-of-bounds write flaw. An attacker can exploit this by enticing a user to open a specially crafted malicious file, leading to arbitrary code execution within the context of the user running the application.

Affected products:
- Substance 3D Sampler (<= 6.0.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48421


Related in this roundup: [CVE-2026-48417](#cve-2026-48417), [CVE-2026-48419](#cve-2026-48419).

## CVE-2026-48424

Adobe Substance 3D Sampler versions 6.0.1 and earlier are vulnerable to a heap-based buffer overflow triggered by opening a specially crafted malicious file. Successful exploitation requires user interaction and can lead to arbitrary code execution within the context of the current user.

Affected products:
- Adobe Substance 3D Sampler (<= 6.0.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48424

Related in this roundup: [CVE-2026-48418](#cve-2026-48418), [CVE-2026-48420](#cve-2026-48420).
