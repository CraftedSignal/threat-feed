---
title: Adobe Security Updates - October 2026
slug: 2026-10-adobe-security-updates
description: Roundup of Adobe security advisories published in October 2026.
date: "2026-10-13T20:38:10Z"
lastmod: "2026-10-14T04:41:30Z"
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
  - id: CVE-2026-103849
    cvss: 10
  - id: CVE-2026-91013
    cvss: 9.3
  - id: CVE-2026-92464
    cvss: 9.1
  - id: CVE-2026-92909
    cvss: 9.8
  - id: CVE-2026-106629
    cvss: 9.3
  - id: CVE-2026-106630
    cvss: 9.3
  - id: CVE-2026-48382
    cvss: 10
  - id: CVE-2026-48383
    cvss: 10
  - id: CVE-2026-75732
    cvss: 9.9
  - id: CVE-2026-90531
    cvss: 9.6
  - id: CVE-2026-103967
    cvss: 7.8
  - id: CVE-2026-104341
    cvss: 7.8
  - id: CVE-2026-106625
    cvss: 7.8
  - id: CVE-2026-92908
    product: Adobe Commerce
    cvss: 8.3
  - id: CVE-2026-92910
    cvss: 7.2
  - id: CVE-2026-103834
    cvss: 7.8
  - id: CVE-2026-103835
    cvss: 7.8
  - id: CVE-2026-103836
    cvss: 7.8
  - id: CVE-2026-103840
    cvss: 7.8
  - id: CVE-2026-103851
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110084
updates:
  - at: "2026-10-14T04:39:49Z"
    level: L2
    summary: added CVE-2026-103834
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103837
  - at: "2026-10-14T04:40:01Z"
    level: L2
    summary: added CVE-2026-106625
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103840
  - at: "2026-10-14T04:41:24Z"
    level: L2
    summary: added CVE-2026-103835 +4
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-106634
  - at: "2026-10-14T04:41:27Z"
    level: L2
    summary: added CVE-2026-103851 +3
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110083
  - at: "2026-10-14T04:41:30Z"
    level: L2
    summary: added CVE-2026-48382
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110084
---

This roundup covers 41 Adobe security vulnerabilities. CVSS base scores range from 7.2 to 10.0. None are reported as actively exploited at the time of release. The issues affect Adobe Commerce, Commerce, Experience Manager, Framemaker, Substance 3D Stager, Substance3D - Stager.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-100133](#cve-2026-100133) | Adobe Commerce | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100133) (authoritative) |
| [CVE-2026-103849](#cve-2026-103849) | Commerce | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103849) (authoritative) |
| [CVE-2026-91013](#cve-2026-91013) | Commerce | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-91013) (authoritative) |
| [CVE-2026-92464](#cve-2026-92464) | Commerce | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92464) (authoritative) |
| [CVE-2026-92909](#cve-2026-92909) | Commerce | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92909) (authoritative) |
| [CVE-2026-103848](#cve-2026-103848) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103848) (authoritative) |
| [CVE-2026-105895](#cve-2026-105895) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105895) (authoritative) |
| [CVE-2026-106626](#cve-2026-106626) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-106626) (authoritative) |
| [CVE-2026-106629](#cve-2026-106629) | Experience Manager | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-106629) (authoritative) |
| [CVE-2026-106630](#cve-2026-106630) | Experience Manager | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-106630) (authoritative) |
| [CVE-2026-48382](#cve-2026-48382) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48382) (authoritative) |
| [CVE-2026-48383](#cve-2026-48383) | Experience Manager | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48383) (authoritative) |
| [CVE-2026-75732](#cve-2026-75732) | Experience Manager | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-75732) (authoritative) |
| [CVE-2026-83662](#cve-2026-83662) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83662) (authoritative) |
| [CVE-2026-90531](#cve-2026-90531) | Experience Manager | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90531) (authoritative) |
| [CVE-2026-90532](#cve-2026-90532) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90532) (authoritative) |
| [CVE-2026-103966](#cve-2026-103966) | Framemaker |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103966) (authoritative) |
| [CVE-2026-103967](#cve-2026-103967) | Framemaker | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103967) (authoritative) |
| [CVE-2026-104340](#cve-2026-104340) | Framemaker |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-104340) (authoritative) |
| [CVE-2026-104341](#cve-2026-104341) | Framemaker | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-104341) (authoritative) |
| [CVE-2026-104342](#cve-2026-104342) | Framemaker |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-104342) (authoritative) |
| [CVE-2026-104344](#cve-2026-104344) | Framemaker |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-104344) (authoritative) |
| [CVE-2026-106625](#cve-2026-106625) | Framemaker | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-106625) (authoritative) |
| [CVE-2026-92908](#cve-2026-92908) | Adobe Commerce | High | 8.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92908) (authoritative) |
| [CVE-2026-92910](#cve-2026-92910) | Commerce | High | 7.2 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92910) (authoritative) |
| [CVE-2026-92911](#cve-2026-92911) | Adobe Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92911) (authoritative) |
| [CVE-2026-92922](#cve-2026-92922) | Adobe Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92922) (authoritative) |
| [CVE-2026-95631](#cve-2026-95631) | Commerce |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-95631) (authoritative) |
| [CVE-2026-103830](#cve-2026-103830) | Substance 3D Stager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103830) (authoritative) |
| [CVE-2026-103832](#cve-2026-103832) | Substance 3D Stager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103832) (authoritative) |
| [CVE-2026-103833](#cve-2026-103833) | Substance 3D Stager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103833) (authoritative) |
| [CVE-2026-103834](#cve-2026-103834) | Substance 3D Stager | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103834) (authoritative) |
| [CVE-2026-103835](#cve-2026-103835) | Substance3D - Stager | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103835) (authoritative) |
| [CVE-2026-103836](#cve-2026-103836) | Substance 3D Stager | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103836) (authoritative) |
| [CVE-2026-103837](#cve-2026-103837) | Substance 3D Stager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103837) (authoritative) |
| [CVE-2026-103838](#cve-2026-103838) | Substance3D - Stager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103838) (authoritative) |
| [CVE-2026-103839](#cve-2026-103839) | Substance3D - Stager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103839) (authoritative) |
| [CVE-2026-103840](#cve-2026-103840) | Substance 3D Stager | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103840) (authoritative) |
| [CVE-2026-103851](#cve-2026-103851) | Substance3D - Stager | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103851) (authoritative) |
| [CVE-2026-106634](#cve-2026-106634) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-106634) (authoritative) |
| [CVE-2026-110083](#cve-2026-110083) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-110083) (authoritative) |


## CVE-2026-100133

Adobe Commerce contains a stored Cross-Site Scripting (XSS) vulnerability allowing attackers to inject malicious JavaScript into form fields. When a victim accesses the affected page, the script executes within the victim's session, enabling potential account takeover or unauthorized actions due to the elevated privileges or scope changes associated with the session.

Affected products:
- Adobe Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100133


















Related in this roundup: [CVE-2026-92908](#cve-2026-92908), [CVE-2026-92911](#cve-2026-92911), [CVE-2026-92922](#cve-2026-92922).

## CVE-2026-103849

Adobe Commerce contains an improper neutralization of special elements vulnerability in its template engine, allowing a remote, unauthenticated attacker to achieve arbitrary code execution. The vulnerability permits attackers to gain elevated access or control over user sessions without requiring user interaction.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103849







































Related in this roundup: [CVE-2026-91013](#cve-2026-91013), [CVE-2026-92464](#cve-2026-92464), [CVE-2026-92909](#cve-2026-92909), [CVE-2026-92910](#cve-2026-92910), [CVE-2026-95631](#cve-2026-95631).

## CVE-2026-91013

Adobe Commerce contains a stored Cross-Site Scripting (XSS) vulnerability that allows attackers to inject malicious JavaScript into form fields. When a victim accesses the affected page, the script executes in their browser, potentially leading to unauthorized account access or session hijacking.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-91013







































Related in this roundup: [CVE-2026-103849](#cve-2026-103849), [CVE-2026-92464](#cve-2026-92464), [CVE-2026-92909](#cve-2026-92909), [CVE-2026-92910](#cve-2026-92910), [CVE-2026-95631](#cve-2026-95631).

## CVE-2026-92464

Adobe Commerce contains an improper input validation vulnerability that allows a high-privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and carries a high impact on the integrity and availability of the affected system.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-92464






































Related in this roundup: [CVE-2026-103849](#cve-2026-103849), [CVE-2026-91013](#cve-2026-91013), [CVE-2026-92909](#cve-2026-92909), [CVE-2026-92910](#cve-2026-92910), [CVE-2026-95631](#cve-2026-95631).

## CVE-2026-92909

CVE-2026-92909 describes an incorrect authorization vulnerability in Adobe Commerce that allows a remote, unauthenticated attacker to achieve arbitrary code execution. The flaw does not require user interaction, making it a high-severity remote code execution risk for e-commerce environments.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-92909





































Related in this roundup: [CVE-2026-103849](#cve-2026-103849), [CVE-2026-91013](#cve-2026-91013), [CVE-2026-92464](#cve-2026-92464), [CVE-2026-92910](#cve-2026-92910), [CVE-2026-95631](#cve-2026-95631).

## CVE-2026-103848

Adobe Experience Manager contains an OS command injection vulnerability, classified under CWE-78, that allows an unauthenticated or low-privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the scope of the affected application, posing a critical risk to environment integrity.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103848



































Related in this roundup: [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-105895

CVE-2026-105895 is an improper input validation vulnerability in Adobe Experience Manager that allows for unauthenticated arbitrary code execution. The vulnerability is highly critical, as it does not require user interaction and can lead to elevated access or account compromise within the context of the running application session.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105895



































Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-106626

Adobe Experience Manager is vulnerable to an improper input validation flaw that allows a highly privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the overall system security scope.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-106626


































Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-106629

Adobe Experience Manager contains a stored cross-site scripting (XSS) vulnerability allowing remote attackers to inject malicious JavaScript into form fields. When rendered in a victim's browser, this script can execute with the context of the user session, potentially leading to unauthorized account access or session hijacking.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-106629

































Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-106630

Adobe Experience Manager contains a stored Cross-Site Scripting (XSS) vulnerability allowing attackers to inject malicious scripts into form fields. When rendered in a victim's browser, the script executes, potentially leading to unauthorized session access or account compromise.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-106630
































Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-48382

Adobe Experience Manager contains an incorrect authorization vulnerability that allows for remote code execution without user interaction. An unauthenticated attacker can exploit this flaw to gain unauthorized access, potentially escalating privileges within the context of the affected session.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48382































Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-48383

Adobe Experience Manager contains an incorrect authorization vulnerability that allows for unauthenticated arbitrary code execution. The vulnerability is characterized by a changed scope and high severity, potentially leading to unauthorized system access or account takeover without requiring user interaction.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48383






























Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-75732

Adobe Experience Manager contains an incorrect authorization vulnerability that allows for unauthenticated, remote arbitrary code execution. Successful exploitation results in full control over the session or account with elevated privileges, impacting the integrity and availability of the system.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-75732





























Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-83662

Adobe Experience Manager is vulnerable to a reflected Cross-Site Scripting (XSS) attack. An attacker can exploit this by enticing a user to visit a maliciously crafted URL, allowing the injection of arbitrary scripts into the victim's session. Successful exploitation may lead to session hijacking or unauthorized actions performed on behalf of the authenticated user.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83662




























Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-90531

Adobe Experience Manager contains an XML External Entity (XXE) vulnerability that allows a low-privileged attacker to achieve privilege escalation and access restricted internal resources without requiring user interaction. The vulnerability significantly changes the security scope of the affected application.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-90531



























Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-90532

Adobe Experience Manager is vulnerable to an incorrect authorization flaw allowing unauthenticated, remote attackers to achieve arbitrary code execution. The vulnerability does not require user interaction and can lead to account or session takeover with elevated privileges.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-90532


























Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-106634](#cve-2026-106634), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-103966

Adobe Framemaker contains a heap-based buffer overflow vulnerability that allows for arbitrary code execution. The vulnerability is triggered when a user opens a specially crafted, malicious file, necessitating user interaction to achieve exploitation in the context of the current user.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103966
























Related in this roundup: [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344), [CVE-2026-106625](#cve-2026-106625).

## CVE-2026-103967

Adobe Framemaker contains an out-of-bounds write vulnerability that can be exploited by enticing a user to open a specially crafted malicious file. Successful exploitation allows an attacker to achieve arbitrary code execution within the security context of the current user.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103967
























Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344), [CVE-2026-106625](#cve-2026-106625).

## CVE-2026-104340

Adobe Framemaker contains a heap-based buffer overflow vulnerability that allows an attacker to achieve arbitrary code execution. The vulnerability is triggered when a user opens a specially crafted, malicious file, necessitating user interaction to execute the exploit.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-104340























Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344), [CVE-2026-106625](#cve-2026-106625).

## CVE-2026-104341

Adobe Framemaker contains an out-of-bounds write vulnerability that allows for arbitrary code execution. The vulnerability is triggered when a user opens a specially crafted malicious file, requiring user interaction to execute the attack.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-104341






















Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344), [CVE-2026-106625](#cve-2026-106625).

## CVE-2026-104342

Adobe Framemaker contains a use-after-free vulnerability that can be triggered when a user opens a maliciously crafted file. Successful exploitation allows for arbitrary code execution within the context of the currently logged-in user, requiring user interaction to execute the attack.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-104342





















Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104344](#cve-2026-104344), [CVE-2026-106625](#cve-2026-106625).

## CVE-2026-104344

Adobe Framemaker is vulnerable to a heap-based buffer overflow that allows for arbitrary code execution. The vulnerability is triggered when a user is convinced to open a maliciously crafted file, making this primarily an exploitation vector via user interaction.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-104344




















Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-106625](#cve-2026-106625).

## CVE-2026-106625

Adobe Framemaker contains an out-of-bounds write vulnerability that allows for arbitrary code execution. An attacker can exploit this by enticing a user to open a specially crafted malicious file, leading to code execution in the context of the currently logged-in user.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-106625



















Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344).

## CVE-2026-92908

Adobe Commerce contains an incorrect authorization vulnerability that allows a low-privileged attacker to bypass security features. This vulnerability grants unauthorized read and write access to the affected instance, potentially leading to limited availability disruption without requiring user interaction.

Affected products:
- Adobe Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-92908


















Related in this roundup: [CVE-2026-100133](#cve-2026-100133), [CVE-2026-92911](#cve-2026-92911), [CVE-2026-92922](#cve-2026-92922).

## CVE-2026-92910

CVE-2026-92910 is an incorrect authorization vulnerability in Adobe Commerce that allows a remote, unauthenticated attacker to bypass security features. Successful exploitation results in unauthorized read and limited write access to the application, without requiring user interaction.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-92910

















Related in this roundup: [CVE-2026-103849](#cve-2026-103849), [CVE-2026-91013](#cve-2026-91013), [CVE-2026-92464](#cve-2026-92464), [CVE-2026-92909](#cve-2026-92909), [CVE-2026-95631](#cve-2026-95631).

## CVE-2026-92911

Adobe Commerce contains a stored Cross-Site Scripting (XSS) vulnerability that allows low-privileged attackers to inject malicious JavaScript into form fields. When viewed by a user, the script executes within the victim's browser context, potentially leading to session hijacking or unauthorized account access.

Affected products:
- Adobe Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-92911
















Related in this roundup: [CVE-2026-100133](#cve-2026-100133), [CVE-2026-92908](#cve-2026-92908), [CVE-2026-92922](#cve-2026-92922).

## CVE-2026-92922

Adobe Commerce is vulnerable to a stored Cross-Site Scripting (XSS) attack. A high-privileged attacker can inject malicious scripts into form fields, which are then executed in the context of a victim's browser session. This can lead to account takeover or session hijacking.

Affected products:
- Adobe Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-92922















Related in this roundup: [CVE-2026-100133](#cve-2026-100133), [CVE-2026-92908](#cve-2026-92908), [CVE-2026-92911](#cve-2026-92911).

## CVE-2026-95631

Adobe Commerce contains an improper input validation vulnerability that allows a high-privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the integrity and availability of the system through changed scope.

Affected products:
- Commerce

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-95631














Related in this roundup: [CVE-2026-103849](#cve-2026-103849), [CVE-2026-91013](#cve-2026-91013), [CVE-2026-92464](#cve-2026-92464), [CVE-2026-92909](#cve-2026-92909), [CVE-2026-92910](#cve-2026-92910).

## CVE-2026-103830

CVE-2026-103830 describes a stack-based buffer overflow vulnerability in Adobe Substance 3D Stager. An attacker can exploit this by enticing a user to open a specially crafted malicious file, leading to arbitrary code execution within the context of the currently logged-in user.

Affected products:
- Substance 3D Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103830












Related in this roundup: [CVE-2026-103832](#cve-2026-103832), [CVE-2026-103833](#cve-2026-103833), [CVE-2026-103834](#cve-2026-103834), [CVE-2026-103836](#cve-2026-103836), [CVE-2026-103837](#cve-2026-103837), [CVE-2026-103840](#cve-2026-103840).

## CVE-2026-103832

CVE-2026-103832 describes an out-of-bounds write vulnerability in Adobe Substance 3D Stager. An attacker can exploit this flaw by enticing a user to open a specially crafted malicious file, which may lead to arbitrary code execution within the context of the current user.

Affected products:
- Substance 3D Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103832












Related in this roundup: [CVE-2026-103830](#cve-2026-103830), [CVE-2026-103833](#cve-2026-103833), [CVE-2026-103834](#cve-2026-103834), [CVE-2026-103836](#cve-2026-103836), [CVE-2026-103837](#cve-2026-103837), [CVE-2026-103840](#cve-2026-103840).

## CVE-2026-103833

CVE-2026-103833 is an out-of-bounds write vulnerability in Adobe Substance 3D Stager. An attacker can exploit this flaw by enticing a user to open a specially crafted malicious file, which may lead to arbitrary code execution within the context of the current user session.

Affected products:
- Substance 3D Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103833











Related in this roundup: [CVE-2026-103830](#cve-2026-103830), [CVE-2026-103832](#cve-2026-103832), [CVE-2026-103834](#cve-2026-103834), [CVE-2026-103836](#cve-2026-103836), [CVE-2026-103837](#cve-2026-103837), [CVE-2026-103840](#cve-2026-103840).

## CVE-2026-103834

Adobe Substance 3D Stager is vulnerable to an out-of-bounds write flaw that can be exploited by enticing a user to open a malicious file. Successful exploitation allows an attacker to execute arbitrary code within the security context of the current user.

Affected products:
- Substance 3D Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103834










Related in this roundup: [CVE-2026-103830](#cve-2026-103830), [CVE-2026-103832](#cve-2026-103832), [CVE-2026-103833](#cve-2026-103833), [CVE-2026-103836](#cve-2026-103836), [CVE-2026-103837](#cve-2026-103837), [CVE-2026-103840](#cve-2026-103840).

## CVE-2026-103835

Substance3D - Stager contains an out-of-bounds write vulnerability that allows for arbitrary code execution if a user is tricked into opening a specially crafted malicious file. Successful exploitation occurs in the context of the current user session.

Affected products:
- Substance3D - Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103835






Related in this roundup: [CVE-2026-103838](#cve-2026-103838), [CVE-2026-103839](#cve-2026-103839), [CVE-2026-103851](#cve-2026-103851).

## CVE-2026-103836

Adobe Substance 3D Stager is vulnerable to an out-of-bounds write issue triggered by opening a malicious file. Successful exploitation allows an attacker to achieve arbitrary code execution in the context of the current user, requiring user interaction.

Affected products:
- Substance 3D Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103836








Related in this roundup: [CVE-2026-103830](#cve-2026-103830), [CVE-2026-103832](#cve-2026-103832), [CVE-2026-103833](#cve-2026-103833), [CVE-2026-103834](#cve-2026-103834), [CVE-2026-103837](#cve-2026-103837), [CVE-2026-103840](#cve-2026-103840).

## CVE-2026-103837

Adobe Substance 3D Stager is vulnerable to an out-of-bounds write flaw that can be triggered when a user opens a specially crafted malicious file. Successful exploitation allows for arbitrary code execution in the context of the current user, necessitating user interaction to execute the attack.

Affected products:
- Substance 3D Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103837







Related in this roundup: [CVE-2026-103830](#cve-2026-103830), [CVE-2026-103832](#cve-2026-103832), [CVE-2026-103833](#cve-2026-103833), [CVE-2026-103834](#cve-2026-103834), [CVE-2026-103836](#cve-2026-103836), [CVE-2026-103840](#cve-2026-103840).

## CVE-2026-103838

Adobe Substance 3D Stager contains an out-of-bounds write vulnerability that can be triggered when a user opens a maliciously crafted file. Successful exploitation allows for arbitrary code execution in the context of the current user, requiring manual user interaction to execute the malicious file.

Affected products:
- Substance3D - Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103838






Related in this roundup: [CVE-2026-103835](#cve-2026-103835), [CVE-2026-103839](#cve-2026-103839), [CVE-2026-103851](#cve-2026-103851).

## CVE-2026-103839

Adobe Substance3D Stager is vulnerable to an out-of-bounds write flaw that allows an attacker to achieve arbitrary code execution. Successful exploitation requires a user to open a specially crafted malicious file, leading to execution within the context of the currently logged-in user.

Affected products:
- Substance3D - Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103839





Related in this roundup: [CVE-2026-103835](#cve-2026-103835), [CVE-2026-103838](#cve-2026-103838), [CVE-2026-103851](#cve-2026-103851).

## CVE-2026-103840

Adobe Substance 3D Stager is vulnerable to an out-of-bounds read when parsing maliciously crafted files. An attacker can exploit this vulnerability by tricking a user into opening a malicious file, leading to potential code execution within the context of the current user.

Affected products:
- Substance 3D Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103840




Related in this roundup: [CVE-2026-103830](#cve-2026-103830), [CVE-2026-103832](#cve-2026-103832), [CVE-2026-103833](#cve-2026-103833), [CVE-2026-103834](#cve-2026-103834), [CVE-2026-103836](#cve-2026-103836), [CVE-2026-103837](#cve-2026-103837).

## CVE-2026-103851

Adobe Substance 3D Stager is vulnerable to a stack-based buffer overflow triggered by opening a specially crafted malicious file, which allows an attacker to achieve arbitrary code execution in the context of the user running the application.

Affected products:
- Substance3D - Stager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103851



Related in this roundup: [CVE-2026-103835](#cve-2026-103835), [CVE-2026-103838](#cve-2026-103838), [CVE-2026-103839](#cve-2026-103839).

## CVE-2026-106634

Adobe Experience Manager is vulnerable to a path traversal flaw (CVE-2026-106634) that allows low-privileged attackers to perform arbitrary file system writes without user interaction. The vulnerability results in a changed scope and could be leveraged by an attacker to write files to unauthorized locations on the host system.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-106634


Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-110083](#cve-2026-110083).

## CVE-2026-110083

Adobe Experience Manager contains an SQL injection vulnerability (CVE-2026-110083) that allows a low-privileged, unauthenticated attacker to bypass security features, resulting in unauthorized read and limited write access to the application data. Exploitation is remote and does not require user interaction, making it a critical threat to the integrity of the affected content management system.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-110083

Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532), [CVE-2026-106634](#cve-2026-106634).
