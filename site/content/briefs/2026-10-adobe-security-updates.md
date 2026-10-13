---
title: Adobe Security Updates - October 2026
slug: 2026-10-adobe-security-updates
description: Roundup of Adobe security advisories published in October 2026.
date: "2026-10-13T20:38:10Z"
lastmod: "2026-10-13T22:41:06Z"
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
  - id: CVE-2026-105895
    cvss: 9.9
  - id: CVE-2026-106626
    product: Experience Manager
    cvss: 9.1
  - id: CVE-2026-106629
    cvss: 9.3
  - id: CVE-2026-106630
    product: Experience Manager
    cvss: 9.3
  - id: CVE-2026-75732
    cvss: 9.9
  - id: CVE-2026-90531
    cvss: 9.6
  - id: CVE-2026-90532
    cvss: 10
  - id: CVE-2026-103967
    cvss: 7.8
  - id: CVE-2026-104340
    cvss: 7.8
  - id: CVE-2026-104341
    cvss: 7.8
  - id: CVE-2026-104342
    product: Framemaker
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106625
updates:
  - at: "2026-10-13T20:44:08Z"
    level: L2
    summary: added CVE-2026-106629
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90532
  - at: "2026-10-13T22:39:26Z"
    level: L2
    summary: added CVE-2026-104342, CVE-2026-92464
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103966
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104342
  - at: "2026-10-13T22:40:55Z"
    level: L2
    summary: added CVE-2026-104340 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104344
  - at: "2026-10-13T22:41:06Z"
    level: L2
    summary: added CVE-2026-103967 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-106625
---

This roundup covers 22 Adobe security vulnerabilities. CVSS base scores range from 7.8 to 10.0. None are reported as actively exploited at the time of release. The issues affect Adobe Commerce, Commerce, Experience Manager, Framemaker.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-100133](#cve-2026-100133) | Adobe Commerce | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100133) (authoritative) |
| [CVE-2026-103849](#cve-2026-103849) | Commerce | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103849) (authoritative) |
| [CVE-2026-91013](#cve-2026-91013) | Commerce | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-91013) (authoritative) |
| [CVE-2026-92464](#cve-2026-92464) | Commerce | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92464) (authoritative) |
| [CVE-2026-92909](#cve-2026-92909) | Commerce | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-92909) (authoritative) |
| [CVE-2026-103848](#cve-2026-103848) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103848) (authoritative) |
| [CVE-2026-105895](#cve-2026-105895) | Experience Manager | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105895) (authoritative) |
| [CVE-2026-106626](#cve-2026-106626) | Experience Manager | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-106626) (authoritative) |
| [CVE-2026-106629](#cve-2026-106629) | Experience Manager | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-106629) (authoritative) |
| [CVE-2026-106630](#cve-2026-106630) | Experience Manager | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-106630) (authoritative) |
| [CVE-2026-48382](#cve-2026-48382) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48382) (authoritative) |
| [CVE-2026-48383](#cve-2026-48383) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48383) (authoritative) |
| [CVE-2026-75732](#cve-2026-75732) | Experience Manager | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-75732) (authoritative) |
| [CVE-2026-83662](#cve-2026-83662) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83662) (authoritative) |
| [CVE-2026-90531](#cve-2026-90531) | Experience Manager |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90531) (authoritative) |
| [CVE-2026-90532](#cve-2026-90532) | Experience Manager | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90532) (authoritative) |
| [CVE-2026-103966](#cve-2026-103966) | Framemaker |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103966) (authoritative) |
| [CVE-2026-103967](#cve-2026-103967) | Framemaker |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103967) (authoritative) |
| [CVE-2026-104340](#cve-2026-104340) | Framemaker | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-104340) (authoritative) |
| [CVE-2026-104341](#cve-2026-104341) | Framemaker |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-104341) (authoritative) |
| [CVE-2026-104342](#cve-2026-104342) | Framemaker | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-104342) (authoritative) |
| [CVE-2026-104344](#cve-2026-104344) | Framemaker |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-104344) (authoritative) |


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
















Related in this roundup: [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-105895

CVE-2026-105895 is an improper input validation vulnerability in Adobe Experience Manager that allows for unauthenticated arbitrary code execution. The vulnerability is highly critical, as it does not require user interaction and can lead to elevated access or account compromise within the context of the running application session.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105895
















Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-106626

Adobe Experience Manager is vulnerable to an improper input validation flaw that allows a highly privileged attacker to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the overall system security scope.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-106626















Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-106629

Adobe Experience Manager contains a stored cross-site scripting (XSS) vulnerability allowing remote attackers to inject malicious JavaScript into form fields. When rendered in a victim's browser, this script can execute with the context of the user session, potentially leading to unauthorized account access or session hijacking.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-106629














Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-106630

Adobe Experience Manager contains a stored Cross-Site Scripting (XSS) vulnerability allowing attackers to inject malicious scripts into form fields. When rendered in a victim's browser, the script executes, potentially leading to unauthorized session access or account compromise.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-106630













Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-48382

Adobe Experience Manager contains an incorrect authorization vulnerability that allows for remote code execution without user interaction. An unauthenticated attacker can exploit this flaw to gain unauthorized access, potentially escalating privileges within the context of the affected session.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48382












Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-48383

Adobe Experience Manager contains an incorrect authorization vulnerability that allows for unauthenticated arbitrary code execution. The vulnerability is characterized by a changed scope and high severity, potentially leading to unauthorized system access or account takeover without requiring user interaction.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48383











Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-75732

Adobe Experience Manager contains an incorrect authorization vulnerability that allows for unauthenticated, remote arbitrary code execution. Successful exploitation results in full control over the session or account with elevated privileges, impacting the integrity and availability of the system.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-75732










Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-83662

Adobe Experience Manager is vulnerable to a reflected Cross-Site Scripting (XSS) attack. An attacker can exploit this by enticing a user to visit a maliciously crafted URL, allowing the injection of arbitrary scripts into the victim's session. Successful exploitation may lead to session hijacking or unauthorized actions performed on behalf of the authenticated user.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83662









Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-90531](#cve-2026-90531), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-90531

Adobe Experience Manager contains an XML External Entity (XXE) vulnerability that allows a low-privileged attacker to achieve privilege escalation and access restricted internal resources without requiring user interaction. The vulnerability significantly changes the security scope of the affected application.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-90531








Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90532](#cve-2026-90532).

## CVE-2026-90532

Adobe Experience Manager is vulnerable to an incorrect authorization flaw allowing unauthenticated, remote attackers to achieve arbitrary code execution. The vulnerability does not require user interaction and can lead to account or session takeover with elevated privileges.

Affected products:
- Experience Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-90532







Related in this roundup: [CVE-2026-103848](#cve-2026-103848), [CVE-2026-105895](#cve-2026-105895), [CVE-2026-106626](#cve-2026-106626), [CVE-2026-106629](#cve-2026-106629), [CVE-2026-106630](#cve-2026-106630), [CVE-2026-48382](#cve-2026-48382), [CVE-2026-48383](#cve-2026-48383), [CVE-2026-75732](#cve-2026-75732), [CVE-2026-83662](#cve-2026-83662), [CVE-2026-90531](#cve-2026-90531).

## CVE-2026-103966

Adobe Framemaker contains a heap-based buffer overflow vulnerability that allows for arbitrary code execution. The vulnerability is triggered when a user opens a specially crafted, malicious file, necessitating user interaction to achieve exploitation in the context of the current user.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103966





Related in this roundup: [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344).

## CVE-2026-103967

Adobe Framemaker contains an out-of-bounds write vulnerability that can be exploited by enticing a user to open a specially crafted malicious file. Successful exploitation allows an attacker to achieve arbitrary code execution within the security context of the current user.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103967





Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344).

## CVE-2026-104340

Adobe Framemaker contains a heap-based buffer overflow vulnerability that allows an attacker to achieve arbitrary code execution. The vulnerability is triggered when a user opens a specially crafted, malicious file, necessitating user interaction to execute the exploit.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-104340




Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344).

## CVE-2026-104341

Adobe Framemaker contains an out-of-bounds write vulnerability that allows for arbitrary code execution. The vulnerability is triggered when a user opens a specially crafted malicious file, requiring user interaction to execute the attack.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-104341



Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104342](#cve-2026-104342), [CVE-2026-104344](#cve-2026-104344).

## CVE-2026-104342

Adobe Framemaker contains a use-after-free vulnerability that can be triggered when a user opens a maliciously crafted file. Successful exploitation allows for arbitrary code execution within the context of the currently logged-in user, requiring user interaction to execute the attack.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-104342


Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104344](#cve-2026-104344).

## CVE-2026-104344

Adobe Framemaker is vulnerable to a heap-based buffer overflow that allows for arbitrary code execution. The vulnerability is triggered when a user is convinced to open a maliciously crafted file, making this primarily an exploitation vector via user interaction.

Affected products:
- Framemaker

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-104344

Related in this roundup: [CVE-2026-103966](#cve-2026-103966), [CVE-2026-103967](#cve-2026-103967), [CVE-2026-104340](#cve-2026-104340), [CVE-2026-104341](#cve-2026-104341), [CVE-2026-104342](#cve-2026-104342).
