---
title: Cisco Security Updates - September 2026
slug: 2026-09-cisco-security-updates
description: Roundup of Cisco security advisories published in September 2026.
date: "2026-09-02T18:06:39Z"
lastmod: "2026-09-16T19:19:36Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:o:cisco:asyncos:*:*:*:*:*:*:*:*
tags:
  - roundup
vendors:
  - Cisco
cves:
  - id: CVE-2026-20354
    product: Secure Email
    cvss: 5.9
    epss: 0.00149
  - id: CVE-2026-20355
    cvss: 5.9
    epss: 0.00149
  - id: CVE-2026-20212
    cvss: 9.8
    epss: 0.00527
  - id: CVE-2026-20281
    cvss: 7.5
    epss: 0.00332
  - id: CVE-2026-20293
    product: UCS Servers
    cvss: 7.1
    epss: 0.00132
  - id: CVE-2026-20353
    product: Secure Email Gateway
    cvss: 9.8
    epss: 0.00373
  - id: CVE-2026-76440
    cvss: 9.8
    epss: 0.00428
  - id: CVE-2026-76441
    cvss: 9.8
  - id: CVE-2026-76443
    cvss: 9.8
    epss: 0.00366
  - id: CVE-2026-76461
    cvss: 9.8
    epss: 0.02162
  - id: CVE-2026-76442
    cvss: 7.5
    epss: 0.00331
  - id: CVE-2026-20234
    cvss: 9.9
  - id: CVE-2026-20305
    cvss: 9.1
  - id: CVE-2026-20306
    cvss: 9.1
  - id: CVE-2026-20307
    cvss: 9.9
  - id: CVE-2024-20260
    product: Secure Firewall Adaptive Security Appliance Software
    cvss: 8.6
    epss: 0.0062
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
updates:
  - at: "2026-09-16T17:51:21Z"
    level: L2
    summary: added CVE-2026-20234
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20306
  - at: "2026-09-16T18:59:14Z"
    level: L2
    summary: added CVE-2026-20306
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-76460
  - at: "2026-09-16T19:19:24Z"
    level: L2
    summary: added CVE-2024-20260, CVE-2026-20305, CVE-2026-20307
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftdvirtual-dos-MuenGnYR?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20SSL%20VPN%20Denial%20of%20Service%20Vulnerability%26vs_k=1
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-javarce-y2NypXwk?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Java%20Deserialization%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
---

This roundup covers 24 Cisco security vulnerabilities. CVSS base scores range from 5.9 to 9.9. None are reported as actively exploited at the time of release. The issues affect Adaptive Security Appliance Software, AsyncOS Software, Desk Phone 9800 Series, Identity Services Engine, Nexus 9000 Series Switches, Secure Adaptive Security Appliance Software, Secure Email, Secure Email Gateway, Secure FMC Software, Secure Firewall Adaptive Security Appliance Software, Secure Firewall Management Center Software, UCS Servers.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-20354](#cve-2026-20354) | Secure Email | Medium | 5.9 | 0.15% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20355](#cve-2026-20355) | Secure Email | Medium | 5.9 | 0.15% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20212](#cve-2026-20212) | Nexus 9000 Series Switches | Critical | 9.8 | 0.53% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9k-s1-rce-EH8dEtr?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Switches%20Silicon%20One%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20281](#cve-2026-20281) | Desk Phone 9800 Series | High | 7.5 | 0.33% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-phone-dos-txMYNRzv?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Desk%20Phone%209800%20Series,%20IP%20Phone%207800%20and%208800%20Series,%20and%20Video%20Phone%208875%20with%20SIP%20Software%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20293](#cve-2026-20293) | UCS Servers | High | 7.1 | 0.13% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20293) (authoritative) |
| [CVE-2026-20353](#cve-2026-20353) | Secure Email Gateway | Critical | 9.8 | 0.37% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20353) (authoritative) |
| [CVE-2026-76440](#cve-2026-76440) | Secure Email Gateway | Critical | 9.8 | 0.43% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76440) (authoritative) |
| [CVE-2026-76441](#cve-2026-76441) | Secure Email Gateway | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76441) (authoritative) |
| [CVE-2026-76443](#cve-2026-76443) | Secure Email Gateway | Critical | 9.8 | 0.37% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76443) (authoritative) |
| [CVE-2026-76461](#cve-2026-76461) | AsyncOS Software | Critical | 9.8 | 2.16% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76461) (authoritative) |
| [CVE-2026-76442](#cve-2026-76442) | Secure Email Gateway | High | 7.5 | 0.33% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76442) (authoritative) |
| [CVE-2026-20234](#cve-2026-20234) | Identity Services Engine | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20234) (authoritative) |
| [CVE-2026-20305](#cve-2026-20305) | Identity Services Engine | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20305) (authoritative) |
| [CVE-2026-20306](#cve-2026-20306) | Identity Services Engine | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20306) (authoritative) |
| [CVE-2026-20307](#cve-2026-20307) | Identity Services Engine |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20307) (authoritative) |
| [CVE-2026-20331](#cve-2026-20331) | Secure Adaptive Security Appliance Software |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20331) (authoritative) |
| [CVE-2026-76420](#cve-2026-76420) | Secure FMC Software |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76420) (authoritative) |
| [CVE-2026-76460](#cve-2026-76460) | Identity Services Engine |  |  |  | no | [source](https://www.cve.org/CVERecord?id=CVE-2026-76460) (authoritative) |
| [CVE-2024-20260](#cve-2024-20260) | Secure Firewall Adaptive Security Appliance Software | High | 8.6 | 0.62% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftdvirtual-dos-MuenGnYR?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20SSL%20VPN%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20250](#cve-2026-20250) | Adaptive Security Appliance Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dtls-dos-Kp57HkyO?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20for%20Secure%20Firewall%203100%20and%204200%20Series%20DTLS%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20242](#cve-2026-20242) | Secure Firewall Management Center Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-javarce-y2NypXwk?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Java%20Deserialization%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20282](#cve-2026-20282) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20283](#cve-2026-20283) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20284](#cve-2026-20284) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1) (authoritative) |


## CVE-2026-20354

Cisco Secure Email contains multiple vulnerabilities in its S/MIME decryption functionality stemming from insufficient message integrity validation. These flaws allow an unauthenticated, remote attacker to perform machine-in-the-middle attacks to intercept encrypted email traffic, modify it, and subsequently recover the plaintext content of the communications.

Affected products:
- Secure Email

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1





















Related in this roundup: [CVE-2026-20355](#cve-2026-20355).

## CVE-2026-20355

Cisco Secure Email contains multiple vulnerabilities in its S/MIME decryption functionality stemming from insufficient message integrity validation. These flaws allow an unauthenticated, remote attacker to perform machine-in-the-middle attacks to intercept encrypted email traffic, modify it, and subsequently recover the plaintext content of the communications.

Affected products:
- Secure Email

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1





















Related in this roundup: [CVE-2026-20354](#cve-2026-20354).

## CVE-2026-20212

A critical vulnerability exists in the Silicon One integration for Cisco Nexus 9000 Series Switches, stemming from exposed TCP ports 43210 and 43211 in the default Layer 3 VRF. An unauthenticated remote attacker can leverage this access to execute arbitrary code with root privileges or cause a device reload via the S1HAL process crash.

Affected products:
- Nexus 9000 Series Switches

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9k-s1-rce-EH8dEtr?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Switches%20Silicon%20One%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1

## CVE-2026-20281

Cisco SIP-enabled desk and video phones are vulnerable to a remote denial-of-service condition due to improper memory management when processing HTTP packets. An unauthenticated attacker can trigger this by sending a continuous stream of crafted HTTP packets to the device, provided the phone is registered to Cisco Unified Communications Manager and has Web Access enabled. Exploitation results in memory exhaustion, necessitating a manual reboot of the device for recovery.

Affected products:
- Desk Phone 9800 Series
- IP Phone 7800 Series
- IP Phone 8800 Series
- Video Phone 8875

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-phone-dos-txMYNRzv?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Desk%20Phone%209800%20Series,%20IP%20Phone%207800%20and%208800%20Series,%20and%20Video%20Phone%208875%20with%20SIP%20Software%20Denial%20of%20Service%20Vulnerability%26vs_k=1

## CVE-2026-20293

A vulnerability in the UEFI Shell implementation of Cisco UCS Servers and UCS-based appliances allows authenticated users or attackers with physical access to bypass UEFI Secure Boot validation. By using memory write commands available within the UEFI Shell, an attacker can modify UEFI memory variables to overwrite Secure Boot-related values, enabling the execution of unauthorized software in the preboot environment.

Affected products:
- UCS Servers
- UCS-based appliances

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20293

## CVE-2026-20353

CVE-2026-20353 refers to vulnerabilities in Cisco Secure Email Gateway and Cisco Secure Email and Web Manager caused by improper control of a resource through its lifetime (CWE-664). This vulnerability carries a CVSS v3.1 base score of 9.8, indicating a critical security flaw identified during an internal security review.

Affected products:
- Secure Email Gateway
- Secure Email and Web Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20353
















Related in this roundup: [CVE-2026-76440](#cve-2026-76440), [CVE-2026-76441](#cve-2026-76441), [CVE-2026-76443](#cve-2026-76443), [CVE-2026-76442](#cve-2026-76442).

## CVE-2026-76440

CVE-2026-76440 identifies a path traversal vulnerability in Cisco Secure Email Gateway and Cisco Secure Email and Web Manager, discovered during an internal security review. The vulnerability allows for unauthorized file system access due to improper input validation, carrying a CVSS base score of 9.8.

Affected products:
- Secure Email Gateway
- Secure Email and Web Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76440
















Related in this roundup: [CVE-2026-20353](#cve-2026-20353), [CVE-2026-76441](#cve-2026-76441), [CVE-2026-76443](#cve-2026-76443), [CVE-2026-76442](#cve-2026-76442).

## CVE-2026-76441

CVE-2026-76441 identifies multiple improper access control vulnerabilities within Cisco Secure Email Gateway and Cisco Secure Email and Web Manager, discovered during an internal security review. These vulnerabilities carry a high CVSS score of 9.8 and highlight a failure to properly restrict access to sensitive components, requiring updates to the affected software.

Affected products:
- Secure Email Gateway
- Secure Email and Web Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76441















Related in this roundup: [CVE-2026-20353](#cve-2026-20353), [CVE-2026-76440](#cve-2026-76440), [CVE-2026-76443](#cve-2026-76443), [CVE-2026-76442](#cve-2026-76442).

## CVE-2026-76443

Cisco has released patches for multiple internally discovered vulnerabilities in the Cisco Secure Email Gateway and Cisco Secure Email and Web Manager, tracked under CVE-2026-76443. The vulnerabilities are identified as improper neutralization issues (CWE-707) and carry a CVSS base score of 9.8, indicating a critical severity level requiring immediate attention from administrators.

Affected products:
- Secure Email Gateway
- Secure Email and Web Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76443














Related in this roundup: [CVE-2026-20353](#cve-2026-20353), [CVE-2026-76440](#cve-2026-76440), [CVE-2026-76441](#cve-2026-76441), [CVE-2026-76442](#cve-2026-76442).

## CVE-2026-76461

CVE-2026-76461 is a critical vulnerability in Cisco AsyncOS Software for Secure Email Gateway caused by insufficient validation during email parsing. An unauthenticated remote attacker can leverage a crafted email containing malicious SQL statements to achieve arbitrary command execution with root privileges on the underlying operating system.

Affected products:
- AsyncOS Software
- Secure Email Gateway

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76461

## CVE-2026-76442

CVE-2026-76442 describes a vulnerability in Cisco Secure Email Gateway and Cisco Secure Email and Web Manager identified during an internal security review. The vulnerability relates to improper validation of input quantity (CWE-1284), which can lead to potential service disruption or security bypass. Remediation involves applying the provided software hardening releases from the vendor.

Affected products:
- Secure Email Gateway
- Secure Email and Web Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76442












Related in this roundup: [CVE-2026-20353](#cve-2026-20353), [CVE-2026-76440](#cve-2026-76440), [CVE-2026-76441](#cve-2026-76441), [CVE-2026-76443](#cve-2026-76443).

## CVE-2026-20234

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC) contain a vulnerability related to insufficiently protected credentials, categorized under CWE-522. The vulnerability carries a high CVSS v3.1 base score of 9.9, and was identified during an internal security review, prompting a software hardening release to address the credential protection flaws.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20234










Related in this roundup: [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284).

## CVE-2026-20305

CVE-2026-20305 is a command injection vulnerability within the diagnostic tools of Cisco ISE and ISE-PIC. An authenticated remote attacker with administrative credentials can exploit improper input validation via the web-based management interface to execute arbitrary code with root privileges. Successful exploitation may result in a denial of service condition by rendering the affected node unavailable.

Affected products:
- Identity Services Engine
- ISE-PIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20305










Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284).

## CVE-2026-20306

CVE-2026-20306 is a command injection vulnerability in the REST API of Cisco Identity Services Engine (ISE) and ISE-PIC. An authenticated remote attacker with administrative credentials can supply crafted commands to the management interface, leading to arbitrary code execution with root privileges or a denial-of-service condition.

Affected products:
- Identity Services Engine
- ISE-PIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20306









Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284).

## CVE-2026-20307

CVE-2026-20307 is a critical remote code execution vulnerability in the web management interface of Cisco Identity Services Engine (ISE). The vulnerability arises from insecure deserialization of Java byte streams, allowing an authenticated, low-privileged administrator to execute arbitrary commands as root on the underlying operating system. Successful exploitation can lead to full system compromise or a denial of service condition affecting network authentication.

Affected products:
- Identity Services Engine

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20307








Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284).

## CVE-2026-20331

CVE-2026-20331 refers to a set of internally discovered vulnerabilities affecting Cisco Secure Adaptive Security Appliance (ASA), Firepower Threat Defense (FTD), and Firepower Management Center (FMC) software. These vulnerabilities are classified under CWE-693 (Protection Mechanism Failure) and carry a CVSS base score of 9.6, indicating critical security implications requiring software hardening updates.

Affected products:
- Secure Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software
- Secure Firewall Management Center Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20331

## CVE-2026-76420

CVE-2026-76420 is a critical vulnerability in the Apache JServ Protocol (AJP) connector within Cisco Secure FMC Software caused by improper encryption parameter initialization during boot. An unauthenticated, remote attacker can exploit this via crafted packets when the sftunnel connection to Cisco Secure FTD Software is inactive, potentially achieving remote code execution as root and gaining unauthorized control over the FMC REST APIs.

Affected products:
- Secure FMC Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76420

## CVE-2026-76460

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC) contain an incorrect use of privileged APIs vulnerability that allows unauthenticated remote attackers to bypass the web-based management interface and gain unauthorized access to the device.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://www.cve.org/CVERecord?id=CVE-2026-76460





Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284).

## CVE-2024-20260

A vulnerability in the VPN and management web servers of Cisco Secure Firewall ASA and FTD software allows an unauthenticated remote attacker to cause a denial of service (DoS) by sending a high volume of SSL/TLS connection requests. The attack depletes system memory or buffer blocks, causing connection processing to slow down or fail entirely. A manual reload may be required to restore services.

Affected products:
- Secure Firewall Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftdvirtual-dos-MuenGnYR?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20SSL%20VPN%20Denial%20of%20Service%20Vulnerability%26vs_k=1

## CVE-2026-20250

A vulnerability in the DTLS message handling of Cisco Secure Firewall ASA and FTD software for 3100 and 4200 series devices allows an unauthenticated, remote attacker to trigger a denial-of-service (DoS) condition. The issue stems from improper resource management during the processing of crafted DTLS traffic, which can force the device to reload. Detection engineers should monitor for anomalous spikes or malformed DTLS traffic patterns directed at the firewall's management or data plane interfaces.

Affected products:
- Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dtls-dos-Kp57HkyO?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20for%20Secure%20Firewall%203100%20and%204200%20Series%20DTLS%20Denial%20of%20Service%20Vulnerability%26vs_k=1

## CVE-2026-20242

A critical remote code execution vulnerability exists in the External Database Access feature of Cisco Secure Firewall Management Center (FMC) Software. The flaw arises from insecure deserialization of user-supplied Java byte streams. An unauthenticated, remote attacker who already controls a host authorized in the external database access list can send a crafted Java object to a specific TCP port to execute arbitrary commands as the root user.

Affected products:
- Secure Firewall Management Center Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-javarce-y2NypXwk?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Java%20Deserialization%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1

## CVE-2026-20282

Cisco Identity Services Engine (ISE) contains multiple vulnerabilities allowing authenticated, remote attackers to perform SQL injections, modify database contents, and execute arbitrary operating system commands. These vulnerabilities are particularly severe as they can be leveraged to escalate privileges to the root level on the affected device.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1

Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284).

## CVE-2026-20283

Cisco Identity Services Engine (ISE) contains multiple vulnerabilities allowing authenticated, remote attackers to perform SQL injections, modify database contents, and execute arbitrary operating system commands. These vulnerabilities are particularly severe as they can be leveraged to escalate privileges to the root level on the affected device.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1

Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20284](#cve-2026-20284).

## CVE-2026-20284

Cisco Identity Services Engine (ISE) contains multiple vulnerabilities allowing authenticated, remote attackers to perform SQL injections, modify database contents, and execute arbitrary operating system commands. These vulnerabilities are particularly severe as they can be leveraged to escalate privileges to the root level on the affected device.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1

Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283).
