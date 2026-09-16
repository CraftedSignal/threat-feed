---
title: Cisco Security Updates - September 2026
slug: 2026-09-cisco-security-updates
description: Roundup of Cisco security advisories published in September 2026.
date: "2026-09-02T18:06:39Z"
lastmod: "2026-09-16T17:51:21Z"
type: threat
types:
  - threat
severities:
  - high
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
  - id: CVE-2026-76442
    cvss: 7.5
  - id: CVE-2026-20234
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20306
updates:
  - at: "2026-09-14T17:34:31Z"
    level: L2
    summary: added CVE-2026-20281 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20353
  - at: "2026-09-14T17:34:33Z"
    level: L2
    summary: added CVE-2026-20212
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76440
  - at: "2026-09-14T19:10:35Z"
    level: L2
    summary: added CVE-2026-76441 +2
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-esa-dfCrfXkm?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Gateway%20and%20Secure%20Email%20and%20Web%20Manager%20Security%20Hardening%20Release:%20September%202026%26vs_k=1
  - at: "2026-09-16T17:51:11Z"
    level: L2
    summary: added CVE-2026-76440 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20305
  - at: "2026-09-16T17:51:21Z"
    level: L2
    summary: added CVE-2026-20234
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20306
---

This roundup covers 13 Cisco security vulnerabilities. CVSS base scores range from 5.9 to 9.8. None are reported as actively exploited at the time of release. The issues affect AsyncOS Software, Desk Phone 9800 Series, Identity Services Engine, Nexus 9000 Series Switches, Secure Email, Secure Email Gateway, UCS Servers.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-20354](#cve-2026-20354) | Secure Email | Medium | 5.9 | 0.15% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20355](#cve-2026-20355) | Secure Email | Medium | 5.9 | 0.15% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20212](#cve-2026-20212) | Nexus 9000 Series Switches | Critical | 9.8 | 0.53% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9k-s1-rce-EH8dEtr?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Switches%20Silicon%20One%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20281](#cve-2026-20281) | Desk Phone 9800 Series | High | 7.5 | 0.33% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-phone-dos-txMYNRzv?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Desk%20Phone%209800%20Series,%20IP%20Phone%207800%20and%208800%20Series,%20and%20Video%20Phone%208875%20with%20SIP%20Software%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20293](#cve-2026-20293) | UCS Servers | High | 7.1 | 0.13% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20293) (authoritative) |
| [CVE-2026-20353](#cve-2026-20353) | Secure Email Gateway | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20353) (authoritative) |
| [CVE-2026-76440](#cve-2026-76440) | Secure Email Gateway | Critical | 9.8 | 0.43% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76440) (authoritative) |
| [CVE-2026-76441](#cve-2026-76441) | Secure Email Gateway | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76441) (authoritative) |
| [CVE-2026-76443](#cve-2026-76443) | Secure Email Gateway | Critical | 9.8 | 0.37% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76443) (authoritative) |
| [CVE-2026-76461](#cve-2026-76461) | AsyncOS Software | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76461) (authoritative) |
| [CVE-2026-76442](#cve-2026-76442) | Secure Email Gateway | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76442) (authoritative) |
| [CVE-2026-20234](#cve-2026-20234) | Identity Services Engine |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20234) (authoritative) |
| [CVE-2026-20305](#cve-2026-20305) | Identity Services Engine |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20305) (authoritative) |


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

Related in this roundup: [CVE-2026-20305](#cve-2026-20305).

## CVE-2026-20305

CVE-2026-20305 is a command injection vulnerability within the diagnostic tools of Cisco ISE and ISE-PIC. An authenticated remote attacker with administrative credentials can exploit improper input validation via the web-based management interface to execute arbitrary code with root privileges. Successful exploitation may result in a denial of service condition by rendering the affected node unavailable.

Affected products:
- Identity Services Engine
- ISE-PIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20305

Related in this roundup: [CVE-2026-20234](#cve-2026-20234).
