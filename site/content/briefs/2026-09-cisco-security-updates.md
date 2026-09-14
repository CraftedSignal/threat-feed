---
title: Cisco Security Updates - September 2026
slug: 2026-09-cisco-security-updates
description: Roundup of Cisco security advisories published in September 2026.
date: "2026-09-02T18:06:39Z"
lastmod: "2026-09-14T17:34:31Z"
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
  - id: CVE-2026-20281
    cvss: 7.5
    epss: 0.00332
  - id: CVE-2026-20293
    product: UCS Servers
    cvss: 7.1
    epss: 0.00132
  - id: CVE-2026-20353
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20353
updates:
  - at: "2026-09-02T18:06:39Z"
    level: L1
    summary: posted roundup
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1
  - at: "2026-09-02T18:06:42Z"
    level: L2
    summary: added CVE-2026-20355
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9k-s1-rce-EH8dEtr?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Switches%20Silicon%20One%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1
  - at: "2026-09-08T17:45:54Z"
    level: L2
    summary: added CVE-2026-20212 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20293
  - at: "2026-09-14T17:34:31Z"
    level: L2
    summary: added CVE-2026-20281 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20353
---

This roundup covers 5 Cisco security vulnerabilities. CVSS base scores range from 5.9 to 9.8. None are reported as actively exploited at the time of release. The issues affect Desk Phone 9800 Series, Nexus 9000 Series Switches, Secure Email, UCS Servers.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-20354](#cve-2026-20354) | Secure Email | Medium | 5.9 | 0.15% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20355](#cve-2026-20355) | Secure Email | Medium | 5.9 | 0.15% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20212](#cve-2026-20212) | Nexus 9000 Series Switches | Critical | 9.8 | 0.53% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9k-s1-rce-EH8dEtr?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Switches%20Silicon%20One%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20281](#cve-2026-20281) | Desk Phone 9800 Series |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-phone-dos-txMYNRzv?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Desk%20Phone%209800%20Series,%20IP%20Phone%207800%20and%208800%20Series,%20and%20Video%20Phone%208875%20with%20SIP%20Software%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20293](#cve-2026-20293) | UCS Servers | High | 7.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20293) (authoritative) |


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
