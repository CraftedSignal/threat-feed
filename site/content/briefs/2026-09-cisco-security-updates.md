---
title: Cisco Security Updates - September 2026
slug: 2026-09-cisco-security-updates
description: Roundup of Cisco security advisories published in September 2026.
date: "2026-09-02T18:06:39Z"
lastmod: "2026-09-02T18:06:39Z"
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
updates:
  - at: "2026-09-02T18:06:39Z"
    level: L1
    summary: posted roundup
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1
---

This roundup covers 2 Cisco security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Secure Email.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-20354](#cve-2026-20354) | Secure Email |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20355](#cve-2026-20355) | Secure Email |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-smime-disc-dzw4rEdY?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Secure/Multipurpose%20Internet%20Mail%20Extensions%20Ciphertext%20Decryption%20Vulnerabilities%26vs_k=1) (authoritative) |


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
