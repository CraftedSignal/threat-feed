---
title: Cisco Security Updates - September 2026
slug: 2026-09-cisco-security-updates
description: Roundup of Cisco security advisories published in September 2026.
date: "2026-09-02T18:06:39Z"
lastmod: "2026-09-16T21:51:28Z"
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
    epss: 0.00465
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
  - id: CVE-2026-76420
    cvss: 9
  - id: CVE-2024-20260
    product: Secure Firewall Adaptive Security Appliance Software
    cvss: 8.6
    epss: 0.0062
  - id: CVE-2026-20343
    cvss: 7.5
  - id: CVE-2026-20290
    cvss: 5.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20322
updates:
  - at: "2026-09-16T19:19:30Z"
    level: L2
    summary: added CVE-2026-20305, CVE-2026-20307
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-javarce-y2NypXwk?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Java%20Deserialization%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
  - at: "2026-09-16T21:51:22Z"
    level: L2
    summary: added CVE-2026-20290, CVE-2026-20343, CVE-2026-76420
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20176
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20211
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20322
---

This roundup covers 71 Cisco security vulnerabilities. CVSS base scores range from 5.8 to 9.9. None are reported as actively exploited at the time of release. The issues affect Adaptive Security Appliance Software, AsyncOS Software, BroadWorks CommPilot Application Software, Desk Phone 9800 Series, Identity Services Engine, Nexus 9000 Series Switches, Secure Adaptive Security Appliance Software, Secure Email, Secure Email Gateway, Secure FMC Software, Secure Firewall Adaptive Security Appliance Software, Secure Firewall Management Center, Secure Firewall Management Center Software, Secure Firewall Threat Defense Software, ThousandEyes Virtual Appliance, UCS Servers.

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
| [CVE-2026-76441](#cve-2026-76441) | Secure Email Gateway | Critical | 9.8 | 0.46% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76441) (authoritative) |
| [CVE-2026-76443](#cve-2026-76443) | Secure Email Gateway | Critical | 9.8 | 0.37% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76443) (authoritative) |
| [CVE-2026-76461](#cve-2026-76461) | AsyncOS Software | Critical | 9.8 | 2.16% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76461) (authoritative) |
| [CVE-2026-76442](#cve-2026-76442) | Secure Email Gateway | High | 7.5 | 0.33% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76442) (authoritative) |
| [CVE-2026-20234](#cve-2026-20234) | Identity Services Engine | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20234) (authoritative) |
| [CVE-2026-20305](#cve-2026-20305) | Identity Services Engine | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20305) (authoritative) |
| [CVE-2026-20306](#cve-2026-20306) | Identity Services Engine | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20306) (authoritative) |
| [CVE-2026-20307](#cve-2026-20307) | Identity Services Engine | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20307) (authoritative) |
| [CVE-2026-20331](#cve-2026-20331) | Secure Adaptive Security Appliance Software |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20331) (authoritative) |
| [CVE-2026-76420](#cve-2026-76420) | Secure FMC Software | Critical | 9.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76420) (authoritative) |
| [CVE-2026-76460](#cve-2026-76460) | Identity Services Engine |  |  |  | no | [source](https://www.cve.org/CVERecord?id=CVE-2026-76460) (authoritative) |
| [CVE-2024-20260](#cve-2024-20260) | Secure Firewall Adaptive Security Appliance Software | High | 8.6 | 0.62% | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftdvirtual-dos-MuenGnYR?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20SSL%20VPN%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20250](#cve-2026-20250) | Adaptive Security Appliance Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dtls-dos-Kp57HkyO?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20for%20Secure%20Firewall%203100%20and%204200%20Series%20DTLS%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20242](#cve-2026-20242) | Secure Firewall Management Center Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-javarce-y2NypXwk?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Java%20Deserialization%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20282](#cve-2026-20282) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20283](#cve-2026-20283) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20284](#cve-2026-20284) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76423](#cve-2026-76423) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76424](#cve-2026-76424) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76425](#cve-2026-76425) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76426](#cve-2026-76426) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76427](#cve-2026-76427) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76428](#cve-2026-76428) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20352](#cve-2026-20352) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-RADIUS-dos-wR3hYPMw?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20RADIUS%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20295](#cve-2026-20295) | Secure Firewall Management Center Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmcftd-sftun-multivulns-WGVHOrN3?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20sftunnel%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20323](#cve-2026-20323) | Secure Firewall Management Center Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmcftd-sftun-multivulns-WGVHOrN3?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20sftunnel%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20135](#cve-2026-20135) | Secure Firewall Threat Defense Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tls1.3-dos-dLxwFWgF?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Threat%20Defense%20Software%20TLS%201.3%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20071](#cve-2026-20071) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-vuln-kWLeNnRD?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20802.1X%20Session%20Hijack%20and%20Information%20Disclosure%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20072](#cve-2026-20072) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-vuln-kWLeNnRD?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20802.1X%20Session%20Hijack%20and%20Information%20Disclosure%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20340](#cve-2026-20340) | Secure Firewall Management Center |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20341](#cve-2026-20341) | Secure Firewall Management Center |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20342](#cve-2026-20342) | Secure Firewall Management Center |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20343](#cve-2026-20343) | Secure Firewall Management Center |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20344](#cve-2026-20344) | Secure Firewall Management Center |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20248](#cve-2026-20248) | Secure Firewall Adaptive Security Appliance Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tcpdns-dos-p6dUnjr5?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20TCP%20DNS%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20350](#cve-2026-20350) | ThousandEyes Virtual Appliance |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-teva-os-command-W4GAO6jp?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20ThousandEyes%20Virtual%20Appliance%20Authenticated%20Web%20Interface%20Command%20Injection%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20290](#cve-2026-20290) | Secure Firewall Threat Defense Software | Medium | 5.8 |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-snort2-ssldos-Mw7WYX9c?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Threat%20Defense%20Software%20Snort%202%20SSL/TLS%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-76431](#cve-2026-76431) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-traversal-WDTgYCdn?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Multiple%20Path%20Traversal%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76432](#cve-2026-76432) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-traversal-WDTgYCdn?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Multiple%20Path%20Traversal%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76433](#cve-2026-76433) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-traversal-WDTgYCdn?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Multiple%20Path%20Traversal%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76434](#cve-2026-76434) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-traversal-WDTgYCdn?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Multiple%20Path%20Traversal%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20309](#cve-2026-20309) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-Uz9VWRQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Cross-Site%20Scripting%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20120](#cve-2026-20120) | Secure Firewall Adaptive Security Appliance Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-acl-bypass-8p6vFvw?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20Object%20Group%20Access%20Control%20List%20Bypass%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20121](#cve-2026-20121) | Secure Firewall Adaptive Security Appliance Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-acl-bypass-8p6vFvw?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20Object%20Group%20Access%20Control%20List%20Bypass%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20285](#cve-2026-20285) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-auth-bypass-1-MxcTNgwx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authorization%20Bypass%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20286](#cve-2026-20286) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-auth-bypass-1-MxcTNgwx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authorization%20Bypass%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76438](#cve-2026-76438) | BroadWorks CommPilot Application Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-auth-bypass-broadwor-57m9dmm5?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20BroadWorks%20CommPilot%20Application%20Software%20Authorization%20Bypass%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20222](#cve-2026-20222) | Secure Firewall Adaptive Security Appliance Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-eigrp-dos-GOhNejSj?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20EIGRP%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20154](#cve-2026-20154) | Secure Firewall Adaptive Security Appliance Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-logging-dos-ZXXNesfN?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20Logging%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-76439](#cve-2026-76439) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authentication%20Bypass%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76444](#cve-2026-76444) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authentication%20Bypass%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76446](#cve-2026-76446) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authentication%20Bypass%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76447](#cve-2026-76447) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authentication%20Bypass%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20249](#cve-2026-20249) | Secure Firewall Adaptive Security Appliance Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ikev2cert-dos-uWyc2xtv?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20IKEv2%20Certificate%20Authentication%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-76448](#cve-2026-76448) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multisql-inject-JnHK54Rq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20and%20HQL%20Injection%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76449](#cve-2026-76449) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multisql-inject-JnHK54Rq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20and%20HQL%20Injection%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76450](#cve-2026-76450) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multisql-inject-JnHK54Rq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20and%20HQL%20Injection%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76451](#cve-2026-76451) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multisql-inject-JnHK54Rq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20and%20HQL%20Injection%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20247](#cve-2026-20247) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-sql-inj-3QTKR947?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20Injection%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20300](#cve-2026-20300) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-sql-inj-3QTKR947?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20Injection%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-20324](#cve-2026-20324) | Secure Firewall Management Center Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-sftunn-codex-c3O4Jft2?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20sftunnel%20Root%20Arbitrary%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20235](#cve-2026-20235) | Identity Services Engine |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-inf-disc-LFWvcCu?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Information%20Disclosure%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20176](#cve-2026-20176) | Identity Services Engine |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20176) (authoritative) |
| [CVE-2026-20211](#cve-2026-20211) | Identity Services Engine |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20211) (authoritative) |


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


































Related in this roundup: [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20305

CVE-2026-20305 is a command injection vulnerability within the diagnostic tools of Cisco ISE and ISE-PIC. An authenticated remote attacker with administrative credentials can exploit improper input validation via the web-based management interface to execute arbitrary code with root privileges. Successful exploitation may result in a denial of service condition by rendering the affected node unavailable.

Affected products:
- Identity Services Engine
- ISE-PIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20305


































Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20306

CVE-2026-20306 is a command injection vulnerability in the REST API of Cisco Identity Services Engine (ISE) and ISE-PIC. An authenticated remote attacker with administrative credentials can supply crafted commands to the management interface, leading to arbitrary code execution with root privileges or a denial-of-service condition.

Affected products:
- Identity Services Engine
- ISE-PIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20306

































Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20307

CVE-2026-20307 is a critical remote code execution vulnerability in the web management interface of Cisco Identity Services Engine (ISE). The vulnerability arises from insecure deserialization of Java byte streams, allowing an authenticated, low-privileged administrator to execute arbitrary commands as root on the underlying operating system. Successful exploitation can lead to full system compromise or a denial of service condition affecting network authentication.

Affected products:
- Identity Services Engine

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20307
































Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

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





























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2024-20260

A vulnerability in the VPN and management web servers of Cisco Secure Firewall ASA and FTD software allows an unauthenticated remote attacker to cause a denial of service (DoS) by sending a high volume of SSL/TLS connection requests. The attack depletes system memory or buffer blocks, causing connection processing to slow down or fail entirely. A manual reload may be required to restore services.

Affected products:
- Secure Firewall Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftdvirtual-dos-MuenGnYR?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20SSL%20VPN%20Denial%20of%20Service%20Vulnerability%26vs_k=1


















Related in this roundup: [CVE-2026-20248](#cve-2026-20248), [CVE-2026-20120](#cve-2026-20120), [CVE-2026-20121](#cve-2026-20121), [CVE-2026-20222](#cve-2026-20222), [CVE-2026-20154](#cve-2026-20154), [CVE-2026-20249](#cve-2026-20249).

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






















Related in this roundup: [CVE-2026-20295](#cve-2026-20295), [CVE-2026-20323](#cve-2026-20323), [CVE-2026-20324](#cve-2026-20324).

## CVE-2026-20282

Cisco Identity Services Engine (ISE) contains multiple vulnerabilities allowing authenticated, remote attackers to perform SQL injections, modify database contents, and execute arbitrary operating system commands. These vulnerabilities are particularly severe as they can be leveraged to escalate privileges to the root level on the affected device.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1

























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20283

Cisco Identity Services Engine (ISE) contains multiple vulnerabilities allowing authenticated, remote attackers to perform SQL injections, modify database contents, and execute arbitrary operating system commands. These vulnerabilities are particularly severe as they can be leveraged to escalate privileges to the root level on the affected device.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1

























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20284

Cisco Identity Services Engine (ISE) contains multiple vulnerabilities allowing authenticated, remote attackers to perform SQL injections, modify database contents, and execute arbitrary operating system commands. These vulnerabilities are particularly severe as they can be leveraged to escalate privileges to the root level on the affected device.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-mult-vul-ymSsTLCc?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authenticated%20Remote%20Code%20Execution%20and%20API%20Vulnerabilities%26vs_k=1

























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76423

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector are vulnerable to multiple critical security flaws, including authentication bypass, remote code execution (RCE), SQL injection, and XML External Entity (XXE) injection via the REST API. These vulnerabilities allow unauthenticated remote attackers to compromise the appliance. Organizations are advised to apply the provided software updates immediately, as no workarounds are available.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76424

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector are vulnerable to multiple critical security flaws, including authentication bypass, remote code execution (RCE), SQL injection, and XML External Entity (XXE) injection via the REST API. These vulnerabilities allow unauthenticated remote attackers to compromise the appliance. Organizations are advised to apply the provided software updates immediately, as no workarounds are available.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76425

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector are vulnerable to multiple critical security flaws, including authentication bypass, remote code execution (RCE), SQL injection, and XML External Entity (XXE) injection via the REST API. These vulnerabilities allow unauthenticated remote attackers to compromise the appliance. Organizations are advised to apply the provided software updates immediately, as no workarounds are available.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76426

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector are vulnerable to multiple critical security flaws, including authentication bypass, remote code execution (RCE), SQL injection, and XML External Entity (XXE) injection via the REST API. These vulnerabilities allow unauthenticated remote attackers to compromise the appliance. Organizations are advised to apply the provided software updates immediately, as no workarounds are available.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76427

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector are vulnerable to multiple critical security flaws, including authentication bypass, remote code execution (RCE), SQL injection, and XML External Entity (XXE) injection via the REST API. These vulnerabilities allow unauthenticated remote attackers to compromise the appliance. Organizations are advised to apply the provided software updates immediately, as no workarounds are available.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76428

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector are vulnerable to multiple critical security flaws, including authentication bypass, remote code execution (RCE), SQL injection, and XML External Entity (XXE) injection via the REST API. These vulnerabilities allow unauthenticated remote attackers to compromise the appliance. Organizations are advised to apply the provided software updates immediately, as no workarounds are available.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-hrP9jQSQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Vulnerabilities%26vs_k=1
























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20352

A vulnerability in the RADIUS implementation of Cisco Identity Services Engine (ISE) allows an unauthenticated, remote attacker to trigger a denial of service (DoS) by sending a specially crafted RADIUS request. This exploit can cause the ISE node to become unresponsive, effectively preventing new authentication attempts until the service recovers.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-RADIUS-dos-wR3hYPMw?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20RADIUS%20Denial%20of%20Service%20Vulnerability%26vs_k=1























Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20295

Cisco Secure Firewall Management Center (FMC) and Secure Firewall Threat Defense (FTD) software contain multiple vulnerabilities in the sftunnel component. These vulnerabilities allow an unauthenticated attacker to bypass authentication or trigger a denial of service (DoS) condition on affected devices. There are no known workarounds, and users are advised to apply the software updates provided by Cisco.

Affected products:
- Secure Firewall Management Center Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmcftd-sftun-multivulns-WGVHOrN3?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20sftunnel%20Vulnerabilities%26vs_k=1






















Related in this roundup: [CVE-2026-20242](#cve-2026-20242), [CVE-2026-20323](#cve-2026-20323), [CVE-2026-20324](#cve-2026-20324).

## CVE-2026-20323

Cisco Secure Firewall Management Center (FMC) and Secure Firewall Threat Defense (FTD) software contain multiple vulnerabilities in the sftunnel component. These vulnerabilities allow an unauthenticated attacker to bypass authentication or trigger a denial of service (DoS) condition on affected devices. There are no known workarounds, and users are advised to apply the software updates provided by Cisco.

Affected products:
- Secure Firewall Management Center Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmcftd-sftun-multivulns-WGVHOrN3?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20sftunnel%20Vulnerabilities%26vs_k=1






















Related in this roundup: [CVE-2026-20242](#cve-2026-20242), [CVE-2026-20295](#cve-2026-20295), [CVE-2026-20324](#cve-2026-20324).

## CVE-2026-20135

A vulnerability in the TLS 1.3 implementation of Cisco Secure Firewall Threat Defense (FTD) Software due to improper buffer management allows an unauthenticated, remote attacker to trigger a crash of the LINA process. Exploitation involves sending a crafted TLS 1.3 packet to a listening socket, resulting in an unexpected device reload and a denial of service condition.

Affected products:
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tls1.3-dos-dLxwFWgF?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Threat%20Defense%20Software%20TLS%201.3%20Denial%20of%20Service%20Vulnerability%26vs_k=1
















Related in this roundup: [CVE-2026-20290](#cve-2026-20290).

## CVE-2026-20071

Cisco Identity Services Engine (ISE) is affected by multiple vulnerabilities that allow an unauthenticated, local attacker to perform authentication bypass or disclose sensitive information. These issues relate to 802.1X session management and security hardening. Cisco has released software updates to remediate these flaws.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-vuln-kWLeNnRD?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20802.1X%20Session%20Hijack%20and%20Information%20Disclosure%20Vulnerabilities%26vs_k=1




















Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20072

Cisco Identity Services Engine (ISE) is affected by multiple vulnerabilities that allow an unauthenticated, local attacker to perform authentication bypass or disclose sensitive information. These issues relate to 802.1X session management and security hardening. Cisco has released software updates to remediate these flaws.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-vuln-kWLeNnRD?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20802.1X%20Session%20Hijack%20and%20Information%20Disclosure%20Vulnerabilities%26vs_k=1




















Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20340

Multiple vulnerabilities in Cisco Secure Firewall Management Center (FMC) Software allow remote attackers to achieve root-level system access, perform unauthorized sensitive file downloads, execute SQL injection attacks, or trigger denial-of-service conditions. No workarounds are available, necessitating immediate application of vendor-provided software updates.

Affected products:
- Secure Firewall Management Center

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1



















Related in this roundup: [CVE-2026-20341](#cve-2026-20341), [CVE-2026-20342](#cve-2026-20342), [CVE-2026-20343](#cve-2026-20343), [CVE-2026-20344](#cve-2026-20344).

## CVE-2026-20341

Multiple vulnerabilities in Cisco Secure Firewall Management Center (FMC) Software allow remote attackers to achieve root-level system access, perform unauthorized sensitive file downloads, execute SQL injection attacks, or trigger denial-of-service conditions. No workarounds are available, necessitating immediate application of vendor-provided software updates.

Affected products:
- Secure Firewall Management Center

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1



















Related in this roundup: [CVE-2026-20340](#cve-2026-20340), [CVE-2026-20342](#cve-2026-20342), [CVE-2026-20343](#cve-2026-20343), [CVE-2026-20344](#cve-2026-20344).

## CVE-2026-20342

Multiple vulnerabilities in Cisco Secure Firewall Management Center (FMC) Software allow remote attackers to achieve root-level system access, perform unauthorized sensitive file downloads, execute SQL injection attacks, or trigger denial-of-service conditions. No workarounds are available, necessitating immediate application of vendor-provided software updates.

Affected products:
- Secure Firewall Management Center

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1



















Related in this roundup: [CVE-2026-20340](#cve-2026-20340), [CVE-2026-20341](#cve-2026-20341), [CVE-2026-20343](#cve-2026-20343), [CVE-2026-20344](#cve-2026-20344).

## CVE-2026-20343

Multiple vulnerabilities in Cisco Secure Firewall Management Center (FMC) Software allow remote attackers to achieve root-level system access, perform unauthorized sensitive file downloads, execute SQL injection attacks, or trigger denial-of-service conditions. No workarounds are available, necessitating immediate application of vendor-provided software updates.

Affected products:
- Secure Firewall Management Center

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1



















Related in this roundup: [CVE-2026-20340](#cve-2026-20340), [CVE-2026-20341](#cve-2026-20341), [CVE-2026-20342](#cve-2026-20342), [CVE-2026-20344](#cve-2026-20344).

## CVE-2026-20344

Multiple vulnerabilities in Cisco Secure Firewall Management Center (FMC) Software allow remote attackers to achieve root-level system access, perform unauthorized sensitive file downloads, execute SQL injection attacks, or trigger denial-of-service conditions. No workarounds are available, necessitating immediate application of vendor-provided software updates.

Affected products:
- Secure Firewall Management Center

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-mulivulns-4PsnFwvx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Vulnerabilities%26vs_k=1



















Related in this roundup: [CVE-2026-20340](#cve-2026-20340), [CVE-2026-20341](#cve-2026-20341), [CVE-2026-20342](#cve-2026-20342), [CVE-2026-20343](#cve-2026-20343).

## CVE-2026-20248

A logic error in the DNS over TCP implementation within Cisco Secure Firewall ASA and FTD software allows an unauthenticated remote attacker to trigger a device reload via a crafted DNS response. This vulnerability requires the attacker to be able to respond to DNS queries from the target device, potentially through a man-in-the-middle position or by controlling the DNS service, resulting in a denial-of-service condition.

Affected products:
- Secure Firewall Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tcpdns-dos-p6dUnjr5?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20TCP%20DNS%20Denial%20of%20Service%20Vulnerability%26vs_k=1


















Related in this roundup: [CVE-2024-20260](#cve-2024-20260), [CVE-2026-20120](#cve-2026-20120), [CVE-2026-20121](#cve-2026-20121), [CVE-2026-20222](#cve-2026-20222), [CVE-2026-20154](#cve-2026-20154), [CVE-2026-20249](#cve-2026-20249).

## CVE-2026-20350

Cisco ThousandEyes Virtual Appliance contains an OS command injection vulnerability in its web-based management interface. An authenticated attacker with administrative credentials can supply malicious input during configuration to execute arbitrary commands with root privileges.

Affected products:
- ThousandEyes Virtual Appliance

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-teva-os-command-W4GAO6jp?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20ThousandEyes%20Virtual%20Appliance%20Authenticated%20Web%20Interface%20Command%20Injection%20Vulnerability%26vs_k=1

## CVE-2026-20290

A vulnerability in the Snort 2 Detection Engine of Cisco Secure Firewall Threat Defense (FTD) Software arises from incomplete SSL/TLS certificate validation. An unauthenticated remote attacker can exploit this by sending a crafted SSL connection setup request, causing the Snort 2 process to restart unexpectedly and resulting in a denial of service condition.

Affected products:
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-snort2-ssldos-Mw7WYX9c?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Threat%20Defense%20Software%20Snort%202%20SSL/TLS%20Denial%20of%20Service%20Vulnerability%26vs_k=1
















Related in this roundup: [CVE-2026-20135](#cve-2026-20135).

## CVE-2026-76431

Multiple path traversal vulnerabilities exist in Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC), potentially allowing a remote attacker to read or access sensitive files on an affected device. Cisco has released software updates to address these vulnerabilities; there are no known workarounds.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-traversal-WDTgYCdn?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Multiple%20Path%20Traversal%20Vulnerabilities%26vs_k=1















Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76432

Multiple path traversal vulnerabilities exist in Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC), potentially allowing a remote attacker to read or access sensitive files on an affected device. Cisco has released software updates to address these vulnerabilities; there are no known workarounds.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-traversal-WDTgYCdn?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Multiple%20Path%20Traversal%20Vulnerabilities%26vs_k=1















Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76433

Multiple path traversal vulnerabilities exist in Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC), potentially allowing a remote attacker to read or access sensitive files on an affected device. Cisco has released software updates to address these vulnerabilities; there are no known workarounds.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-traversal-WDTgYCdn?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Multiple%20Path%20Traversal%20Vulnerabilities%26vs_k=1















Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76434

Multiple path traversal vulnerabilities exist in Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC), potentially allowing a remote attacker to read or access sensitive files on an affected device. Cisco has released software updates to address these vulnerabilities; there are no known workarounds.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-traversal-WDTgYCdn?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Multiple%20Path%20Traversal%20Vulnerabilities%26vs_k=1















Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20309

Cisco Identity Services Engine (ISE) is vulnerable to a reflected cross-site scripting (XSS) attack due to improper validation of user-supplied input in its web-based management interface. An unauthenticated remote attacker can exploit this by enticing an authenticated user to click a crafted link, potentially allowing the execution of arbitrary script code within the context of the interface or unauthorized access to sensitive browser-based information.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-Uz9VWRQ?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Cross-Site%20Scripting%20Vulnerability%26vs_k=1














Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20120

Multiple vulnerabilities in the Object Group Search (OGS) implementation of Cisco Secure Firewall ASA and FTD software allow unauthenticated, remote attackers to bypass access control lists. The vulnerabilities stem from a logic error in how group access control policies are populated, potentially allowing traffic that should be blocked to pass through the device to protected networks.

Affected products:
- Secure Firewall Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-acl-bypass-8p6vFvw?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20Object%20Group%20Access%20Control%20List%20Bypass%20Vulnerabilities%26vs_k=1













Related in this roundup: [CVE-2024-20260](#cve-2024-20260), [CVE-2026-20248](#cve-2026-20248), [CVE-2026-20121](#cve-2026-20121), [CVE-2026-20222](#cve-2026-20222), [CVE-2026-20154](#cve-2026-20154), [CVE-2026-20249](#cve-2026-20249).

## CVE-2026-20121

Multiple vulnerabilities in the Object Group Search (OGS) implementation of Cisco Secure Firewall ASA and FTD software allow unauthenticated, remote attackers to bypass access control lists. The vulnerabilities stem from a logic error in how group access control policies are populated, potentially allowing traffic that should be blocked to pass through the device to protected networks.

Affected products:
- Secure Firewall Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-acl-bypass-8p6vFvw?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20Object%20Group%20Access%20Control%20List%20Bypass%20Vulnerabilities%26vs_k=1













Related in this roundup: [CVE-2024-20260](#cve-2024-20260), [CVE-2026-20248](#cve-2026-20248), [CVE-2026-20120](#cve-2026-20120), [CVE-2026-20222](#cve-2026-20222), [CVE-2026-20154](#cve-2026-20154), [CVE-2026-20249](#cve-2026-20249).

## CVE-2026-20285

Multiple authorization bypass vulnerabilities exist in the web-based management interface of Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC). The vulnerabilities stem from insufficient server-side validation of Administrator permissions. An authenticated remote attacker possessing valid Administrator credentials can exploit these flaws by submitting crafted HTTP requests to modify file descriptions on specific system pages.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-auth-bypass-1-MxcTNgwx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authorization%20Bypass%20Vulnerabilities%26vs_k=1












Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20286

Multiple authorization bypass vulnerabilities exist in the web-based management interface of Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC). The vulnerabilities stem from insufficient server-side validation of Administrator permissions. An authenticated remote attacker possessing valid Administrator credentials can exploit these flaws by submitting crafted HTTP requests to modify file descriptions on specific system pages.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-auth-bypass-1-MxcTNgwx?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authorization%20Bypass%20Vulnerabilities%26vs_k=1












Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76438

A vulnerability in the web-based management interface of Cisco BroadWorks CommPilot Application Software allows authenticated remote attackers with low privileges to bypass authorization checks and modify device configurations via crafted HTTP requests.

Affected products:
- BroadWorks CommPilot Application Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-auth-bypass-broadwor-57m9dmm5?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20BroadWorks%20CommPilot%20Application%20Software%20Authorization%20Bypass%20Vulnerability%26vs_k=1

## CVE-2026-20222

A vulnerability in the EIGRP implementation of Cisco Secure Firewall ASA and FTD software allows an unauthenticated, adjacent attacker to trigger a memory leak by sending crafted EIGRP update messages at a high rate. This can lead to an unexpected device reload and a denial of service condition.

Affected products:
- Secure Firewall Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-eigrp-dos-GOhNejSj?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20EIGRP%20Denial%20of%20Service%20Vulnerability%26vs_k=1










Related in this roundup: [CVE-2024-20260](#cve-2024-20260), [CVE-2026-20248](#cve-2026-20248), [CVE-2026-20120](#cve-2026-20120), [CVE-2026-20121](#cve-2026-20121), [CVE-2026-20154](#cve-2026-20154), [CVE-2026-20249](#cve-2026-20249).

## CVE-2026-20154

A denial of service (DoS) vulnerability exists in Cisco Secure Firewall ASA and FTD software due to improper rate limiting for syslog message 419002. An unauthenticated, remote attacker can exploit this by sending a flood of TCP SYN packets, causing high CPU utilization and performance degradation on the affected appliance.

Affected products:
- Secure Firewall Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-logging-dos-ZXXNesfN?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20Logging%20Denial%20of%20Service%20Vulnerability%26vs_k=1









Related in this roundup: [CVE-2024-20260](#cve-2024-20260), [CVE-2026-20248](#cve-2026-20248), [CVE-2026-20120](#cve-2026-20120), [CVE-2026-20121](#cve-2026-20121), [CVE-2026-20222](#cve-2026-20222), [CVE-2026-20249](#cve-2026-20249).

## CVE-2026-76439

Multiple authentication bypass vulnerabilities exist in Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC). These vulnerabilities could allow a remote attacker to manipulate data, access sensitive information, or trigger a reload of certificate and key material on affected devices. There are no workarounds; patching is required.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authentication%20Bypass%20Vulnerabilities%26vs_k=1








Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76444

Multiple authentication bypass vulnerabilities exist in Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC). These vulnerabilities could allow a remote attacker to manipulate data, access sensitive information, or trigger a reload of certificate and key material on affected devices. There are no workarounds; patching is required.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authentication%20Bypass%20Vulnerabilities%26vs_k=1








Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76446

Multiple authentication bypass vulnerabilities exist in Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC). These vulnerabilities could allow a remote attacker to manipulate data, access sensitive information, or trigger a reload of certificate and key material on affected devices. There are no workarounds; patching is required.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authentication%20Bypass%20Vulnerabilities%26vs_k=1








Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76447

Multiple authentication bypass vulnerabilities exist in Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC). These vulnerabilities could allow a remote attacker to manipulate data, access sensitive information, or trigger a reload of certificate and key material on affected devices. There are no workarounds; patching is required.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Authentication%20Bypass%20Vulnerabilities%26vs_k=1








Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20249

A logic error exists in the IKEv2 certificate authentication process of Cisco Secure Firewall Adaptive Security Appliance (ASA) and Threat Defense (FTD) software. An unauthenticated remote attacker can exploit this by sending a crafted certificate during the IKEv2 connection setup, causing the IKEv2 process to crash and resulting in a device reload and denial of service condition.

Affected products:
- Secure Firewall Adaptive Security Appliance Software
- Secure Firewall Threat Defense Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ikev2cert-dos-uWyc2xtv?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20and%20Secure%20Firewall%20Threat%20Defense%20Software%20IKEv2%20Certificate%20Authentication%20Denial%20of%20Service%20Vulnerability%26vs_k=1







Related in this roundup: [CVE-2024-20260](#cve-2024-20260), [CVE-2026-20248](#cve-2026-20248), [CVE-2026-20120](#cve-2026-20120), [CVE-2026-20121](#cve-2026-20121), [CVE-2026-20222](#cve-2026-20222), [CVE-2026-20154](#cve-2026-20154).

## CVE-2026-76448

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC) contain multiple vulnerabilities due to improper input validation in APIs. An authenticated remote attacker with administrative credentials can exploit these flaws to perform SQL or HQL injection, allowing unauthorized data access or modification in the underlying database.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multisql-inject-JnHK54Rq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20and%20HQL%20Injection%20Vulnerabilities%26vs_k=1






Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76449

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC) contain multiple vulnerabilities due to improper input validation in APIs. An authenticated remote attacker with administrative credentials can exploit these flaws to perform SQL or HQL injection, allowing unauthorized data access or modification in the underlying database.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multisql-inject-JnHK54Rq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20and%20HQL%20Injection%20Vulnerabilities%26vs_k=1






Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76450

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC) contain multiple vulnerabilities due to improper input validation in APIs. An authenticated remote attacker with administrative credentials can exploit these flaws to perform SQL or HQL injection, allowing unauthorized data access or modification in the underlying database.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multisql-inject-JnHK54Rq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20and%20HQL%20Injection%20Vulnerabilities%26vs_k=1






Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-76451

Cisco Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC) contain multiple vulnerabilities due to improper input validation in APIs. An authenticated remote attacker with administrative credentials can exploit these flaws to perform SQL or HQL injection, allowing unauthorized data access or modification in the underlying database.

Affected products:
- Identity Services Engine
- ISE Passive Identity Connector

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multisql-inject-JnHK54Rq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20and%20HQL%20Injection%20Vulnerabilities%26vs_k=1






Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20247

Multiple SQL injection vulnerabilities exist in Cisco Identity Services Engine (ISE) that allow a remote attacker to execute arbitrary SQL commands on the affected device. These vulnerabilities are addressed in official software updates provided by Cisco.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-sql-inj-3QTKR947?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20Injection%20Vulnerabilities%26vs_k=1





Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20300

Multiple SQL injection vulnerabilities exist in Cisco Identity Services Engine (ISE) that allow a remote attacker to execute arbitrary SQL commands on the affected device. These vulnerabilities are addressed in official software updates provided by Cisco.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-sql-inj-3QTKR947?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20SQL%20Injection%20Vulnerabilities%26vs_k=1





Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20324

A vulnerability in the sftunnel inter-device communication protocol of Cisco Secure Firewall Management Center (FMC) Software allows an authenticated, remote attacker to execute arbitrary commands as root. The issue stems from improper file system permissions granted to registered sftunnel peers, enabling the writing and subsequent execution of malicious files. Successful exploitation requires valid user credentials on the affected device.

Affected products:
- Secure Firewall Management Center Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-sftunn-codex-c3O4Jft2?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20sftunnel%20Root%20Arbitrary%20Code%20Execution%20Vulnerability%26vs_k=1




Related in this roundup: [CVE-2026-20242](#cve-2026-20242), [CVE-2026-20295](#cve-2026-20295), [CVE-2026-20323](#cve-2026-20323).

## CVE-2026-20235

An information disclosure vulnerability in the Cisco Identity Services Engine (ISE) API allows an authenticated remote attacker with administrative credentials to access sensitive data, including hashed credentials, by sending crafted API requests. The vulnerability stems from improper validation of user-supplied parameters.

Affected products:
- Identity Services Engine

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-inf-disc-LFWvcCu?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Information%20Disclosure%20Vulnerability%26vs_k=1



Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20176](#cve-2026-20176), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20176

CVE-2026-20176 is a command injection vulnerability in Cisco Identity Services Engine (ISE) arising from insufficient validation of user-supplied input in HTTP requests. Authenticated, high-privileged remote attackers can leverage this flaw to execute arbitrary system-level commands on the underlying OS, potentially leading to privilege escalation to root or a Denial of Service (DoS) condition on single-node deployments.

Affected products:
- Identity Services Engine

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20176


Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20211](#cve-2026-20211).

## CVE-2026-20211

Cisco Identity Services Engine (ISE) is susceptible to a remote code execution vulnerability caused by insecure deserialization of Java objects. An authenticated, high-privileged attacker can exploit this by sending a crafted serialized object to the device, leading to arbitrary command execution on the underlying OS, privilege escalation to root, and potential denial-of-service in single-node deployments.

Affected products:
- Identity Services Engine

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20211

Related in this roundup: [CVE-2026-20234](#cve-2026-20234), [CVE-2026-20305](#cve-2026-20305), [CVE-2026-20306](#cve-2026-20306), [CVE-2026-20307](#cve-2026-20307), [CVE-2026-76460](#cve-2026-76460), [CVE-2026-20282](#cve-2026-20282), [CVE-2026-20283](#cve-2026-20283), [CVE-2026-20284](#cve-2026-20284), [CVE-2026-76423](#cve-2026-76423), [CVE-2026-76424](#cve-2026-76424), [CVE-2026-76425](#cve-2026-76425), [CVE-2026-76426](#cve-2026-76426), [CVE-2026-76427](#cve-2026-76427), [CVE-2026-76428](#cve-2026-76428), [CVE-2026-20352](#cve-2026-20352), [CVE-2026-20071](#cve-2026-20071), [CVE-2026-20072](#cve-2026-20072), [CVE-2026-76431](#cve-2026-76431), [CVE-2026-76432](#cve-2026-76432), [CVE-2026-76433](#cve-2026-76433), [CVE-2026-76434](#cve-2026-76434), [CVE-2026-20309](#cve-2026-20309), [CVE-2026-20285](#cve-2026-20285), [CVE-2026-20286](#cve-2026-20286), [CVE-2026-76439](#cve-2026-76439), [CVE-2026-76444](#cve-2026-76444), [CVE-2026-76446](#cve-2026-76446), [CVE-2026-76447](#cve-2026-76447), [CVE-2026-76448](#cve-2026-76448), [CVE-2026-76449](#cve-2026-76449), [CVE-2026-76450](#cve-2026-76450), [CVE-2026-76451](#cve-2026-76451), [CVE-2026-20247](#cve-2026-20247), [CVE-2026-20300](#cve-2026-20300), [CVE-2026-20235](#cve-2026-20235), [CVE-2026-20176](#cve-2026-20176).
