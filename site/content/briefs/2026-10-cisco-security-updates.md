---
title: Cisco Security Updates - October 2026
slug: 2026-10-cisco-security-updates
description: Roundup of Cisco security advisories published in October 2026.
date: "2026-10-07T17:00:15Z"
lastmod: "2026-10-07T18:45:58Z"
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
  - id: CVE-2026-76471
    cvss: 9.8
  - id: CVE-2026-20173
    product: NX-OS Software
    cvss: 5.8
  - id: CVE-2026-20328
    cvss: 9.1
  - id: CVE-2026-76454
    cvss: 9.1
  - id: CVE-2026-76453
    cvss: 8.8
  - id: CVE-2026-76456
    cvss: 8.6
  - id: CVE-2026-76458
    product: NX-OS
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76459
updates:
  - at: "2026-10-07T17:01:46Z"
    level: L2
    summary: added CVE-2026-20173
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-nscpdos-SnderkC7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Control%20Plane%20Denial%20of%20Service%20Vulnerability%26vs_k=1
  - at: "2026-10-07T18:45:21Z"
    level: L2
    summary: added CVE-2026-20328
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20328
  - at: "2026-10-07T18:45:36Z"
    level: L2
    summary: added CVE-2026-20328 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76455
  - at: "2026-10-07T18:45:55Z"
    level: L2
    summary: added CVE-2026-76453 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76458
  - at: "2026-10-07T18:45:58Z"
    level: L2
    summary: added CVE-2026-76456
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76459
---

This roundup covers 18 Cisco security vulnerabilities. CVSS base scores range from 5.8 to 9.8. None are reported as actively exploited at the time of release. The issues affect Application Policy Infrastructure Controller, Cisco networking, Finesse, License On-Prem, NX-OS, NX-OS Software, Nexus 3000 Series Switches, Nexus 9000 Series Fabric Switches.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-20032](#cve-2026-20032) | NX-OS Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-mppe-dhKZAFgb?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Python%20Sandbox%20Escape%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20362](#cve-2026-20362) | Finesse |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-mmSuyugS?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Finesse%20Server-Side%20Request%20Forgery%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-76465](#cve-2026-76465) | Nexus 3000 Series Switches |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-moam-rce-uBTzYV7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20MPLS%20OAM%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-76488](#cve-2026-76488) | Application Policy Infrastructure Controller |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-info-priv-enAdB5vD?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Application%20Policy%20Infrastructure%20Controller%20Unauthorized%20File%20Access%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20321](#cve-2026-20321) | Application Policy Infrastructure Controller |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-cmdinj-L6VR4E7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Application%20Policy%20Infrastructure%20Controller%20API%20Command%20Injection%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20038](#cve-2026-20038) | Nexus 9000 Series Fabric Switches |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aci-epgcbp-SfDU7NLf?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Fabric%20Switches%20in%20ACI%20Mode%20Endpoint%20Group%20Contract%20Bypass%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-76485](#cve-2026-76485) | Nexus 3000 Series Switches |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngoam-rce-LWKQ4BU?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20NGOAM%20Remote%20Code%20Execution%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76486](#cve-2026-76486) | Nexus 3000 Series Switches |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngoam-rce-LWKQ4BU?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20NGOAM%20Remote%20Code%20Execution%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76501](#cve-2026-76501) | Nexus 3000 Series Switches |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngoam-rce-LWKQ4BU?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20NGOAM%20Remote%20Code%20Execution%20Vulnerabilities%26vs_k=1) (authoritative) |
| [CVE-2026-76471](#cve-2026-76471) | NX-OS Software | Critical | 9.8 |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-napi-rce-r2shwu2j?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20NX-API%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20173](#cve-2026-20173) | NX-OS Software | Medium | 5.8 |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-nscpdos-SnderkC7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Control%20Plane%20Denial%20of%20Service%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20328](#cve-2026-20328) | License On-Prem | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20328) (authoritative) |
| [CVE-2026-76454](#cve-2026-76454) | License On-Prem | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76454) (authoritative) |
| [CVE-2026-76455](#cve-2026-76455) | NX-OS |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76455) (authoritative) |
| [CVE-2026-76464](#cve-2026-76464) | Cisco networking |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76464) (authoritative) |
| [CVE-2026-76453](#cve-2026-76453) | NX-OS | High | 8.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76453) (authoritative) |
| [CVE-2026-76456](#cve-2026-76456) | NX-OS |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76456) (authoritative) |
| [CVE-2026-76458](#cve-2026-76458) | NX-OS | High | 8.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76458) (authoritative) |


## CVE-2026-20032

A sandbox escape vulnerability exists within the Python interpreter of Cisco NX-OS Software. An authenticated local attacker with low privileges and Python execution rights can exploit insufficient input validation to escape the sandbox and execute arbitrary commands on the underlying operating system with the privileges of the authenticated user.

Affected products:
- NX-OS Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-mppe-dhKZAFgb?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Python%20Sandbox%20Escape%20Vulnerability%26vs_k=1









Related in this roundup: [CVE-2026-76471](#cve-2026-76471), [CVE-2026-20173](#cve-2026-20173).

## CVE-2026-20362

Cisco Finesse contains a server-side request forgery (SSRF) vulnerability in its web-based management interface. An unauthenticated remote attacker can exploit improper input validation of crafted HTTP requests to perform unauthorized requests from the device, potentially allowing the exfiltration of sensitive information from associated internal services.

Affected products:
- Finesse

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-mmSuyugS?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Finesse%20Server-Side%20Request%20Forgery%20Vulnerability%26vs_k=1

## CVE-2026-76465

A critical remote code execution (RCE) vulnerability exists in the MPLS OAM feature of Cisco NX-OS Software on Nexus 3000 and 9000 Series Switches. An unauthenticated remote attacker can exploit the vulnerability by sending a crafted MPLS echo-request packet to the device, potentially resulting in arbitrary code execution with root privileges or a denial-of-service condition due to process crashes.

Affected products:
- Nexus 3000 Series Switches
- Nexus 9000 Series Switches
- NX-OS Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-moam-rce-uBTzYV7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20MPLS%20OAM%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1










Related in this roundup: [CVE-2026-76485](#cve-2026-76485), [CVE-2026-76486](#cve-2026-76486), [CVE-2026-76501](#cve-2026-76501).

## CVE-2026-76488

Cisco Application Policy Infrastructure Controller (APIC) contains a vulnerability in its export policies functionality that allows an authenticated, remote attacker with administrative credentials to access sensitive files on the device. By submitting crafted values in UI fields, an attacker can bypass access controls to read system files, including cryptographic materials that could facilitate privilege escalation to root on the APIC or managed switches.

Affected products:
- Application Policy Infrastructure Controller

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-info-priv-enAdB5vD?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Application%20Policy%20Infrastructure%20Controller%20Unauthorized%20File%20Access%20Vulnerability%26vs_k=1












Related in this roundup: [CVE-2026-20321](#cve-2026-20321).

## CVE-2026-20321

A command injection vulnerability exists in the web-based management API of Cisco Application Policy Infrastructure Controller (APIC). An authenticated attacker with administrative credentials can leverage insufficient input validation in command arguments to execute arbitrary commands with root-level privileges on the underlying operating system.

Affected products:
- Application Policy Infrastructure Controller

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-cmdinj-L6VR4E7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Application%20Policy%20Infrastructure%20Controller%20API%20Command%20Injection%20Vulnerability%26vs_k=1












Related in this roundup: [CVE-2026-76488](#cve-2026-76488).

## CVE-2026-20038

A vulnerability in the endpoint group (EPG) contract functionality of Cisco Nexus 9000 Series Fabric Switches in ACI Mode allows unauthenticated, remote attackers to bypass EPG security policies. By sending crafted IPv4 or IPv6 packets using UDP source and destination ports associated with DHCP traffic, an attacker can circumvent configured network security contracts, potentially allowing unauthorized communication across segments.

Affected products:
- Nexus 9000 Series Fabric Switches

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aci-epgcbp-SfDU7NLf?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Fabric%20Switches%20in%20ACI%20Mode%20Endpoint%20Group%20Contract%20Bypass%20Vulnerability%26vs_k=1

## CVE-2026-76485

Multiple critical vulnerabilities in the Next Generation OAM (NGOAM) feature of Cisco NX-OS Software on Nexus 3000 and 9000 series switches allow unauthenticated, remote attackers to achieve arbitrary code execution with root privileges or cause a denial of service. The flaws stem from improper input validation of IP traffic when the NGOAM feature is enabled, which can be triggered by sending crafted packets to an affected device interface.

Affected products:
- Nexus 3000 Series Switches
- Nexus 9000 Series Switches
- NX-OS Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngoam-rce-LWKQ4BU?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20NGOAM%20Remote%20Code%20Execution%20Vulnerabilities%26vs_k=1










Related in this roundup: [CVE-2026-76465](#cve-2026-76465), [CVE-2026-76486](#cve-2026-76486), [CVE-2026-76501](#cve-2026-76501).

## CVE-2026-76486

Multiple critical vulnerabilities in the Next Generation OAM (NGOAM) feature of Cisco NX-OS Software on Nexus 3000 and 9000 series switches allow unauthenticated, remote attackers to achieve arbitrary code execution with root privileges or cause a denial of service. The flaws stem from improper input validation of IP traffic when the NGOAM feature is enabled, which can be triggered by sending crafted packets to an affected device interface.

Affected products:
- Nexus 3000 Series Switches
- Nexus 9000 Series Switches
- NX-OS Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngoam-rce-LWKQ4BU?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20NGOAM%20Remote%20Code%20Execution%20Vulnerabilities%26vs_k=1










Related in this roundup: [CVE-2026-76465](#cve-2026-76465), [CVE-2026-76485](#cve-2026-76485), [CVE-2026-76501](#cve-2026-76501).

## CVE-2026-76501

Multiple critical vulnerabilities in the Next Generation OAM (NGOAM) feature of Cisco NX-OS Software on Nexus 3000 and 9000 series switches allow unauthenticated, remote attackers to achieve arbitrary code execution with root privileges or cause a denial of service. The flaws stem from improper input validation of IP traffic when the NGOAM feature is enabled, which can be triggered by sending crafted packets to an affected device interface.

Affected products:
- Nexus 3000 Series Switches
- Nexus 9000 Series Switches
- NX-OS Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngoam-rce-LWKQ4BU?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20NGOAM%20Remote%20Code%20Execution%20Vulnerabilities%26vs_k=1










Related in this roundup: [CVE-2026-76465](#cve-2026-76465), [CVE-2026-76485](#cve-2026-76485), [CVE-2026-76486](#cve-2026-76486).

## CVE-2026-76471

Cisco NX-OS Software contains a critical vulnerability in its NX-API feature due to insufficient input validation. An unauthenticated remote attacker can exploit this via a crafted HTTP request to execute arbitrary code with root privileges or trigger a denial of service by causing the device process to crash.

Affected products:
- NX-OS Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-napi-rce-r2shwu2j?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20NX-API%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1









Related in this roundup: [CVE-2026-20032](#cve-2026-20032), [CVE-2026-20173](#cve-2026-20173).

## CVE-2026-20173

A vulnerability in Cisco NX-OS Software due to improper rate limiting of protocols allows an unauthenticated, remote attacker to trigger a denial of service (DoS) condition by sending high rates of UDP or TCP traffic to a data plane interface, causing routing and control plane instability.

Affected products:
- NX-OS Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-nscpdos-SnderkC7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Control%20Plane%20Denial%20of%20Service%20Vulnerability%26vs_k=1








Related in this roundup: [CVE-2026-20032](#cve-2026-20032), [CVE-2026-76471](#cve-2026-76471).

## CVE-2026-20328

CVE-2026-20328 is an authentication-bypass vulnerability in the web-based management interface of Cisco License On-Prem (formerly Smart Software Manager On-Prem). An unauthenticated remote attacker can exploit improper password reset checks by sending a malicious request, allowing the attacker to reset the credentials for any account, including administrative users, and gain full unauthorized access to the application.

Affected products:
- License On-Prem
- Smart Software Manager On-Prem

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20328






Related in this roundup: [CVE-2026-76454](#cve-2026-76454).

## CVE-2026-76454

CVE-2026-76454 is a critical vulnerability in the Cisco Smart Licensing Utility API within Cisco License On-Prem (formerly Cisco Smart Software Manager On-Prem). The flaw stems from improper input validation and missing authentication, allowing unauthenticated, remote attackers to perform arbitrary file writes or trigger a denial-of-service (DoS) condition via crafted API requests.

Affected products:
- License On-Prem

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76454






Related in this roundup: [CVE-2026-20328](#cve-2026-20328).

## CVE-2026-76455

Cisco NX-OS contains multiple improper access control vulnerabilities identified during an internal security review. These vulnerabilities are classified under CWE-284 and have a CVSS base score of 9.8, indicating a critical severity level requiring immediate attention through software hardening updates.

Affected products:
- NX-OS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76455



Related in this roundup: [CVE-2026-76453](#cve-2026-76453), [CVE-2026-76456](#cve-2026-76456), [CVE-2026-76458](#cve-2026-76458).

## CVE-2026-76464

Cisco identified multiple internally discovered buffer management vulnerabilities, categorized under CWE-119, affecting Cisco networking products. These vulnerabilities were identified during an internal security review and have a CVSS v3.1 base score of 9.6.

Affected products:
- Cisco networking

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76464

## CVE-2026-76453

CVE-2026-76453 refers to vulnerabilities identified within Cisco NX-OS related to improper neutralization of input, classified under CWE-707. These vulnerabilities were identified during an internal security review and addressed through a software hardening release.

Affected products:
- NX-OS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76453



Related in this roundup: [CVE-2026-76455](#cve-2026-76455), [CVE-2026-76456](#cve-2026-76456), [CVE-2026-76458](#cve-2026-76458).

## CVE-2026-76456

CVE-2026-76456 describes an improper input validation vulnerability within Cisco NX-OS. The flaw involves the incorrect handling of special elements in commands, which can lead to command injection or unauthorized command execution. The issue was identified through an internal security review and is associated with CWE-20.

Affected products:
- NX-OS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76456


Related in this roundup: [CVE-2026-76455](#cve-2026-76455), [CVE-2026-76453](#cve-2026-76453), [CVE-2026-76458](#cve-2026-76458).

## CVE-2026-76458

CVE-2026-76458 identifies a vulnerability in Cisco NX-OS involving improper handling of exceptional conditions (CWE-703). This issue was discovered internally by Cisco and addressed as part of a proactive software hardening release, carrying a CVSS v3.1 base score of 8.6.

Affected products:
- NX-OS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76458

Related in this roundup: [CVE-2026-76455](#cve-2026-76455), [CVE-2026-76453](#cve-2026-76453), [CVE-2026-76456](#cve-2026-76456).
