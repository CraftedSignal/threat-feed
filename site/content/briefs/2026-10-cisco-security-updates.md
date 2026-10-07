---
title: Cisco Security Updates - October 2026
slug: 2026-10-cisco-security-updates
description: Roundup of Cisco security advisories published in October 2026.
date: "2026-10-07T17:00:15Z"
lastmod: "2026-10-07T17:01:09Z"
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
  - id: CVE-2026-20032
    product: NX-OS Software
  - id: CVE-2026-20362
    product: Finesse
  - id: CVE-2026-76465
    product: Nexus 3000 Series Switches
  - id: CVE-2026-76488
    product: Application Policy Infrastructure Controller
  - id: CVE-2026-20321
    product: Application Policy Infrastructure Controller
  - id: CVE-2026-20038
    product: Nexus 9000 Series Fabric Switches
  - id: CVE-2026-76485
  - id: CVE-2026-76486
  - id: CVE-2026-76501
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngoam-rce-LWKQ4BU?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20NGOAM%20Remote%20Code%20Execution%20Vulnerabilities%26vs_k=1
updates:
  - at: "2026-10-07T17:00:30Z"
    level: L2
    summary: added CVE-2026-20321, CVE-2026-76465, CVE-2026-76488
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-moam-rce-uBTzYV7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20MPLS%20OAM%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-info-priv-enAdB5vD?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Application%20Policy%20Infrastructure%20Controller%20Unauthorized%20File%20Access%20Vulnerability%26vs_k=1
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-cmdinj-L6VR4E7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Application%20Policy%20Infrastructure%20Controller%20API%20Command%20Injection%20Vulnerability%26vs_k=1
  - at: "2026-10-07T17:01:04Z"
    level: L2
    summary: added CVE-2026-20038
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aci-epgcbp-SfDU7NLf?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Fabric%20Switches%20in%20ACI%20Mode%20Endpoint%20Group%20Contract%20Bypass%20Vulnerability%26vs_k=1
  - at: "2026-10-07T17:01:09Z"
    level: L2
    summary: added CVE-2026-76485 +2
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngoam-rce-LWKQ4BU?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20NGOAM%20Remote%20Code%20Execution%20Vulnerabilities%26vs_k=1
---

This roundup covers 6 Cisco security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Application Policy Infrastructure Controller, Finesse, NX-OS Software, Nexus 3000 Series Switches, Nexus 9000 Series Fabric Switches.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-20032](#cve-2026-20032) | NX-OS Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-mppe-dhKZAFgb?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Python%20Sandbox%20Escape%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20362](#cve-2026-20362) | Finesse |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-mmSuyugS?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Finesse%20Server-Side%20Request%20Forgery%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-76465](#cve-2026-76465) | Nexus 3000 Series Switches |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-moam-rce-uBTzYV7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20MPLS%20OAM%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-76488](#cve-2026-76488) | Application Policy Infrastructure Controller |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-info-priv-enAdB5vD?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Application%20Policy%20Infrastructure%20Controller%20Unauthorized%20File%20Access%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20321](#cve-2026-20321) | Application Policy Infrastructure Controller |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-cmdinj-L6VR4E7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Application%20Policy%20Infrastructure%20Controller%20API%20Command%20Injection%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20038](#cve-2026-20038) | Nexus 9000 Series Fabric Switches |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aci-epgcbp-SfDU7NLf?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%209000%20Series%20Fabric%20Switches%20in%20ACI%20Mode%20Endpoint%20Group%20Contract%20Bypass%20Vulnerability%26vs_k=1) (authoritative) |


## CVE-2026-20032

A sandbox escape vulnerability exists within the Python interpreter of Cisco NX-OS Software. An authenticated local attacker with low privileges and Python execution rights can exploit insufficient input validation to escape the sandbox and execute arbitrary commands on the underlying operating system with the privileges of the authenticated user.

Affected products:
- NX-OS Software

Source: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-mppe-dhKZAFgb?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Python%20Sandbox%20Escape%20Vulnerability%26vs_k=1

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
