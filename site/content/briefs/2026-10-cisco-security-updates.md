---
title: Cisco Security Updates - October 2026
slug: 2026-10-cisco-security-updates
description: Roundup of Cisco security advisories published in October 2026.
date: "2026-10-07T17:00:15Z"
lastmod: "2026-10-07T17:00:30Z"
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
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-moam-rce-uBTzYV7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20MPLS%20OAM%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1
updates:
  - at: "2026-10-07T17:00:15Z"
    level: L1
    summary: posted roundup
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-mppe-dhKZAFgb?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Python%20Sandbox%20Escape%20Vulnerability%26vs_k=1
  - at: "2026-10-07T17:00:18Z"
    level: L2
    summary: added CVE-2026-20362, CVE-2026-76465
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-mmSuyugS?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Finesse%20Server-Side%20Request%20Forgery%20Vulnerability%26vs_k=1
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-moam-rce-uBTzYV7?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Nexus%203000%20and%209000%20Series%20Switches%20MPLS%20OAM%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1
---

This roundup covers 2 Cisco security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Finesse, NX-OS Software.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-20032](#cve-2026-20032) | NX-OS Software |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-mppe-dhKZAFgb?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20NX-OS%20Software%20Python%20Sandbox%20Escape%20Vulnerability%26vs_k=1) (authoritative) |
| [CVE-2026-20362](#cve-2026-20362) | Finesse |  |  |  | no | [source](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-finesse-ssrf-mmSuyugS?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Finesse%20Server-Side%20Request%20Forgery%20Vulnerability%26vs_k=1) (authoritative) |


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
