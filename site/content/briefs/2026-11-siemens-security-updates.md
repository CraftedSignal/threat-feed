---
brief_id: brief-2026-11-siemens-security-updates
event_id: brief-2026-11-siemens-security-updates
revision: 1
activity_at: "2026-11-10T14:33:15Z"
title: Siemens Security Updates - November 2026
slug: 2026-11-siemens-security-updates
description: Roundup of Siemens security advisories published in November 2026.
date: "2026-11-10T14:33:15Z"
lastmod: "2026-11-10T14:33:43Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - roundup
vendors:
  - Siemens
cves:
  - id: CVE-2026-109097
    product: ROS# (< V2.3.1)
    cvss: 8.2
    kev_status: "false"
  - id: CVE-2026-109830
    product: meta-iot2050 (>= V01.03.01)
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-112136
    product: Mendix Studio Pro 11 (>= V11.15.0 < V11.16.0)
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-58114
    product: SIMATIC BATCH
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-59082
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59082
updates:
  - at: "2026-11-10T14:33:15Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109097
  - at: "2026-11-10T14:33:18Z"
    level: L2
    summary: added CVE-2026-109830 +3
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109830
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112136
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58114
      - https://nvd.nist.gov/vuln/detail/CVE-2026-59082
---

This roundup covers 4 Siemens security vulnerabilities. CVSS base scores range from 7.3 to 8.8. None are reported as actively exploited at the time of release. The issues affect Mendix Studio Pro 11, ROS#, SIMATIC BATCH, meta-iot2050.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-109097](#cve-2026-109097) | ROS# (< V2.3.1) | High | 8.2 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109097) (authoritative) |
| [CVE-2026-109830](#cve-2026-109830) | meta-iot2050 (>= V01.03.01) | High | 7.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109830) (authoritative) |
| [CVE-2026-112136](#cve-2026-112136) | Mendix Studio Pro 11 (>= V11.15.0 < V11.16.0) | High | 8.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-112136) (authoritative) |
| [CVE-2026-58114](#cve-2026-58114) | SIMATIC BATCH | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58114) (authoritative) |


## CVE-2026-109097

ROS# versions prior to V2.3.1 are vulnerable to a code injection attack due to improper escaping of text within message definition files. An attacker capable of supplying a crafted message definition file to a user of the library can trigger the execution of arbitrary code within the context of the generated program.

Affected products:
- ROS# (< V2.3.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109097

## CVE-2026-109830

A vulnerability in the meta-iot2050 configuration parsing logic allows for arbitrary code execution. The system fails to sanitize input from configuration files before processing, enabling an attacker with file-write access to inject and execute unauthorized commands.

Affected products:
- meta-iot2050 (>= V01.03.01)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109830

## CVE-2026-112136

Mendix Studio Pro 11 versions 11.15.0 through 11.16.0 and 11.12.6 through 11.12.7 contain a vulnerability where the MCP Server's HTTP listener is not restricted to the loopback interface. This misconfiguration exposes the interface to unauthorized remote network access, potentially allowing an attacker to interact with the server remotely.

Affected products:
- Mendix Studio Pro 11 (>= V11.15.0 < V11.16.0)
- Mendix Studio Pro 11.12 (>= V11.12.6 < V11.12.7)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-112136

## CVE-2026-58114

SIMATIC software products utilize the deprecated NTLM protocol for remote user authentication without adequate security controls. An unauthenticated remote attacker performing a machine-in-the-middle attack can relay NTLM authentication packets to impersonate legitimate users and potentially gain unauthorized access to underlying services such as SQL servers.

Affected products:
- SIMATIC BATCH
- SIMATIC Information Server
- SIMATIC PCS 7
- SIMATIC Process Historian
- SIMATIC WinCC Runtime Professional
- SIMATIC WinCC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58114
