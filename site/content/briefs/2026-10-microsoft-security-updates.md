---
title: Microsoft Security Updates - October 2026
slug: 2026-10-microsoft-security-updates
description: Roundup of Microsoft security advisories published in October 2026.
date: "2026-10-02T20:23:41Z"
lastmod: "2026-10-13T20:38:13Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Microsoft
cves:
  - id: CVE-2026-96940
    product: Exchange Server
    cvss: 8.8
    epss: 0.00496
  - id: CVE-2026-77900
    product: Azure App Service
    cvss: 9.8
    epss: 0.00494
  - id: CVE-2026-88131
    cvss: 9.8
    epss: 0.00841
  - id: CVE-2026-108744
    cvss: 7
    epss: 0.00547
  - id: CVE-2026-100202
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100202
updates:
  - at: "2026-10-09T00:06:57Z"
    level: L2
    summary: added CVE-2026-88131
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-88131
  - at: "2026-10-09T00:08:42Z"
    level: L2
    summary: added CVE-2026-94510
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-94510
  - at: "2026-10-09T00:09:49Z"
    level: L2
    summary: added CVE-2026-96207
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-96207
  - at: "2026-10-09T00:31:38Z"
    level: L2
    summary: added CVE-2026-83943 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83947
  - at: "2026-10-13T20:38:13Z"
    level: L2
    summary: added CVE-2026-100202 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100202
---

This roundup covers 9 Microsoft security vulnerabilities. CVSS base scores range from 8.8 to 9.8. None are reported as actively exploited at the time of release. The issues affect Azure API Center, Azure App Service, Azure Event Grid, Azure SRE Agent, Bookings, Dataverse, Exchange Server, Partner Center, pbi-cli.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-96940](#cve-2026-96940) | Exchange Server | High | 8.8 | 0.50% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96940) (authoritative) |
| [CVE-2026-69435](#cve-2026-69435) | Azure SRE Agent | Critical | 9.6 | 0.39% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69435) (authoritative) |
| [CVE-2026-77900](#cve-2026-77900) | Azure App Service | Critical | 9.8 | 0.49% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-77900) (authoritative) |
| [CVE-2026-88131](#cve-2026-88131) | Dataverse |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-88131) (authoritative) |
| [CVE-2026-94510](#cve-2026-94510) | Bookings |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-94510) (authoritative) |
| [CVE-2026-96207](#cve-2026-96207) | Partner Center |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-96207) (authoritative) |
| [CVE-2026-83943](#cve-2026-83943) | Azure API Center |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83943) (authoritative) |
| [CVE-2026-83947](#cve-2026-83947) | Azure Event Grid |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83947) (authoritative) |
| [CVE-2026-108744](#cve-2026-108744) | pbi-cli (3.10.1 through 3.12.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108744) (authoritative) |


## CVE-2026-96940

Microsoft Exchange Server contains a vulnerability due to weak authorization that allows an authenticated attacker to elevate their privileges over the network.

Affected products:
- Exchange Server

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96940

## CVE-2026-69435

CVE-2026-69435 is a vulnerability in the Microsoft Azure SRE Agent caused by missing authorization checks. This flaw allows an authenticated attacker to perform unauthorized actions and escalate privileges over the network.

Affected products:
- Azure SRE Agent

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69435

## CVE-2026-77900

A vulnerability in Microsoft Azure App Service allows an unauthorized remote attacker to execute arbitrary code due to missing authentication for a critical function. This flaw carries a high CVSS base score of 9.8 and facilitates RCE over a network without requiring prior authentication.

Affected products:
- Azure App Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-77900

## CVE-2026-88131

CVE-2026-88131 is a critical vulnerability in Microsoft Dataverse involving insecure deserialization of untrusted data, which allows an unauthenticated remote attacker to achieve remote code execution (RCE) over a network.

Affected products:
- Dataverse

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-88131

## CVE-2026-94510

Microsoft Bookings contains an authorization bypass vulnerability (CVE-2026-94510) caused by a user-controlled key, which allows an unauthenticated attacker to perform privilege escalation over a network. The vulnerability carries a high CVSS base score of 9.9, indicating critical severity.

Affected products:
- Bookings

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-94510

## CVE-2026-96207

CVE-2026-96207 describes a vulnerability in Microsoft Partner Center involving improper certificate validation. This flaw allows an unauthorized, network-adjacent attacker to perform privilege escalation within the platform.

Affected products:
- Partner Center

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-96207

## CVE-2026-83943

CVE-2026-83943 is an information exposure vulnerability in Microsoft Azure API Center that allows an unauthorized attacker to access sensitive information over a network. The vulnerability has a CVSS v3.1 base score of 8.7, indicating a high risk of unauthorized data disclosure.

Affected products:
- Azure API Center

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83943

## CVE-2026-83947

CVE-2026-83947 describes a missing authorization vulnerability in Azure Event Grid. This flaw allows an authenticated attacker to perform spoofing attacks over a network, potentially leading to unauthorized data handling or service manipulation within the event-driven architecture.

Affected products:
- Azure Event Grid

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83947

## CVE-2026-108744

The pbi-cli tool is vulnerable to OS command injection due to the improper handling of .pbip file paths within the desktop_sync.py module. When reopening projects, the application passes unquoted file paths to 'cmd /c start', allowing an attacker to execute arbitrary commands by crafting a malicious path containing shell metacharacters such as '&'. This vulnerability results in command execution with the privileges of the user running the application.

Affected products:
- pbi-cli (3.10.1 through 3.12.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108744
