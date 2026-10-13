---
title: Microsoft Security Updates - October 2026
slug: 2026-10-microsoft-security-updates
description: Roundup of Microsoft security advisories published in October 2026.
date: "2026-10-02T20:23:41Z"
lastmod: "2026-10-13T20:39:57Z"
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
  - id: CVE-2026-69435
    cvss: 9.6
    epss: 0.0039
  - id: CVE-2026-77900
    product: Azure App Service
    cvss: 9.8
    epss: 0.00494
  - id: CVE-2026-88131
    cvss: 9.8
    epss: 0.00841
  - id: CVE-2026-83943
    cvss: 8.7
    epss: 0.00379
  - id: CVE-2026-83947
    cvss: 7.7
    epss: 0.0037
  - id: CVE-2026-108744
    cvss: 7
    epss: 0.00547
  - id: CVE-2026-100202
    product: Windows Message Queuing Queue Manager
    cvss: 9.8
  - id: CVE-2026-100219
    cvss: 9.8
  - id: CVE-2026-105010
    cvss: 9.8
  - id: CVE-2026-105016
    cvss: 9.8
  - id: CVE-2026-69634
    cvss: 9.8
  - id: CVE-2026-69705
    cvss: 9.8
  - id: CVE-2026-69883
    cvss: 9.8
  - id: CVE-2026-70153
    cvss: 9.8
  - id: CVE-2026-83517
    cvss: 9.8
  - id: CVE-2026-83519
    product: Windows Error Reporting
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83748
updates:
  - at: "2026-10-13T20:39:14Z"
    level: L2
    summary: added CVE-2026-100219, CVE-2026-105016
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70153
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70188
  - at: "2026-10-13T20:39:31Z"
    level: L2
    summary: added CVE-2026-69705 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70300
  - at: "2026-10-13T20:39:50Z"
    level: L2
    summary: added CVE-2026-105010 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83519
  - at: "2026-10-13T20:39:57Z"
    level: L2
    summary: added CVE-2026-70153
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83748
---

This roundup covers 28 Microsoft security vulnerabilities. CVSS base scores range from 7.0 to 9.8. None are reported as actively exploited at the time of release. The issues affect ASP.NET Core, Azure API Center, Azure App Service, Azure Event Grid, Azure SRE Agent, Bookings, Dataverse, Exchange Server, Microsoft QUIC, Network Policy Server, Office Word, Partner Center, PostScript Printer Driver, Windows, Windows Error Reporting, Windows Imaging Component, Windows Media Foundation, Windows Message Queuing Queue Manager, Windows Rich Text Edit Control, Windows Search Component, Windows System Information Console, Windows Text Shaping, Windows iSCSI, pbi-cli.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-96940](#cve-2026-96940) | Exchange Server | High | 8.8 | 0.50% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96940) (authoritative) |
| [CVE-2026-69435](#cve-2026-69435) | Azure SRE Agent | Critical | 9.6 | 0.39% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69435) (authoritative) |
| [CVE-2026-77900](#cve-2026-77900) | Azure App Service | Critical | 9.8 | 0.49% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-77900) (authoritative) |
| [CVE-2026-88131](#cve-2026-88131) | Dataverse | Critical | 9.8 | 0.84% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-88131) (authoritative) |
| [CVE-2026-94510](#cve-2026-94510) | Bookings |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-94510) (authoritative) |
| [CVE-2026-96207](#cve-2026-96207) | Partner Center |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-96207) (authoritative) |
| [CVE-2026-83943](#cve-2026-83943) | Azure API Center | High | 8.7 | 0.38% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83943) (authoritative) |
| [CVE-2026-83947](#cve-2026-83947) | Azure Event Grid | High | 7.7 | 0.37% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83947) (authoritative) |
| [CVE-2026-108744](#cve-2026-108744) | pbi-cli (3.10.1 through 3.12.0) | High | 7.0 | 0.55% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108744) (authoritative) |
| [CVE-2026-100202](#cve-2026-100202) | Windows Message Queuing Queue Manager | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100202) (authoritative) |
| [CVE-2026-100219](#cve-2026-100219) | Microsoft QUIC | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100219) (authoritative) |
| [CVE-2026-100222](#cve-2026-100222) | Network Policy Server |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100222) (authoritative) |
| [CVE-2026-102210](#cve-2026-102210) | Windows Text Shaping |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102210) (authoritative) |
| [CVE-2026-105010](#cve-2026-105010) | Windows Search Component | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105010) (authoritative) |
| [CVE-2026-105016](#cve-2026-105016) | Microsoft QUIC | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105016) (authoritative) |
| [CVE-2026-69634](#cve-2026-69634) | Windows iSCSI | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69634) (authoritative) |
| [CVE-2026-69705](#cve-2026-69705) | Windows | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69705) (authoritative) |
| [CVE-2026-69883](#cve-2026-69883) | Windows | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69883) (authoritative) |
| [CVE-2026-69886](#cve-2026-69886) | Windows Imaging Component |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69886) (authoritative) |
| [CVE-2026-70096](#cve-2026-70096) | Windows Rich Text Edit Control |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70096) (authoritative) |
| [CVE-2026-70147](#cve-2026-70147) | PostScript Printer Driver |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70147) (authoritative) |
| [CVE-2026-70153](#cve-2026-70153) | PostScript Printer Driver |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70153) (authoritative) |
| [CVE-2026-70157](#cve-2026-70157) | Windows System Information Console |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70157) (authoritative) |
| [CVE-2026-70188](#cve-2026-70188) | ASP.NET Core |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70188) (authoritative) |
| [CVE-2026-70300](#cve-2026-70300) | Office Word |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70300) (authoritative) |
| [CVE-2026-83517](#cve-2026-83517) | Windows Media Foundation | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83517) (authoritative) |
| [CVE-2026-83519](#cve-2026-83519) | Windows Error Reporting | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83519) (authoritative) |
| [CVE-2026-83693](#cve-2026-83693) | Windows Error Reporting |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83693) (authoritative) |


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

## CVE-2026-100202

A use-after-free vulnerability in the Windows Message Queuing (MSMQ) Queue Manager allows a remote, unauthorized attacker to achieve remote code execution over a network. This critical vulnerability poses a high risk as it can be exploited without authentication.

Affected products:
- Windows Message Queuing Queue Manager

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100202

## CVE-2026-100219

CVE-2026-100219 describes a use-after-free vulnerability in Microsoft QUIC. The flaw allows a remote, unauthorized attacker to trigger arbitrary code execution over a network with a CVSS v3.1 base score of 9.8, indicating critical severity.

Affected products:
- Microsoft QUIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100219














Related in this roundup: [CVE-2026-105016](#cve-2026-105016).

## CVE-2026-100222

CVE-2026-100222 is a heap-based buffer overflow vulnerability in the Microsoft Network Policy Server (NPS) component. The vulnerability allows an unauthorized remote attacker to achieve arbitrary code execution over a network, carrying a critical CVSS score of 9.8.

Affected products:
- Network Policy Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100222

## CVE-2026-102210

CVE-2026-102210 is a heap-based buffer overflow vulnerability in the Windows Text Shaping component, which enables an unauthorized remote attacker to achieve arbitrary code execution. The vulnerability is characterized by a high CVSS score of 9.8, indicating the potential for significant impact and ease of network exploitation.

Affected products:
- Windows Text Shaping

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102210

## CVE-2026-105010

CVE-2026-105010 is a use-after-free vulnerability in the Microsoft Windows Search Component that can be exploited by a remote unauthorized attacker to achieve privilege escalation over a network.

Affected products:
- Windows Search Component

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105010

## CVE-2026-105016

CVE-2026-105016 describes a heap-based buffer overflow vulnerability in Microsoft QUIC that allows an unauthorized, remote attacker to achieve arbitrary code execution. The vulnerability is highly critical, as indicated by a CVSS v3.1 base score of 9.8, and can be exploited over a network.

Affected products:
- Microsoft QUIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105016














Related in this roundup: [CVE-2026-100219](#cve-2026-100219).

## CVE-2026-69634

CVE-2026-69634 describes a heap-based buffer overflow vulnerability in the Windows iSCSI implementation. An unauthenticated attacker can exploit this remotely over the network to achieve arbitrary code execution, presenting a critical security risk (CVSS 9.8).

Affected products:
- Windows iSCSI

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69634

## CVE-2026-69705

CVE-2026-69705 is an out-of-bounds write vulnerability within the Windows iSCSI component, enabling unauthenticated remote attackers to achieve arbitrary code execution over a network. The vulnerability carries a CVSS v3.1 base score of 9.8, indicating a critical severity due to the lack of required privileges and the potential for remote exploitation.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69705











Related in this roundup: [CVE-2026-69883](#cve-2026-69883).

## CVE-2026-69883

CVE-2026-69883 is a use-after-free vulnerability in the Windows iSCSI component that enables a remote, unauthorized attacker to achieve remote code execution. Given the high CVSS score, this represents a critical risk for Windows environments.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69883











Related in this roundup: [CVE-2026-69705](#cve-2026-69705).

## CVE-2026-69886

CVE-2026-69886 describes a heap-based buffer overflow vulnerability within the Windows Imaging Component. This flaw allows a remote, unauthorized attacker to achieve arbitrary code execution over a network by leveraging the memory corruption vulnerability.

Affected products:
- Windows Imaging Component

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69886

## CVE-2026-70096

CVE-2026-70096 describes a heap-based buffer overflow vulnerability within the Windows Rich Text Edit Control. This flaw allows a remote, unauthorized attacker to execute arbitrary code over the network, potentially leading to full system compromise.

Affected products:
- Windows Rich Text Edit Control

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70096

## CVE-2026-70147

A heap-based buffer overflow vulnerability in the Microsoft PostScript Printer Driver allows an unauthenticated, remote attacker to execute arbitrary code over the network. This high-severity vulnerability poses a significant risk for remote code execution.

Affected products:
- PostScript Printer Driver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70147







Related in this roundup: [CVE-2026-70153](#cve-2026-70153).

## CVE-2026-70153

CVE-2026-70153 describes a heap-based buffer overflow vulnerability in the Microsoft PostScript Printer Driver. The vulnerability allows an unauthorized remote attacker to achieve arbitrary code execution over a network, presenting a critical risk to systems utilizing this driver.

Affected products:
- PostScript Printer Driver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70153







Related in this roundup: [CVE-2026-70147](#cve-2026-70147).

## CVE-2026-70157

CVE-2026-70157 is a heap-based buffer overflow vulnerability in the Windows System Information Console. An unauthenticated attacker can exploit this flaw to achieve remote code execution over a network, presenting a critical risk to affected Windows environments.

Affected products:
- Windows System Information Console

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70157

## CVE-2026-70188

CVE-2026-70188 describes an HTTP request/response smuggling vulnerability in Microsoft ASP.NET Core caused by inconsistent interpretation of HTTP requests. This vulnerability allows an unauthorized attacker to bypass security controls over a network, potentially leading to unauthorized access or security feature circumvention.

Affected products:
- ASP.NET Core

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70188

## CVE-2026-70300

CVE-2026-70300 is a critical vulnerability in Microsoft Office Word resulting from an untrusted pointer dereference. This flaw enables a remote, unauthorized attacker to execute arbitrary code over a network, potentially leading to full system compromise.

Affected products:
- Office Word

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70300

## CVE-2026-83517

CVE-2026-83517 is a heap-based buffer overflow vulnerability in Microsoft Windows Media Foundation that permits an unauthenticated attacker to achieve remote code execution over a network. The vulnerability carries a CVSS v3.1 base score of 9.8, indicating a critical severity level due to the potential for full system compromise without user interaction.

Affected products:
- Windows Media Foundation

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83517

## CVE-2026-83519

CVE-2026-83519 describes a critical heap-based buffer overflow vulnerability within Windows Error Reporting. The flaw allows an unauthenticated, unauthorized attacker to achieve remote code execution over a network with a high CVSS base score of 9.8.

Affected products:
- Windows Error Reporting

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83519

Related in this roundup: [CVE-2026-83693](#cve-2026-83693).

## CVE-2026-83693

CVE-2026-83693 is a heap-based buffer overflow vulnerability within the Windows Error Reporting component, which can be exploited by an unauthorized remote attacker to achieve arbitrary code execution.

Affected products:
- Windows Error Reporting

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83693

Related in this roundup: [CVE-2026-83519](#cve-2026-83519).
