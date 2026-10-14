---
title: Microsoft Security Updates - October 2026
slug: 2026-10-microsoft-security-updates
description: Roundup of Microsoft security advisories published in October 2026.
date: "2026-10-02T20:23:41Z"
lastmod: "2026-10-14T00:33:14Z"
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
  - id: CVE-2026-94510
    cvss: 9.9
    epss: 0.00402
  - id: CVE-2026-96207
    cvss: 10
    epss: 0.00477
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
  - id: CVE-2026-100222
    cvss: 9.8
  - id: CVE-2026-102210
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
  - id: CVE-2026-70157
    cvss: 9.8
  - id: CVE-2026-70188
    cvss: 9.1
  - id: CVE-2026-70300
    cvss: 9.8
  - id: CVE-2026-83517
    cvss: 9.8
  - id: CVE-2026-83519
    product: Windows Error Reporting
    cvss: 9.8
  - id: CVE-2026-83693
    cvss: 9.8
  - id: CVE-2026-83748
    cvss: 9.8
  - id: CVE-2026-83770
    cvss: 9.8
  - id: CVE-2026-83780
    cvss: 9.8
  - id: CVE-2026-83782
    cvss: 9.8
  - id: CVE-2026-83862
    cvss: 9.8
  - id: CVE-2026-83935
    cvss: 9.8
  - id: CVE-2026-85792
    cvss: 9.8
  - id: CVE-2026-85806
    product: Network Policy Server
    cvss: 9.8
  - id: CVE-2026-85809
    cvss: 9.8
  - id: CVE-2026-85814
    cvss: 9.8
  - id: CVE-2026-85818
    cvss: 9
  - id: CVE-2026-85928
    cvss: 9.8
  - id: CVE-2026-88102
    cvss: 9.8
  - id: CVE-2026-96113
    cvss: 9.8
  - id: CVE-2026-97016
    cvss: 9.8
  - id: CVE-2026-97814
    product: Windows
    cvss: 9.8
  - id: CVE-2026-97815
    cvss: 9.8
  - id: CVE-2026-97816
    cvss: 9.8
  - id: CVE-2026-102238
    product: Visual Studio Code
    cvss: 9.6
  - id: CVE-2026-100200
    cvss: 7
  - id: CVE-2026-100201
    cvss: 7
  - id: CVE-2026-100203
    cvss: 7
  - id: CVE-2026-100205
    cvss: 7.1
  - id: CVE-2026-100207
    cvss: 7.3
  - id: CVE-2026-100220
    cvss: 8.8
  - id: CVE-2026-102231
    cvss: 7.7
  - id: CVE-2026-103569
    cvss: 7.5
  - id: CVE-2026-105728
    cvss: 7.5
  - id: CVE-2026-108399
    cvss: 7.2
  - id: CVE-2026-108400
    cvss: 8.8
  - id: CVE-2026-96951
    cvss: 8.8
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102849
updates:
  - at: "2026-10-13T22:41:04Z"
    level: L2
    summary: added CVE-2026-100220 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-105728
  - at: "2026-10-13T22:41:09Z"
    level: L2
    summary: added CVE-2026-103569, CVE-2026-108399
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108130
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108400
  - at: "2026-10-13T23:36:54Z"
    level: L2
    summary: added CVE-2026-100222
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-96951
  - at: "2026-10-14T00:33:14Z"
    level: L2
    summary: added CVE-2026-105728 +2
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-102849
---

This roundup covers 82 Microsoft security vulnerabilities. CVSS base scores range from 7.0 to 10.0. None are reported as actively exploited at the time of release. The issues affect ASP.NET Core, Azure API Center, Azure App Service, Azure CycleCloud, Azure Event Grid, Azure SRE Agent, Bookings, CCFFilter Driver, Dataverse, Defender for Endpoint, Dynamics Business Central, Excel, Exchange Server, Hyper-V, Microsoft QUIC, Network Policy Server, Office Access, Office Outlook, Office Word, OpenSSH for Windows, Partner Center, PostScript Printer Driver, Remote Desktop Client, Resilient File System, Routing and Remote Access Service, Software Protection Platform, Sysinternals, Visual Studio Code, Windows, Windows Autopilot, Windows Backup Engine, Windows Broadcast DVR User Service, Windows Client License Service, Windows Codecs Library, Windows Error Reporting, Windows Failover Cluster, Windows Imaging Component, Windows Media Foundation, Windows Media Video Decoder, Windows Message Queuing, Windows Message Queuing Queue Manager, Windows Modern Device Management, Windows Network Load Balancing, Windows PDF, Windows Partition Management Driver, Windows Rich Text Edit Control, Windows Routing and Remote Access Service, Windows Schannel, Windows Search Component, Windows Server, Windows Shell, Windows SmartScreen, Windows System Information Console, Windows Text Shaping, Windows Update Delivery Optimization, Windows Update Service, Windows Volume Manager Extension Driver, Windows iSCSI, XML, pbi-cli.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-96940](#cve-2026-96940) | Exchange Server | High | 8.8 | 0.50% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96940) (authoritative) |
| [CVE-2026-69435](#cve-2026-69435) | Azure SRE Agent | Critical | 9.6 | 0.39% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69435) (authoritative) |
| [CVE-2026-77900](#cve-2026-77900) | Azure App Service | Critical | 9.8 | 0.49% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-77900) (authoritative) |
| [CVE-2026-88131](#cve-2026-88131) | Dataverse | Critical | 9.8 | 0.84% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-88131) (authoritative) |
| [CVE-2026-94510](#cve-2026-94510) | Bookings | Critical | 9.9 | 0.40% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-94510) (authoritative) |
| [CVE-2026-96207](#cve-2026-96207) | Partner Center | Critical | 10.0 | 0.48% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-96207) (authoritative) |
| [CVE-2026-83943](#cve-2026-83943) | Azure API Center | High | 8.7 | 0.38% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83943) (authoritative) |
| [CVE-2026-83947](#cve-2026-83947) | Azure Event Grid | High | 7.7 | 0.37% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83947) (authoritative) |
| [CVE-2026-108744](#cve-2026-108744) | pbi-cli (3.10.1 through 3.12.0) | High | 7.0 | 0.55% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108744) (authoritative) |
| [CVE-2026-100202](#cve-2026-100202) | Windows Message Queuing Queue Manager | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100202) (authoritative) |
| [CVE-2026-100219](#cve-2026-100219) | Microsoft QUIC | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100219) (authoritative) |
| [CVE-2026-100222](#cve-2026-100222) | Network Policy Server | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100222) (authoritative) |
| [CVE-2026-102210](#cve-2026-102210) | Windows Text Shaping | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102210) (authoritative) |
| [CVE-2026-105010](#cve-2026-105010) | Windows Search Component | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105010) (authoritative) |
| [CVE-2026-105016](#cve-2026-105016) | Microsoft QUIC | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105016) (authoritative) |
| [CVE-2026-69634](#cve-2026-69634) | Windows iSCSI | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69634) (authoritative) |
| [CVE-2026-69705](#cve-2026-69705) | Windows | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69705) (authoritative) |
| [CVE-2026-69883](#cve-2026-69883) | Windows | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69883) (authoritative) |
| [CVE-2026-69886](#cve-2026-69886) | Windows Imaging Component |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69886) (authoritative) |
| [CVE-2026-70096](#cve-2026-70096) | Windows Rich Text Edit Control |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70096) (authoritative) |
| [CVE-2026-70147](#cve-2026-70147) | PostScript Printer Driver |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70147) (authoritative) |
| [CVE-2026-70153](#cve-2026-70153) | PostScript Printer Driver | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70153) (authoritative) |
| [CVE-2026-70157](#cve-2026-70157) | Windows System Information Console | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70157) (authoritative) |
| [CVE-2026-70188](#cve-2026-70188) | ASP.NET Core | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70188) (authoritative) |
| [CVE-2026-70300](#cve-2026-70300) | Office Word | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70300) (authoritative) |
| [CVE-2026-83517](#cve-2026-83517) | Windows Media Foundation | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83517) (authoritative) |
| [CVE-2026-83519](#cve-2026-83519) | Windows Error Reporting | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83519) (authoritative) |
| [CVE-2026-83693](#cve-2026-83693) | Windows Error Reporting | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83693) (authoritative) |
| [CVE-2026-83748](#cve-2026-83748) | Windows Error Reporting | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83748) (authoritative) |
| [CVE-2026-83770](#cve-2026-83770) | Windows | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83770) (authoritative) |
| [CVE-2026-83780](#cve-2026-83780) | CCFFilter Driver | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83780) (authoritative) |
| [CVE-2026-83782](#cve-2026-83782) | Windows Shell | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83782) (authoritative) |
| [CVE-2026-83862](#cve-2026-83862) | Windows Network Load Balancing | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83862) (authoritative) |
| [CVE-2026-83935](#cve-2026-83935) | XML | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83935) (authoritative) |
| [CVE-2026-85792](#cve-2026-85792) | Windows Routing and Remote Access Service | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-85792) (authoritative) |
| [CVE-2026-85806](#cve-2026-85806) | Network Policy Server | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-85806) (authoritative) |
| [CVE-2026-85809](#cve-2026-85809) | Routing and Remote Access Service | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-85809) (authoritative) |
| [CVE-2026-85814](#cve-2026-85814) | Windows Media Foundation | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-85814) (authoritative) |
| [CVE-2026-85818](#cve-2026-85818) | Windows Schannel | Critical | 9.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-85818) (authoritative) |
| [CVE-2026-85928](#cve-2026-85928) | Windows Volume Manager Extension Driver | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-85928) (authoritative) |
| [CVE-2026-88092](#cve-2026-88092) | ASP.NET Core |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-88092) (authoritative) |
| [CVE-2026-88102](#cve-2026-88102) | Windows Failover Cluster | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-88102) (authoritative) |
| [CVE-2026-88156](#cve-2026-88156) | Office Outlook |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-88156) (authoritative) |
| [CVE-2026-96113](#cve-2026-96113) | Windows Server | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-96113) (authoritative) |
| [CVE-2026-97016](#cve-2026-97016) | Office Outlook | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-97016) (authoritative) |
| [CVE-2026-97805](#cve-2026-97805) | Windows Partition Management Driver |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-97805) (authoritative) |
| [CVE-2026-97814](#cve-2026-97814) | Windows | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-97814) (authoritative) |
| [CVE-2026-97815](#cve-2026-97815) | Windows Error Reporting | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-97815) (authoritative) |
| [CVE-2026-97816](#cve-2026-97816) | OpenSSH for Windows | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-97816) (authoritative) |
| [CVE-2026-102238](#cve-2026-102238) | Visual Studio Code | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102238) (authoritative) |
| [CVE-2026-100200](#cve-2026-100200) | Windows Update Service | High | 7.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100200) (authoritative) |
| [CVE-2026-100201](#cve-2026-100201) | Windows Client License Service | High | 7.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100201) (authoritative) |
| [CVE-2026-100203](#cve-2026-100203) | Windows Update Service | High | 7.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100203) (authoritative) |
| [CVE-2026-100205](#cve-2026-100205) | Sysinternals | High | 7.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100205) (authoritative) |
| [CVE-2026-100207](#cve-2026-100207) | Azure CycleCloud | High | 7.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100207) (authoritative) |
| [CVE-2026-100220](#cve-2026-100220) | Windows Media Video Decoder | High | 8.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-100220) (authoritative) |
| [CVE-2026-102204](#cve-2026-102204) | Defender for Endpoint |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102204) (authoritative) |
| [CVE-2026-102227](#cve-2026-102227) | Resilient File System (ReFS) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102227) (authoritative) |
| [CVE-2026-102231](#cve-2026-102231) | Visual Studio Code | High | 7.7 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102231) (authoritative) |
| [CVE-2026-102233](#cve-2026-102233) | Visual Studio Code |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102233) (authoritative) |
| [CVE-2026-103569](#cve-2026-103569) | Windows | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103569) (authoritative) |
| [CVE-2026-103577](#cve-2026-103577) | Microsoft QUIC |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-103577) (authoritative) |
| [CVE-2026-105717](#cve-2026-105717) | Office Access |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105717) (authoritative) |
| [CVE-2026-105718](#cve-2026-105718) | Excel |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105718) (authoritative) |
| [CVE-2026-105728](#cve-2026-105728) | Dynamics Business Central |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-105728) (authoritative) |
| [CVE-2026-108130](#cve-2026-108130) | Windows |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108130) (authoritative) |
| [CVE-2026-108132](#cve-2026-108132) | Windows |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108132) (authoritative) |
| [CVE-2026-108133](#cve-2026-108133) | Windows Modern Device Management |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108133) (authoritative) |
| [CVE-2026-108134](#cve-2026-108134) | Windows Autopilot |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108134) (authoritative) |
| [CVE-2026-108135](#cve-2026-108135) | Windows Backup Engine |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108135) (authoritative) |
| [CVE-2026-108136](#cve-2026-108136) | Windows Search Component |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108136) (authoritative) |
| [CVE-2026-108396](#cve-2026-108396) | Windows Modern Device Management |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108396) (authoritative) |
| [CVE-2026-108399](#cve-2026-108399) | Hyper-V | High | 7.2 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108399) (authoritative) |
| [CVE-2026-108400](#cve-2026-108400) | Windows Codecs Library |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108400) (authoritative) |
| [CVE-2026-108457](#cve-2026-108457) | Windows PDF |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108457) (authoritative) |
| [CVE-2026-108458](#cve-2026-108458) | Remote Desktop Client |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108458) (authoritative) |
| [CVE-2026-108460](#cve-2026-108460) | Windows Message Queuing |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108460) (authoritative) |
| [CVE-2026-108461](#cve-2026-108461) | Windows Broadcast DVR User Service |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108461) (authoritative) |
| [CVE-2026-108463](#cve-2026-108463) | Windows SmartScreen |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108463) (authoritative) |
| [CVE-2026-108464](#cve-2026-108464) | Software Protection Platform |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108464) (authoritative) |
| [CVE-2026-108465](#cve-2026-108465) | Windows Update Delivery Optimization |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-108465) (authoritative) |
| [CVE-2026-96951](#cve-2026-96951) | Windows |  |  |  | no | [source](https://www.cve.org/CVERecord?id=CVE-2026-96951) (authoritative) |


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




































































Related in this roundup: [CVE-2026-105016](#cve-2026-105016), [CVE-2026-103577](#cve-2026-103577).

## CVE-2026-100222

CVE-2026-100222 is a heap-based buffer overflow vulnerability in the Microsoft Network Policy Server (NPS) component. The vulnerability allows an unauthorized remote attacker to achieve arbitrary code execution over a network, carrying a critical CVSS score of 9.8.

Affected products:
- Network Policy Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100222















































Related in this roundup: [CVE-2026-85806](#cve-2026-85806).

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












Related in this roundup: [CVE-2026-108136](#cve-2026-108136).

## CVE-2026-105016

CVE-2026-105016 describes a heap-based buffer overflow vulnerability in Microsoft QUIC that allows an unauthorized, remote attacker to achieve arbitrary code execution. The vulnerability is highly critical, as indicated by a CVSS v3.1 base score of 9.8, and can be exploited over a network.

Affected products:
- Microsoft QUIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105016




































































Related in this roundup: [CVE-2026-100219](#cve-2026-100219), [CVE-2026-103577](#cve-2026-103577).

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

































































Related in this roundup: [CVE-2026-69883](#cve-2026-69883), [CVE-2026-83770](#cve-2026-83770), [CVE-2026-97814](#cve-2026-97814), [CVE-2026-103569](#cve-2026-103569), [CVE-2026-108130](#cve-2026-108130), [CVE-2026-108132](#cve-2026-108132), [CVE-2026-96951](#cve-2026-96951).

## CVE-2026-69883

CVE-2026-69883 is a use-after-free vulnerability in the Windows iSCSI component that enables a remote, unauthorized attacker to achieve remote code execution. Given the high CVSS score, this represents a critical risk for Windows environments.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69883

































































Related in this roundup: [CVE-2026-69705](#cve-2026-69705), [CVE-2026-83770](#cve-2026-83770), [CVE-2026-97814](#cve-2026-97814), [CVE-2026-103569](#cve-2026-103569), [CVE-2026-108130](#cve-2026-108130), [CVE-2026-108132](#cve-2026-108132), [CVE-2026-96951](#cve-2026-96951).

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










































Related in this roundup: [CVE-2026-88092](#cve-2026-88092).

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













































Related in this roundup: [CVE-2026-85814](#cve-2026-85814).

## CVE-2026-83519

CVE-2026-83519 describes a critical heap-based buffer overflow vulnerability within Windows Error Reporting. The flaw allows an unauthenticated, unauthorized attacker to achieve remote code execution over a network with a high CVSS base score of 9.8.

Affected products:
- Windows Error Reporting

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83519























































Related in this roundup: [CVE-2026-83693](#cve-2026-83693), [CVE-2026-83748](#cve-2026-83748), [CVE-2026-97815](#cve-2026-97815).

## CVE-2026-83693

CVE-2026-83693 is a heap-based buffer overflow vulnerability within the Windows Error Reporting component, which can be exploited by an unauthorized remote attacker to achieve arbitrary code execution.

Affected products:
- Windows Error Reporting

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83693























































Related in this roundup: [CVE-2026-83519](#cve-2026-83519), [CVE-2026-83748](#cve-2026-83748), [CVE-2026-97815](#cve-2026-97815).

## CVE-2026-83748

CVE-2026-83748 is a critical heap-based buffer overflow vulnerability in Windows Error Reporting that can be exploited by an unauthorized remote attacker to achieve arbitrary code execution. The vulnerability is network-exploitable, posing a significant risk to affected Windows systems.

Affected products:
- Windows Error Reporting

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83748






















































Related in this roundup: [CVE-2026-83519](#cve-2026-83519), [CVE-2026-83693](#cve-2026-83693), [CVE-2026-97815](#cve-2026-97815).

## CVE-2026-83770

A heap-based buffer overflow vulnerability in the Windows Text Shaping component allows an unauthorized remote attacker to achieve code execution. The vulnerability is exploitable over a network, presenting a high risk (CVSS 9.8) for systems handling crafted text inputs.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83770





















































Related in this roundup: [CVE-2026-69705](#cve-2026-69705), [CVE-2026-69883](#cve-2026-69883), [CVE-2026-97814](#cve-2026-97814), [CVE-2026-103569](#cve-2026-103569), [CVE-2026-108130](#cve-2026-108130), [CVE-2026-108132](#cve-2026-108132), [CVE-2026-96951](#cve-2026-96951).

## CVE-2026-83780

The Windows CCFFilter Driver is susceptible to a use-after-free vulnerability that allows a remote, unauthorized attacker to achieve arbitrary code execution over a network. This critical vulnerability, carrying a CVSS base score of 9.8, represents a significant risk for unauthorized system compromise via network-accessible services.

Affected products:
- CCFFilter Driver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83780

## CVE-2026-83782

CVE-2026-83782 is a critical heap-based buffer overflow vulnerability within the Windows Shell component. An unauthorized remote attacker can leverage this vulnerability to achieve arbitrary code execution via network-based vectors.

Affected products:
- Windows Shell

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83782

## CVE-2026-83862

A use-after-free vulnerability in the Windows Network Load Balancing component allows a remote, unauthorized attacker to achieve remote code execution (RCE) via network-based exploitation. The vulnerability carries a CVSS base score of 9.8, indicating a critical severity level.

Affected products:
- Windows Network Load Balancing

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83862

## CVE-2026-83935

CVE-2026-83935 describes a heap-based buffer overflow vulnerability in Microsoft XML, which allows a remote, unauthorized attacker to execute arbitrary code over a network with a CVSS base score of 9.8.

Affected products:
- XML

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83935

## CVE-2026-85792

CVE-2026-85792 is a critical remote code execution vulnerability residing in the Windows Routing and Remote Access Service (RRAS). An unauthenticated attacker can exploit this flaw to gain unauthorized access and execute arbitrary code on a target machine, necessitating immediate patching of affected Windows systems.

Affected products:
- Windows Routing and Remote Access Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-85792

## CVE-2026-85806

CVE-2026-85806 describes an integer underflow vulnerability in the Microsoft Network Policy Server (NPS) component. This flaw allows an unauthenticated, remote attacker to execute arbitrary code by sending specially crafted network packets that trigger the underflow condition. Due to the high CVSS score, this represents a critical risk requiring immediate patching of all Windows Server instances running the NPS role.

Affected products:
- Network Policy Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-85806















































Related in this roundup: [CVE-2026-100222](#cve-2026-100222).

## CVE-2026-85809

A remote code execution vulnerability exists in the Windows Routing and Remote Access Service (RRAS) that allows an unauthenticated attacker to gain unauthorized access to a victim's machine. The high CVSS score of 9.8 indicates that this vulnerability is critical and likely exploitable over the network.

Affected products:
- Routing and Remote Access Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-85809

## CVE-2026-85814

CVE-2026-85814 is a critical heap-based buffer overflow vulnerability in Microsoft Windows Media Foundation. An unauthenticated attacker can exploit this flaw to achieve remote code execution over a network, presenting a significant risk to affected Windows systems.

Affected products:
- Windows Media Foundation

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-85814













































Related in this roundup: [CVE-2026-83517](#cve-2026-83517).

## CVE-2026-85818

CVE-2026-85818 describes a vulnerability in the Windows Schannel component involving improper verification of cryptographic signatures. This flaw enables an unauthorized remote attacker to perform spoofing attacks over a network, potentially compromising the integrity of secure communications.

Affected products:
- Windows Schannel

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-85818

## CVE-2026-85928

CVE-2026-85928 is a critical heap-based buffer overflow vulnerability in the Windows Volume Manager Extension Driver. An unauthenticated attacker can exploit this flaw over a network to achieve remote code execution on the target system.

Affected products:
- Windows Volume Manager Extension Driver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-85928

## CVE-2026-88092

CVE-2026-88092 is a high-severity vulnerability in ASP.NET Core involving HTTP request/response smuggling. An unauthorized attacker can leverage this inconsistency in how HTTP requests are interpreted to perform unauthorized data tampering over a network.

Affected products:
- ASP.NET Core

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-88092










































Related in this roundup: [CVE-2026-70188](#cve-2026-70188).

## CVE-2026-88102

CVE-2026-88102 is a use-after-free vulnerability in the Windows Failover Cluster component. It allows an unauthenticated, remote attacker to trigger arbitrary code execution by sending specifically crafted network requests to the vulnerable service, presenting a high risk to availability and system integrity.

Affected products:
- Windows Failover Cluster

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-88102

## CVE-2026-88156

CVE-2026-88156 describes a critical stack-based buffer overflow vulnerability in Microsoft Office Outlook. An unauthorized attacker can leverage this flaw to achieve remote code execution over a network, presenting a high risk for enterprise environments relying on Outlook for email communication.

Affected products:
- Office Outlook

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-88156






































Related in this roundup: [CVE-2026-97016](#cve-2026-97016).

## CVE-2026-96113

CVE-2026-96113 describes a heap-based buffer overflow vulnerability within a DNS server implementation that enables remote code execution by an unauthorized attacker over the network. The vulnerability carries a CVSS v3.1 base score of 9.8, indicating a critical severity level due to the potential for unauthenticated exploitation.

Affected products:
- Windows Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-96113

## CVE-2026-97016

CVE-2026-97016 is a critical heap-based buffer overflow vulnerability in Microsoft Office Outlook that enables remote code execution by an unauthorized attacker over a network.

Affected products:
- Office Outlook

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-97016






































Related in this roundup: [CVE-2026-88156](#cve-2026-88156).

## CVE-2026-97805

CVE-2026-97805 describes an out-of-bounds read vulnerability within the Windows Partition Management Driver. An unauthorized remote attacker can leverage this flaw to achieve remote code execution on affected Windows systems.

Affected products:
- Windows Partition Management Driver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-97805

## CVE-2026-97814

CVE-2026-97814 is a critical heap-based buffer overflow vulnerability within the Windows Text Shaping component, which enables an unauthorized remote attacker to achieve arbitrary code execution. The vulnerability is highly exploitable via network-based vectors, warranting immediate attention for patch management.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-97814




































Related in this roundup: [CVE-2026-69705](#cve-2026-69705), [CVE-2026-69883](#cve-2026-69883), [CVE-2026-83770](#cve-2026-83770), [CVE-2026-103569](#cve-2026-103569), [CVE-2026-108130](#cve-2026-108130), [CVE-2026-108132](#cve-2026-108132), [CVE-2026-96951](#cve-2026-96951).

## CVE-2026-97815

CVE-2026-97815 describes a heap-based buffer overflow vulnerability in Windows Error Reporting that permits a remote, unauthorized attacker to achieve arbitrary code execution. The vulnerability is highly critical with a CVSS base score of 9.8, indicating the potential for network-based exploitation without authentication.

Affected products:
- Windows Error Reporting

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-97815



































Related in this roundup: [CVE-2026-83519](#cve-2026-83519), [CVE-2026-83693](#cve-2026-83693), [CVE-2026-83748](#cve-2026-83748).

## CVE-2026-97816

CVE-2026-97816 is a critical use-after-free vulnerability in OpenSSH for Windows that enables an unauthorized remote attacker to achieve remote code execution. The vulnerability is exploitable over the network without authentication, warranting immediate attention for patching and monitoring for exploitation attempts against SSH services.

Affected products:
- OpenSSH for Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-97816

## CVE-2026-102238

Visual Studio Code contains a path traversal vulnerability that can be exploited by an unauthorized remote attacker to achieve remote code execution. The vulnerability arises from improper limitation of a pathname to a restricted directory.

Affected products:
- Visual Studio Code

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102238
























Related in this roundup: [CVE-2026-102231](#cve-2026-102231), [CVE-2026-102233](#cve-2026-102233).

## CVE-2026-100200

CVE-2026-100200 is a use-after-free vulnerability in the Windows Update Service that enables a locally authenticated attacker to achieve privilege escalation. The vulnerability exists within the service's memory management logic, allowing an attacker to execute arbitrary code or gain higher-level permissions on the local system.

Affected products:
- Windows Update Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100200






























Related in this roundup: [CVE-2026-100203](#cve-2026-100203).

## CVE-2026-100201

A heap-based buffer overflow vulnerability in the Windows Client License Service allows an authenticated, locally authorized attacker to escalate privileges to a higher level of authority on the host system.

Affected products:
- Windows Client License Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100201

## CVE-2026-100203

CVE-2026-100203 describes a heap-based buffer overflow vulnerability in the Windows Update Service that enables a locally authenticated attacker to escalate privileges on the affected system.

Affected products:
- Windows Update Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100203






























Related in this roundup: [CVE-2026-100200](#cve-2026-100200).

## CVE-2026-100205

An untrusted pointer dereference vulnerability in Microsoft Sysinternals allows a locally authenticated attacker to escalate privileges to a higher level of access by exploiting the flaw in the software.

Affected products:
- Sysinternals

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100205

## CVE-2026-100207

CVE-2026-100207 describes an OS command injection vulnerability in Microsoft Azure CycleCloud. The vulnerability allows an authorized attacker to execute arbitrary code locally due to improper neutralization of special elements used in OS commands, potentially leading to unauthorized system control.

Affected products:
- Azure CycleCloud

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100207

## CVE-2026-100220

CVE-2026-100220 is a heap-based buffer overflow vulnerability residing in the Windows Media Video Decoder. This flaw allows a remote, unauthorized attacker to trigger arbitrary code execution by sending a specially crafted video stream to the affected component over a network.

Affected products:
- Windows Media Video Decoder

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-100220

## CVE-2026-102204

CVE-2026-102204 is a local privilege escalation vulnerability in Microsoft Defender for Endpoint caused by improper link resolution before file access (link following). An authorized attacker can exploit this flaw to elevate their privileges on the host system.

Affected products:
- Defender for Endpoint

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102204

## CVE-2026-102227

CVE-2026-102227 describes a heap-based buffer overflow vulnerability in the Windows Resilient File System (ReFS). An authorized local attacker can exploit this flaw to execute arbitrary code with elevated privileges on the affected system.

Affected products:
- Resilient File System (ReFS)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102227

## CVE-2026-102231

CVE-2026-102231 is a security vulnerability in Visual Studio Code resulting from improper path equivalence resolution. This flaw allows a local, unauthorized attacker to bypass security features, potentially leading to unauthorized operations or privilege escalation depending on the environment context.

Affected products:
- Visual Studio Code

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102231
























Related in this roundup: [CVE-2026-102238](#cve-2026-102238), [CVE-2026-102233](#cve-2026-102233).

## CVE-2026-102233

CVE-2026-102233 identifies a missing authorization vulnerability in Microsoft Visual Studio Code. This flaw allows a local, unauthorized attacker to bypass security features, potentially leading to unauthorized access or privilege escalation on the affected system.

Affected products:
- Visual Studio Code

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102233























Related in this roundup: [CVE-2026-102238](#cve-2026-102238), [CVE-2026-102231](#cve-2026-102231).

## CVE-2026-103569

CVE-2026-103569 describes an out-of-bounds read vulnerability in the Windows Internet Key Exchange (IKE) extension. This vulnerability can be exploited by an unauthorized remote attacker to disclose sensitive information over the network.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103569






















Related in this roundup: [CVE-2026-69705](#cve-2026-69705), [CVE-2026-69883](#cve-2026-69883), [CVE-2026-83770](#cve-2026-83770), [CVE-2026-97814](#cve-2026-97814), [CVE-2026-108130](#cve-2026-108130), [CVE-2026-108132](#cve-2026-108132), [CVE-2026-96951](#cve-2026-96951).

## CVE-2026-103577

CVE-2026-103577 is a vulnerability in Microsoft QUIC resulting from insecure default variable initialization. This flaw allows a remote, unauthorized attacker to bypass security features during network communication, potentially compromising the integrity of protocol-level protections.

Affected products:
- Microsoft QUIC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-103577





















Related in this roundup: [CVE-2026-100219](#cve-2026-100219), [CVE-2026-105016](#cve-2026-105016).

## CVE-2026-105717

CVE-2026-105717 is a heap-based buffer overflow vulnerability in Microsoft Office Access. An unauthenticated attacker can exploit this flaw to achieve remote code execution over a network. Detection engineers should monitor for anomalous network traffic and process execution behavior originating from the Access application.

Affected products:
- Office Access

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105717

## CVE-2026-105718

CVE-2026-105718 describes an out-of-bounds read vulnerability in Microsoft Excel that can be leveraged by a remote unauthorized attacker to achieve remote code execution over a network. Detection should focus on monitoring anomalous network traffic originating from the Excel process and identifying unexpected child process creation or unauthorized file access patterns related to office applications.

Affected products:
- Excel

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105718

## CVE-2026-105728

CVE-2026-105728 describes an improper authentication vulnerability in Microsoft Dynamics Business Central. This flaw enables an unauthorized network-based attacker to disclose sensitive information, likely due to a failure in validating credentials or session tokens within the application's authentication flow.

Affected products:
- Dynamics Business Central

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-105728

## CVE-2026-108130

CVE-2026-108130 is a heap-based buffer overflow vulnerability residing in the Windows Virtualization-Based Security (VBS) Enclave. The flaw allows a local, authorized attacker to exploit the memory corruption to achieve privilege escalation within the system.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108130

















Related in this roundup: [CVE-2026-69705](#cve-2026-69705), [CVE-2026-69883](#cve-2026-69883), [CVE-2026-83770](#cve-2026-83770), [CVE-2026-97814](#cve-2026-97814), [CVE-2026-103569](#cve-2026-103569), [CVE-2026-108132](#cve-2026-108132), [CVE-2026-96951](#cve-2026-96951).

## CVE-2026-108132

CVE-2026-108132 is a double-free vulnerability in the Windows Kerberos component that allows an authorized local attacker to achieve privilege escalation by exploiting memory corruption.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108132
















Related in this roundup: [CVE-2026-69705](#cve-2026-69705), [CVE-2026-69883](#cve-2026-69883), [CVE-2026-83770](#cve-2026-83770), [CVE-2026-97814](#cve-2026-97814), [CVE-2026-103569](#cve-2026-103569), [CVE-2026-108130](#cve-2026-108130), [CVE-2026-96951](#cve-2026-96951).

## CVE-2026-108133

A vulnerability in Windows Modern Device Management (MDM) involves the release of an invalid pointer or reference, which can be exploited by an authorized local attacker to achieve privilege escalation.

Affected products:
- Windows Modern Device Management

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108133











Related in this roundup: [CVE-2026-108396](#cve-2026-108396).

## CVE-2026-108134

A use-after-free vulnerability exists in the Windows Autopilot component of the Windows operating system. An authorized local attacker can exploit this flaw to execute code or perform actions with elevated privileges on the target system.

Affected products:
- Windows Autopilot

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108134

## CVE-2026-108135

CVE-2026-108135 is a local privilege escalation vulnerability in the Windows Backup Engine caused by improper link resolution before file access. An authorized local attacker can exploit this flaw to gain higher privileges by leveraging the 'link following' vulnerability during the backup process.

Affected products:
- Windows Backup Engine

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108135

## CVE-2026-108136

CVE-2026-108136 is a use-after-free vulnerability within the Microsoft Windows Search Component that can be exploited by an authenticated local attacker to achieve privilege escalation on the affected system.

Affected products:
- Windows Search Component

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108136












Related in this roundup: [CVE-2026-105010](#cve-2026-105010).

## CVE-2026-108396

A time-of-check time-of-use (TOCTOU) race condition vulnerability exists in Windows Modern Device Management (MDM). An authenticated attacker with local access can exploit this flaw to escalate privileges on the target system.

Affected products:
- Windows Modern Device Management

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108396











Related in this roundup: [CVE-2026-108133](#cve-2026-108133).

## CVE-2026-108399

CVE-2026-108399 is a heap-based buffer overflow vulnerability in Microsoft Hyper-V that allows an authorized local attacker to achieve privilege escalation on the host system.

Affected products:
- Hyper-V

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108399

## CVE-2026-108400

CVE-2026-108400 describes an integer overflow or wraparound vulnerability in the Microsoft Windows Codecs Library. This vulnerability allows a remote, unauthorized attacker to execute arbitrary code over a network, potentially leading to full system compromise.

Affected products:
- Windows Codecs Library

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108400

## CVE-2026-108457

CVE-2026-108457 is an out-of-bounds write vulnerability in the Microsoft Windows PDF component that allows an unauthorized, network-based attacker to achieve remote code execution on the target system.

Affected products:
- Windows PDF

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108457

## CVE-2026-108458

CVE-2026-108458 is a use-after-free vulnerability in the Microsoft Remote Desktop Client that allows an unauthorized attacker to achieve remote code execution over a network. This flaw represents a critical security risk as it can be triggered by an attacker without prior authentication.

Affected products:
- Remote Desktop Client

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108458

## CVE-2026-108460

CVE-2026-108460 is a use-after-free vulnerability in the Windows Message Queuing (MSMQ) component. An unauthorized remote attacker can leverage this flaw to achieve arbitrary code execution over a network, presenting a significant risk to affected Windows systems.

Affected products:
- Windows Message Queuing

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108460

## CVE-2026-108461

CVE-2026-108461 is a use-after-free vulnerability within the Windows Broadcast DVR User Service. An authorized local attacker can exploit this flaw to escalate privileges on the affected system.

Affected products:
- Windows Broadcast DVR User Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108461

## CVE-2026-108463

CVE-2026-108463 is a vulnerability in Windows SmartScreen involving improper resolution of path equivalence, which allows an unauthorized remote attacker to bypass security checks over a network. Detection engineers should monitor for abnormal path resolutions or bypassed security warnings associated with file execution originating from network locations.

Affected products:
- Windows SmartScreen

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108463

## CVE-2026-108464

A use-after-free vulnerability in the Microsoft Software Protection Platform (SPP) allows a locally authenticated attacker to escalate privileges. The vulnerability occurs due to improper memory management, enabling the execution of arbitrary code or elevated system actions.

Affected products:
- Software Protection Platform

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108464

## CVE-2026-108465

CVE-2026-108465 is a use-after-free vulnerability in the Windows Update Delivery Optimization component that allows an authorized local attacker to achieve privilege escalation.

Affected products:
- Windows Update Delivery Optimization

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-108465

## CVE-2026-96951

Microsoft Windows Shell contains a command injection vulnerability that permits an unauthorized attacker to bypass security features over a network. This flaw is actively being exploited, requiring immediate mitigation in accordance with CISA BOD 26-04.

Affected products:
- Windows

Source: https://www.cve.org/CVERecord?id=CVE-2026-96951

Related in this roundup: [CVE-2026-69705](#cve-2026-69705), [CVE-2026-69883](#cve-2026-69883), [CVE-2026-83770](#cve-2026-83770), [CVE-2026-97814](#cve-2026-97814), [CVE-2026-103569](#cve-2026-103569), [CVE-2026-108130](#cve-2026-108130), [CVE-2026-108132](#cve-2026-108132).
