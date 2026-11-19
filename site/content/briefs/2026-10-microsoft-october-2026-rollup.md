---
brief_id: brief-2026-10-microsoft-october-2026-rollup
event_id: brief-2026-10-microsoft-october-2026-rollup
revision: 2
activity_at: "2026-11-19T16:15:02Z"
revision_history:
  - revision: 2
    at: "2026-11-19T16:15:02Z"
    checksum: sha256:d44abef21d5489e432020e3ef60b19ff170dd615147f70c06553f69ed91981f9
    summary: exploited:true; KEV CVE-2026-96951
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Microsoft October 2026 Monthly Security Updates
slug: 2026-10-microsoft-october-2026-rollup
description: Microsoft's October 2026 security rollup addresses multiple vulnerabilities across its product ecosystem, including CVE-2026-96951 which is confirmed as actively exploited in the wild.
date: "2026-10-13T23:44:18Z"
lastmod: "2026-11-19T16:14:17Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-10-13T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source confirmed active exploitation
tags:
  - vulnerability
  - microsoft
  - cve
  - patch-management
vendors:
  - Microsoft
products:
  - .NET
  - ASP.NET Core
  - Microsoft Exchange Server (2016, 2019, Subscription Edition)
  - Microsoft Office (365, LTSC 2021, LTSC 2024, Online Server)
  - Microsoft SharePoint Server (2016, 2019, Subscription Edition)
  - Microsoft SQL Server
  - Windows
  - Windows Server (2012, 2012 R2, 2016, 2019, 2022, 2025)
product_versions:
  - product: .NET
    range: 8.0, 9.0, 10.0, 11.0
  - product: ASP.NET Core
    range: 8.0, 9.0, 10.0, 11.0
  - product: Microsoft SQL Server
    range: 2017, 2019, 2022, 2025
  - product: Windows
    range: 10, 11
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2012
  - Windows Server 2012 R2
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
  - Windows Server 2025
cves:
  - id: CVE-2026-96951
    cvss: 8.8
    kev: true
    kev_status: "true"
  - id: CVE-2026-84008
    cvss: 7.5
    kev_status: unknown
  - id: CVE-2026-96957
    cvss: 8.8
    kev_status: unknown
  - id: CVE-2026-96959
    cvss: 7.5
    kev_status: unknown
  - id: CVE-2026-96958
    cvss: 7.5
    kev_status: unknown
  - id: CVE-2026-66822
    cvss: 5.9
    kev_status: unknown
  - id: CVE-2026-96229
    kev_status: unknown
  - id: CVE-2026-96234
    kev_status: unknown
  - id: CVE-2026-96238
    kev_status: unknown
  - id: CVE-2026-96960
    kev_status: unknown
references:
  - https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-96951
  - https://cyber.gc.ca/en/alerts-advisories/microsoft-security-advisory-october-2026-monthly-rollup-av26-1038
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-66822
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-84008
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96229
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96234
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96238
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96957
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96958
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96959
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96960
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Microsoft products listed in the October 2026 security rollup
      owner: IT Operations
      due: 24h
      evidence: Microsoft security advisory AV26-1038
  mitigation_plan:
    - priority: immediate
      action: Apply October 2026 monthly rollup updates
      owner: IT Operations
      addresses: CVE-2026-96951
      evidence: CISA KEV catalog entry
updates:
  - at: "2026-10-14T03:24:23Z"
    level: L2
    summary: added CVE-2026-96238
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96238
  - at: "2026-10-14T03:37:16Z"
    level: L2
    summary: added CVE-2026-96957
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96957
  - at: "2026-10-14T03:43:51Z"
    level: L2
    summary: added CVE-2026-96958 +1
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96959
  - at: "2026-10-14T03:43:54Z"
    level: L2
    summary: added CVE-2026-66822
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96960
  - at: "2026-11-19T16:14:17Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-96951
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Microsoft's October 2026 security release includes patches for a comprehensive list of products, ranging from core Windows OS components and .NET frameworks to enterprise applications like Exchange Server, SharePoint, and SQL Server. This monthly rollup is particularly urgent due to the disclosure of active, in-the-wild exploitation of CVE-2026-96951. The Cybersecurity and Infrastructure Security Agency (CISA) has formally added CVE-2026-96951 to its Known Exploited Vulnerabilities (KEV) catalog, underscoring the necessity for immediate patch deployment. Organizations should prioritize updating internet-facing infrastructure and critical server assets that fall within the scope of the affected product list, which includes various versions of Windows Server, Microsoft Office, and Azure-integrated services.

## Impact

Successful exploitation of the vulnerabilities addressed in this rollup, particularly the actively exploited CVE-2026-96951, could lead to unauthorized system access, potential code execution, or privilege escalation. These vulnerabilities affect a wide surface area, including enterprise-grade servers and endpoint applications. Given the inclusion of CVE-2026-96951 in the CISA KEV catalog, adversaries are actively targeting this flaw, increasing the risk of widespread compromise for unpatched systems across all sectors.

## Recommendation

* Prioritize the deployment of October 2026 security updates for all affected Microsoft products, with immediate focus on those hosting critical or internet-exposed services.
* Verify the installation of patches by reviewing the official Microsoft Security Update Guide for October 2026.
* Monitor internal assets for indicators of exploitation related to CVE-2026-96951, ensuring that security logs are ingested and reviewed for anomalous process creation or unauthorized network traffic on exposed servers.
* Ensure that CISA KEV monitoring workflows are updated to include CVE-2026-96951 for internal compliance and risk assessment.
