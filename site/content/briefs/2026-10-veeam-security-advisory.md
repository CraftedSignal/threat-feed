---
brief_id: brief-2026-10-28-veeam-security-advisory
event_id: brief-2026-10-28-veeam-security-advisory
revision: 2
activity_at: "2026-10-29T06:23:46Z"
revision_history:
  - revision: 2
    at: "2026-10-29T06:23:46Z"
    checksum: sha256:5281c84801a6a9d55a2925b77d49e264e7bf97bfb7cb58298cab9efd32391ac2
    summary: added CVE-2026-105477 +3; OS windows; OS linux
    changed_fields:
      - affected_os
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/veeam-october-2026-security-updates-cve-2026-108142
title: 'Veeam: Security updates for multiple backup and management products'
slug: 2026-10-veeam-security-advisory
description: Veeam has released security updates for multiple products, including Veeam Agent for Linux, Veeam Backup and Replication, Veeam Backup for Microsoft 365, and Veeam ONE, to address undisclosed vulnerabilities.
date: "2026-10-28T23:59:37Z"
lastmod: "2026-10-29T06:23:12Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Verified against Cyber Centre advisory and Veeam KB links
tags:
  - security-advisory
  - patch-management
  - product-news
vendors:
  - Veeam
products:
  - Veeam Agent for Linux (< 13.1.2)
  - Veeam Backup and Replication (< 13.0.3, < 13.1.2)
  - Veeam Backup for Microsoft 365 (<= 8.5.0.1014, <= 8.6.0.1102)
  - Veeam ONE (<= 13.1.0.7233)
affected_os:
  - Windows
  - Linux
cves:
  - id: CVE-2026-105477
    kev_status: "false"
  - id: CVE-2026-106076
    kev_status: "false"
  - id: CVE-2026-106077
    kev_status: "false"
  - id: CVE-2026-106078
    kev_status: "false"
  - id: CVE-2026-108142
    kev_status: unknown
references:
  - https://cyber.gc.ca/en/alerts-advisories/veeam-security-advisory-av26-1096
  - https://www.veeam.com/kb4957
  - https://www.veeam.com/kb4948
  - https://www.veeam.com/kb4951
  - https://pwn.watch/i/veeam-october-2026-security-updates-cve-2026-108142
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Veeam Agent for Linux to 13.1.2, Veeam Backup and Replication to 13.1.2, and apply available patches for Veeam Backup for Microsoft 365 and Veeam ONE.
      owner: IT Operations
      addresses: Multiple vulnerabilities across Veeam suite
      evidence: Advisory AV26-1096 and associated Veeam KBs
updates:
  - at: "2026-10-29T06:23:12Z"
    level: L2
    summary: added CVE-2026-105477 +3; OS windows; OS linux
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/veeam-october-2026-security-updates-cve-2026-108142
---

On October 27, 2026, the Cyber Centre published an advisory regarding security vulnerabilities affecting several Veeam products. While specific vulnerability details are undisclosed, the manufacturer has released updates to mitigate these security risks. Administrators are encouraged to verify current versions and apply the patches listed in the official Veeam knowledge base articles.

## Recommendation

* Inventory all environments for the affected Veeam products listed below.
* Upgrade Veeam Agent for Linux to version 13.1.2 or later.
* Upgrade Veeam Backup and Replication to version 13.1.2 or later (ensuring all versions prior to 13.0.3 and 13.1.2 are addressed).
* Upgrade Veeam Backup for Microsoft 365 to the latest version, ensuring migration past build 8.6.0.1102.
* Upgrade Veeam ONE to the version specified in KB4951 (post-13.1.0.7233).
* Monitor the Veeam Support Knowledge Base for further details as they are released.
