---
brief_id: brief-2026-11-11-microsoft-office-vulnerabilities
event_id: brief-2026-11-11-microsoft-office-vulnerabilities
revision: 2
activity_at: "2026-11-17T09:06:45Z"
revision_history:
  - revision: 2
    at: "2026-11-17T09:06:45Z"
    checksum: sha256:f5fa545fab14455c3a2ddf117961e8bc681d798ae8f3162766f42900345612cd
    summary: added coverage for SharePoint Server Subscription Edition (< 16.0.20326.20278) +6 products
    changed_fields:
      - action_plan
      - affected_products
      - content
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - summary
      - tags
      - title
      - ttps
      - updates
    source_urls:
      - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-products-could-allow-for-remote-code-execution_2026-134
title: 'Microsoft Office and SharePoint: Multiple Remote Code Execution Vulnerabilities'
slug: 2026-11-microsoft-office-vulnerabilities
description: Multiple Microsoft Office and SharePoint products are vulnerable to remote code execution due to deserialization, authorization, and buffer overflow flaws (CVE-2026-124222, CVE-2026-124223, CVE-2026-126526).
date: "2026-11-11T13:53:23Z"
lastmod: "2026-11-17T09:06:02Z"
type: advisory
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
  validation_status: Patch installation needs verification across the server estate.
tags:
  - vulnerability
  - rce
  - microsoft-office
  - sharepoint
vendors:
  - Microsoft
products:
  - Microsoft 365 Apps for Enterprise (< https://aka.ms/OfficeSecurityReleases)
  - Microsoft Office
  - Microsoft Office 365 for Mac
  - Microsoft Office LTSC 2021
  - Microsoft Office LTSC 2024
  - Microsoft Office LTSC for Mac 2021
  - Microsoft Office LTSC for Mac 2024
  - SharePoint
  - SharePoint Server Subscription Edition
product_versions:
  - product: Microsoft Office 365 for Mac
    range: < 16.115.26110837
  - product: Microsoft Office LTSC 2021
    range: < 16.0.14334.21048
  - product: Microsoft Office LTSC 2024
    range: < 16.0.17932.21140
  - product: Microsoft Office LTSC for Mac 2021
    range: < 16.115.26110837
  - product: Microsoft Office LTSC for Mac 2024
    range: < 16.115.26110837
  - product: SharePoint Server Subscription Edition
    range: < 16.0.20326.20278
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Deserialization of untrusted data in Microsoft Office SharePoint (CVE-2026-124223) and Improper authorization in Microsoft Office SharePoint (CVE-2026-124222).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Heap-based buffer overflow in Microsoft Office OneNote (CVE-2026-126526).
    confidence_band: high
cves:
  - id: CVE-2026-124222
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-124223
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-126526
    cvss: 8.8
    kev_status: "false"
references:
  - https://www.ncsc.nl/alerts/ernstige-kwetsbaarheden-in-microsoft-office
  - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-products-could-allow-for-remote-code-execution_2026-134
  - https://cveawg.mitre.org/api/cve/CVE-2026-124222
  - https://cveawg.mitre.org/api/cve/CVE-2026-124223
  - https://cveawg.mitre.org/api/cve/CVE-2026-126526
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all SharePoint and Office environments using the latest security updates provided by Microsoft
      owner: IT Operations
      due: 48h
      evidence: NCSC-NL advises that the available security updates be installed as soon as possible.
    - action: Deploy identified Microsoft security patches for SharePoint and Office suite products.
      owner: IT Operations
      due: 48h
      evidence: Advisory recommends immediate application of updates.
  hunt_leads:
    - lead: Monitor SharePoint access logs for unusual administrative activity or successful logins from atypical IP addresses
      technique_id: T1078
      data_needed:
        - SharePoint Unified Audit Logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The advisory states that an attacker could impersonate a user and perform malicious actions.
    - lead: Investigate for abnormal exploitation attempts targeting SharePoint web-server logs (POST requests containing serialized payloads) or OneNote abnormal crashes indicative of memory corruption.
      technique_id: T1190
      data_needed:
        - IIS/web server access logs
        - Endpoint crash logs (WER/Windows Event Logs)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies deserialization of untrusted data and buffer overflow as vulnerability classes.
  mitigation_plan:
    - priority: immediate
      action: Apply Microsoft security updates
      owner: IT Operations
      addresses: SharePoint and Office vulnerabilities
      evidence: Microsoft has made security updates available that address these vulnerabilities.
    - priority: immediate
      action: Apply relevant patches for SharePoint and Office products to remediate CVE-2026-124222, CVE-2026-124223, and CVE-2026-126526.
      owner: IT Operations
      addresses: CVE-2026-124222, CVE-2026-124223, CVE-2026-126526
      evidence: Vendor security update requirements.
updates:
  - at: "2026-11-17T09:06:02Z"
    level: L2
    summary: added coverage for SharePoint Server Subscription Edition (< 16.0.20326.20278) +6 products
    sources:
      - ms-isac
    source_urls:
      - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-products-could-allow-for-remote-code-execution_2026-134
---

## Overview
Multiple vulnerabilities have been discovered across Microsoft Office, Microsoft 365 Apps, and SharePoint Server. These flaws include deserialization of untrusted data and improper authorization in Microsoft SharePoint, as well as a heap-based buffer overflow in Microsoft Office OneNote. Successful exploitation allows an attacker to execute arbitrary code with the privileges of the logged-in user, potentially leading to unauthorized data modification, account creation, or program execution.

## Impact
Exploitation results in the attacker gaining the privileges of the logged-on user. If the user possesses administrative rights, the impact is elevated, potentially granting full system compromise.

## Recommendation
- Patch all affected systems immediately using the vendor-provided updates found on the official Microsoft Security Update pages.
- Prioritize remediation for systems with users operating with administrative privileges to minimize risk.
- Follow the CIS Controls 7.1, 7.2, 7.4, 7.7, and 12.1 for standardized vulnerability and patch management.
- Enforce the principle of least privilege to restrict the impact of potential client-side exploitation.
