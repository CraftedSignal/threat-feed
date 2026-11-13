---
brief_id: brief-2026-11-10-sap-patches
event_id: brief-2026-11-10-sap-patches
revision: 3
activity_at: "2026-11-13T10:15:15Z"
revision_history:
  - revision: 2
    at: "2026-11-10T16:31:37Z"
    checksum: sha256:1d5ec7b47c6e757e5fa0b6c103664279295b2471c9057347e086d5f69fb2ba4c
    summary: added coverage for SAP Software
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4420
  - revision: 3
    at: "2026-11-13T10:15:15Z"
    checksum: sha256:4de3b325623afbcbe9b279d8a9aaaf521ba0fbb602b29e67536e952c5b708ee2
    summary: added coverage for SAP NetWeaver AS ABAP +14 products
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - updates
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/sap-security-advisory-november-2026-monthly-rollup-av26-1137
title: SAP NetWeaver, Web Dispatcher, and Gateway Critical Vulnerabilities
slug: 2026-11-sap-patches
description: SAP released 42 security notes, including nine critical-severity vulnerabilities such as ICM2SHELL and ProxyGate, which allow unauthenticated remote code execution with <sid>adm privileges.
date: "2026-11-10T15:52:05Z"
lastmod: "2026-11-13T10:14:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
qa_status:
  verdict: pass
vendors:
  - SAP
products:
  - BusinessObjects
  - Gateway
  - NetWeaver
  - S4CRM
  - SAP ABAP Developer Tools
  - SAP ABAP Platform
  - SAP astonish
  - SAP BusinessObjects Business Intelligence Platform
  - SAP Cloud SDK for AI
  - SAP Cloud SDK for Python
  - SAP Gateway
  - SAP Host Agent
  - SAP Internet Graphics Service
  - SAP NetWeaver Application Server
  - SAP NetWeaver AS ABAP
  - SAP NetWeaver AS Java EDM Application
  - SAP NetWeaver Knowledge Management
  - SAP Software
  - SAP Web Dispatcher
  - Web Dispatcher
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The Onapsis Research Labs provided SAP a working exploit that achieves full, unauthenticated remote code execution end to end, running arbitrary commands as <sid>adm on the target system.
    confidence_band: high
cves:
  - id: CVE-2026-109795
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-109798
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-109803
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-120017
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-76964
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-76965
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-89103
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-89119
    cvss: 9.6
    kev_status: "false"
  - id: CVE-2026-89126
    cvss: 10
    kev_status: "false"
references:
  - https://www.securityweek.com/sap-patches-critical-icm2shell-proxygate-vulnerabilities/
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4420
  - https://cyber.gc.ca/en/alerts-advisories/sap-security-advisory-november-2026-monthly-rollup-av26-1137
  - https://support.sap.com/en/my-support/knowledge-base/security-notes-news/november-2026.html
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch critical SAP vulnerabilities per November 2026 bulletin
      owner: IT Operations
      due: 48h
      evidence: SAP has published 42 new and updated security advisories, including nine that address critical-severity vulnerabilities.
    - action: Inventory SAP software versions
      owner: IT Operations
      due: 48h
      evidence: SAP Patch Day necessitates identifying affected deployments
    - action: Inventory all SAP assets listed in the advisory and cross-reference with internal versions.
      owner: IT Operations
      due: 48h
      evidence: Source identifies multiple product versions as affected.
  hunt_leads:
    - lead: Identify unauthenticated attempts to manipulate WebSocket fragments in ICM/Web Dispatcher logs
      technique_id: T1203
      data_needed:
        - SAP ICM/Web Dispatcher internal trace and access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: ICM2SHELL issue is related to reassembling large WebSocket messages, which may be split into fragments.
    - lead: Audit Gateway prxyinfo configurations for permissive access
      technique_id: T1190
      data_needed:
        - SAP Gateway configuration files (prxyinfo)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: ProxyGate is related to the prxyinfo access-control list, which should restrict requests to trusted networks only.
  mitigation_plan:
    - priority: immediate
      action: Apply security notes released in the November 2026 SAP bulletin
      owner: IT Operations
      addresses: CVE-2026-76964, CVE-2026-89126, CVE-2026-89103, CVE-2026-120017, CVE-2026-109803, CVE-2026-76965, CVE-2026-109795, CVE-2026-89119, CVE-2026-109798
      evidence: SAP has published 42 new and updated security advisories, including nine that address critical-severity vulnerabilities.
    - priority: immediate
      action: Apply relevant SAP security patches for November 2026
      owner: IT Operations
      addresses: Multiple SAP security vulnerabilities
      evidence: Source advises applying latest SAP patches
    - priority: immediate
      action: Review the November 2026 SAP security notes and apply relevant patches to identified systems.
      owner: IT Operations
      addresses: All affected SAP products identified in the advisory
      evidence: The Cyber Centre encourages users and administrators to review the provided web link and apply any necessary updates.
updates:
  - at: "2026-11-10T16:30:47Z"
    level: L1
    summary: added coverage for SAP Software
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4420
  - at: "2026-11-13T10:14:39Z"
    level: L1
    summary: added coverage for SAP NetWeaver AS ABAP +14 products
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/sap-security-advisory-november-2026-monthly-rollup-av26-1137
---

SAP published its November 2026 security bulletin containing 42 new and updated security notes. Nine of these are rated critical, including maximum-severity flaws in NetWeaver, Web Dispatcher, and Gateway components. Key vulnerabilities include ICM2SHELL (CVE-2026-76964, CVE-2026-89126) related to improper WebSocket message fragmentation handling, and ProxyGate (CVE-2026-89103) involving a bypass of the prxyinfo access-control list. Both vulnerabilities permit unauthenticated remote code execution (RCE) with &lt;sid>adm privileges. Additionally, CVE-2026-120017 addresses a missing authentication bug in NetWeaver that can lead to full system compromise via user impersonation.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary operating system commands with &lt;sid>adm privileges, resulting in full control over affected SAP systems. Researchers have confirmed that a working exploit exists for ICM2SHELL, which reproduces on multiple SAP Kernel releases.

## Recommendation
- Immediately identify all SAP environments using the affected NetWeaver, Web Dispatcher, and Gateway components.
- Prioritize patching the nine critical vulnerabilities listed in the November 2026 SAP security bulletin, specifically focusing on CVE-2026-76964, CVE-2026-89126, and CVE-2026-89103.
- Review and harden the prxyinfo access-control list configurations to restrict Gateway access to trusted networks only.
- Consult the official SAP security portal for the full list of 42 notes and apply available patches as directed.
