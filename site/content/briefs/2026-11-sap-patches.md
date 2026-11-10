---
brief_id: brief-2026-11-10-sap-patches
event_id: brief-2026-11-10-sap-patches
revision: 1
activity_at: "2026-11-10T15:52:05Z"
title: SAP NetWeaver, Web Dispatcher, and Gateway Critical Vulnerabilities
slug: 2026-11-sap-patches
description: SAP released 42 security notes, including nine critical-severity vulnerabilities such as ICM2SHELL and ProxyGate, which allow unauthenticated remote code execution with <sid>adm privileges.
date: "2026-11-10T15:52:05Z"
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
  - NetWeaver
  - Web Dispatcher
  - Gateway
  - S4CRM
  - BusinessObjects
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
---

SAP published its November 2026 security bulletin containing 42 new and updated security notes. Nine of these are rated critical, including maximum-severity flaws in NetWeaver, Web Dispatcher, and Gateway components. Key vulnerabilities include ICM2SHELL (CVE-2026-76964, CVE-2026-89126) related to improper WebSocket message fragmentation handling, and ProxyGate (CVE-2026-89103) involving a bypass of the prxyinfo access-control list. Both vulnerabilities permit unauthenticated remote code execution (RCE) with &lt;sid>adm privileges. Additionally, CVE-2026-120017 addresses a missing authentication bug in NetWeaver that can lead to full system compromise via user impersonation.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary operating system commands with &lt;sid>adm privileges, resulting in full control over affected SAP systems. Researchers have confirmed that a working exploit exists for ICM2SHELL, which reproduces on multiple SAP Kernel releases.

## Recommendation
- Immediately identify all SAP environments using the affected NetWeaver, Web Dispatcher, and Gateway components.
- Prioritize patching the nine critical vulnerabilities listed in the November 2026 SAP security bulletin, specifically focusing on CVE-2026-76964, CVE-2026-89126, and CVE-2026-89103.
- Review and harden the prxyinfo access-control list configurations to restrict Gateway access to trusted networks only.
- Consult the official SAP security portal for the full list of 42 notes and apply available patches as directed.
