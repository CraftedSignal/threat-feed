---
brief_id: brief-2026-11-06-windows-paint-rce
event_id: brief-2026-11-06-windows-paint-rce
revision: 3
activity_at: "2026-11-06T23:59:50Z"
revision_history:
  - revision: 2
    at: "2026-11-06T15:20:25Z"
    checksum: sha256:b0819935803a85a0a8bfe36f26574f956a678f4b917c83ba64441c13aa22d174
    summary: OS windows
    changed_fields:
      - affected_os
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/microsoft-paint-rce-cve-2026-83844-store-fix-nov-2026
  - revision: 3
    at: "2026-11-06T23:59:50Z"
    checksum: sha256:a6f50b23c70dcdc0e24a789f9b11ca5db1e2d212c53cb10c9decd111df5dd72b
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CDE61D1E-0968-57F8-AEB6-CFE5CFEB3EBB&utm_source=rss&utm_medium=rss
title: 'Microsoft Windows Paint: Remote code execution (CVE-2026-83844)'
slug: 2026-11-windows-paint-rce
description: A critical remote code execution vulnerability (CVE-2026-83844) in Microsoft Windows Paint allows attackers to execute arbitrary code when a victim opens a specially crafted image file.
date: "2026-11-06T11:17:20Z"
lastmod: "2026-11-06T23:59:11Z"
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
cpes:
  - cpe:2.3:a:microsoft:paint:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CDE61D1E-0968-57F8-AEB6-CFE5CFEB3EBB&utm_source=rss&utm_medium=rss
tags:
  - windows
  - vulnerability
  - rce
vendors:
  - Microsoft
products:
  - Paint (< 11.2609.401.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability can be misused by an attacker who opens a specially crafted image in Windows Paint.
    confidence_band: high
cves:
  - id: CVE-2026-83844
    cvss: 8.1
    epss: 0.00734
    kev_status: "false"
references:
  - https://www.ncsc.nl/alerts/kwetsbaarheid-in-microsoft-windows-paint-met-risico-op-misbruik
  - https://pwn.watch/i/microsoft-paint-rce-cve-2026-83844-store-fix-nov-2026
  - https://getrff.com/blog/windows-paint-cve-2026-83844-store-fix-missing/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83844
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-83844
  - https://sploitus.com/exploit?id=CDE61D1E-0968-57F8-AEB6-CFE5CFEB3EBB&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Microsoft Windows Paint to version 11.2609.401.0 or later on all managed endpoints.
      owner: IT Operations
      due: 72h
      evidence: NCSC advisory recommends installing the available update.
  hunt_leads:
    - lead: Monitor for Paint.exe spawning child processes (e.g., cmd.exe, powershell.exe, wscript.exe) which is indicative of malicious payload execution.
      technique_id: T1203
      data_needed:
        - Sysmon Event ID 1 (Process Creation)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability allows an attacker to execute their own commands on the computer.
  mitigation_plan:
    - priority: immediate
      action: Deploy update to version 11.2609.401.0
      owner: IT Operations
      addresses: CVE-2026-83844
      evidence: Microsoft release version 11.2609.401.0
updates:
  - at: "2026-11-06T15:19:39Z"
    level: L1
    summary: OS windows
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/microsoft-paint-rce-cve-2026-83844-store-fix-nov-2026
  - at: "2026-11-06T23:59:11Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CDE61D1E-0968-57F8-AEB6-CFE5CFEB3EBB&utm_source=rss&utm_medium=rss
---

A vulnerability (CVE-2026-83844) exists in Microsoft Windows Paint, rated with a risk score of 8.1. An attacker can exploit this flaw by enticing a user to open a specially crafted image file within the application. Successful exploitation permits the execution of arbitrary commands, enabling unauthorized access, data manipulation, or the installation of malicious software. No active exploitation has been reported as of the date of the advisory.

## Impact
Successful exploitation allows an attacker to gain control over the affected system, enabling the viewing, modification, or deletion of data and the execution of arbitrary programs.

## Recommendation
- Update Microsoft Windows Paint to version 11.2609.401.0 or later via the Microsoft Store or standard Windows update channels.
- If the application version is unknown, conduct an inventory of installed software versions to identify systems requiring updates.
