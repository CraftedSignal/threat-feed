---
brief_id: brief-2026-10-21-october-patch-tuesday
event_id: brief-2026-10-21-october-patch-tuesday
revision: 1
activity_at: "2026-10-21T07:58:52Z"
title: Microsoft October 2026 Security Updates
slug: 2026-10-october-patch-tuesday
description: Microsoft addressed 1,413 vulnerabilities including 75 critical flaws and an exploited zero-day (CVE-2026-96951) bypass in Windows Shell that circumvents Mark of the Web protections.
date: "2026-10-21T07:58:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source-derived content checked for accuracy and technical alignment.
cpes:
  - cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:outlook_web:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_26h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:x64:*
tags:
  - patch-tuesday
  - windows
  - vulnerability
  - identity
  - zero-day
vendors:
  - Microsoft
products:
  - Windows
  - Office
  - Excel
  - PowerPoint
  - Visio
  - DHCP Server
  - Microsoft QUIC
  - PostScript Printer Driver
  - Active Directory Federation Services
  - Outlook
  - Windows Shell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: Preview Pane-triggered exploitation dominates this release with 23 CVEs across Office applications including Excel, PowerPoint, and Visio.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553.005
    technique_name: Mark-of-the-Web Bypass
    evidence: Successful exploitation allows an attacker to evade Mark of the Web (MOTW) defenses, the trust boundary mechanism that triggers Protected View in Office documents and SmartScreen warnings.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: CVE-2026-108398 ... allows execution of unauthorized code within a protected process context.
    confidence_band: high
cves:
  - id: CVE-2026-108398
    kev_status: unknown
  - id: CVE-2026-70229
    kev_status: unknown
  - id: CVE-2026-96951
    cvss: 8.8
    epss: 0.01512
    kev_status: "false"
references:
  - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-october-2026/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy October 2026 security updates across all Windows and Office environments.
      owner: IT Operations
      due: 24h
      evidence: Microsoft October 2026 Patch Tuesday bulletin
  mitigation_plan:
    - priority: immediate
      action: Prioritize patching Windows Shell (CVE-2026-96951) and critical Identity service components (AD DS/AD FS).
      owner: IT Operations
      addresses: CVE-2026-96951, CVE-2026-70229
      evidence: Confirmed active exploitation of Windows Shell
---

The October 2026 Microsoft security release contains 1,413 CVEs, featuring one exploited zero-day (CVE-2026-96951) and two publicly disclosed zero-days. Notable risks include remote code execution (RCE) in identity services (AD DS, AD FS), critical RCE vulnerabilities in Microsoft Outlook, and 23 preview-pane triggered flaws in Office applications that allow code execution with minimal user interaction.

## Impact

The disclosed vulnerabilities include 75 critical-rated items. CVE-2026-96951 allows attackers to strip Mark of the Web (MOTW) protections, facilitating the execution of malicious payloads by bypassing SmartScreen and Office Protected View. Unauthenticated RCEs in DHCP, Microsoft QUIC, and printer drivers enable potential lateral movement. Identity fabric compromise via AD DS and AD FS could allow for complete domain takeover or authentication boundary bypass.

## Recommendation

- Prioritize patching of CVE-2026-96951 (Windows Shell), CVE-2026-70229 (AD DS), and the five critical Outlook RCE vulnerabilities.
- Audit internal DHCP and QUIC-enabled services for exposure to unauthenticated network access.
- Evaluate the exposure of AD FS and AD DS interfaces and implement restricted access to mitigate lateral movement risk.
- For .NET environments, review existing WDAC policies and ensure assembly loading protections are maintained to mitigate CVE-2026-108398.
