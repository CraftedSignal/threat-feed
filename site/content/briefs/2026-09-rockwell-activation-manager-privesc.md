---
title: Privilege Escalation Vulnerability in Rockwell Automation FactoryTalk Activation Manager
slug: 2026-09-rockwell-activation-manager-privesc
description: Rockwell Automation FactoryTalk Activation Manager versions V5.02 and below are vulnerable to local privilege escalation via insecure installer custom actions that spawn SYSTEM-level console windows.
date: "2026-09-01T17:11:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rockwellautomation:factorytalk_activation_manager:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - industrial-control-systems
  - windows
  - ics
vendors:
  - Rockwell Automation
products:
  - FactoryTalk Activation Manager (<= V5.02)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker with Windows credentials could hijack these console windows to obtain a SYSTEM-level command prompt.
    confidence_band: high
cves:
  - id: CVE-2026-16675
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-244-04
  - https://www.cve.org/CVERecord?id=CVE-2026-16675
rules:
  - title: Detect FactoryTalk Activation Manager Privilege Escalation Attempt
    description: Detects the spawning of cmd.exe or other shells by FactoryTalk Activation Manager installer processes, which may indicate exploitation of CVE-2026-16675.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all FactoryTalk Activation Manager instances to V5.03.
      owner: IT Operations
      due: 72h
      evidence: Vendor recommendation for CVE-2026-16675.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to V5.03.
      owner: IT Operations
      addresses: CVE-2026-16675
      evidence: Vendor remediation steps.
---

Rockwell Automation FactoryTalk Activation Manager versions V5.02 and below are susceptible to a privilege escalation vulnerability tracked as CVE-2026-16675. The flaw originates from custom actions implemented within the software's installer process. During installation or repair operations, these custom actions spawn visible console windows that operate with SYSTEM-level privileges. An attacker who has already achieved local access on a Windows system can interact with or hijack these exposed console windows to execute arbitrary commands with SYSTEM permissions. This vulnerability is particularly critical in industrial environments where the affected management software may be present on engineering workstations or server infrastructure, potentially granting an attacker full control over the host OS. The vendor has released version V5.03 to address this security defect.

## Impact

Successful exploitation allows a local authenticated user to gain full SYSTEM privileges on the affected host. This provides the attacker with total control over system processes, sensitive files, and configuration data. The impact is significant for industrial environments where engineering workstations could be compromised, potentially facilitating lateral movement into sensitive operational technology networks.

## Recommendation

Prioritized actions for security and IT teams:
- Upgrade all instances of Rockwell Automation FactoryTalk Activation Manager to version V5.03 or later immediately to patch CVE-2026-16675.
- Audit industrial workstations for installations of FactoryTalk Activation Manager V5.02 and below to prioritize remediation.
- Implement restrictive access controls for users on machines running industrial management software to limit the scope of potential local exploitation.
- Use the provided Sigma rule to detect suspicious console window activity spawned by installation processes during software maintenance windows.
