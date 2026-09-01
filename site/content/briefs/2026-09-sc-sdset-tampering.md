---
title: Service Security Descriptor Tampering via Sc.exe
slug: 2026-09-sc-sdset-tampering
description: Adversaries can exploit the Windows 'sc.exe' utility to modify service Discretionary Access Control Lists (DACLs) via the 'sdset' command, facilitating privilege escalation and persistence by granting unauthorized service access.
date: "2026-09-01T12:24:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - persistence
  - windows
  - security-descriptor
  - sc-exe
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Detects suspicious DACL modifications to allow access to a service from a suspicious trustee.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sc_sdset_allow_service_changes.yml
  - https://twitter.com/0gtweet/status/1628720819537936386
rules:
  - title: Detect Service Security Descriptor Tampering via Sc.exe
    description: Detects the use of 'sc.exe sdset' to modify a service DACL, potentially granting excessive permissions to interactive users, the 'everyone' group, or built-in administrators.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for 'sc.exe sdset' activity.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides detection logic for this TTP.
  hunt_leads:
    - lead: Audit existing Windows services for non-standard security descriptors.
      technique_id: T1543.003
      data_needed:
        - 'Registry data: HKLM\SYSTEM\CurrentControlSet\Services\*\Security'
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers modify security descriptors to gain unauthorized service access.
  mitigation_plan:
    - priority: medium_term
      action: Restrict local administrative privileges to prevent arbitrary service modification.
      owner: IT Operations
      addresses: Privilege Escalation
      evidence: This technique requires administrative rights.
---

Adversaries often use the Windows Service Control utility (sc.exe) to maintain persistence or escalate privileges by manipulating service security descriptors. By utilizing the 'sdset' command, an attacker can modify the Discretionary Access Control List (DACL) of a target service, allowing them to assign broad or specific access rights to arbitrary users or security principals. This technique is particularly effective for granting 'everyone' or specific logon users (such as interactive users or service accounts) control over sensitive system services. Because this activity requires legitimate administrative or SYSTEM privileges, it is frequently observed during the post-compromise stage of an intrusion to ensure continued access or to bypass service-level restrictions. Defenders should monitor for sc.exe command lines that incorporate Security Descriptor Definition Language (SDDL) strings designed to explicitly permit new access rights.

## Impact

Successful manipulation of service security descriptors allows an attacker to gain control over high-privilege services, leading to unauthorized code execution as SYSTEM. This technique can be used to reconfigure services to run malicious binaries or to modify the behavior of existing services, effectively bypassing standard Windows service security hardening.

## Recommendation

Deploy the provided Sigma rule to detect suspicious use of 'sc.exe sdset'. Prioritize monitoring for administrative commands that modify DACLs, especially those referencing wide-access principals like 'Everyone' (WD) or 'Interactive Users' (IU). Enable Sysmon Event ID 1 (Process Creation) to capture the full command-line arguments, as these are required to inspect the SDDL string.
