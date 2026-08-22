---
title: NachoMDM Vulnerability in Windows MDM Enrollment
slug: 2026-08-nachomdm
description: NachoMDM is a vulnerability within the Windows Mobile Device Management (MDM) enrollment process that allows an attacker to achieve UAC bypass and execute arbitrary code with SYSTEM privileges.
date: "2026-08-22T16:21:44Z"
type: rumour
types:
  - rumour
severities:
  - rumour
tags:
  - privilege-escalation
  - windows
  - mdm
vendors:
  - Microsoft
products:
  - Windows Mobile Device Management
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: NachoMDM is a vulnerability in Windows Mobile Device Management (MDM) enrollment processes that can be weaponized to achieve User Account Control (UAC) bypass.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The attack leverages the enrollment flow to execute arbitrary code with elevated permissions.
    confidence_band: high
references:
  - https://blog.amberwolf.com/blog/2026/august/weaponising-windows-mdm/
  - https://www.reddit.com/r/blueteamsec/comments/1vvew7y/nachomdm_weaponising_windows_mdm_for_uac_bypass/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit MDM enrollment policies and restrict self-enrollment privileges
      owner: IT Operations
      due: 48h
      evidence: Source advisory regarding weaponization of enrollment flow
  hunt_leads:
    - lead: Search for unauthorized or non-standard Windows MDM enrollment processes
      technique_id: T1548.002
      data_needed:
        - Event logs for Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: NachoMDM exploits the enrollment flow
---

NachoMDM identifies a critical security flaw in the Windows Mobile Device Management (MDM) enrollment mechanism. Discovered by researchers and detailed in August 2026, this vulnerability permits an attacker to intercept or manipulate the standard enrollment workflow, leading to a bypass of User Account Control (UAC). By weaponizing this process, an attacker can escalate privileges from a standard user context to NT AUTHORITY\SYSTEM. The vulnerability exploits the trust relationship and the elevated processes invoked during device configuration, allowing for arbitrary code execution. This is particularly significant for environments that allow self-enrollment or rely on automated MDM provisioning, as an attacker with initial local access can weaponize the enrollment sequence to gain full control of the Windows operating system.

## Impact

The vulnerability results in a total compromise of the host system through privilege escalation to SYSTEM level. Organizations utilizing Windows MDM enrollment are at risk, particularly those that permit non-administrative users to initiate enrollment processes. Successful exploitation allows for persistent access, credential theft, and full system control.

## Recommendation

Prioritized actions for detection engineering and security teams:

- Monitor the Windows MDM enrollment log (Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin) for anomalous initiation or high-frequency failures that may indicate enrollment process tampering.
- Review and restrict permissions for initiating MDM enrollment to authorized service accounts or administrative roles only.
- Audit existing MDM configurations to ensure that enrollment endpoints are strictly hardened and that no unauthorized enrollment profiles are active in the environment.
