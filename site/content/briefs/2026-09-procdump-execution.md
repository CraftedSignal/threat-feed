---
title: Detection of Sysinternals Procdump Execution
slug: 2026-09-procdump-execution
description: Detection of the execution of the Sysinternals Procdump utility, which is frequently used by attackers to dump process memory for credential access.
date: "2026-09-01T12:25:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - stealth
  - windows
  - tool-abuse
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The utility is frequently used by attackers to dump process memory for credential access.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Adversaries frequently rename or use the official binary to target the Local Security Authority Subsystem Service.
    confidence_band: med
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml
rules:
  - title: Detect Procdump Execution
    description: Detects usage of the Sysinternals Procdump utility which is often used for memory dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - stealth
    techniques:
      - T1003.001
      - T1036
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
    - action: Deploy Sigma rule to monitor for Procdump execution
      owner: Detection Engineering
      due: 48h
      evidence: Source rule requirement
  mitigation_plan:
    - priority: medium_term
      action: Restrict procdump.exe execution via AppLocker or EDR policy to authorized users only
      owner: IT Operations
      addresses: Unauthorized use of credential dumping tools
      evidence: Tool capability for memory dumping
---

The Microsoft Sysinternals Procdump utility is a legitimate administrative tool designed to capture process memory dumps, typically for troubleshooting application crashes. Because of its ability to read process memory, it is a highly attractive tool for malicious actors performing credential access. Adversaries frequently rename or use the official binary to target the Local Security Authority Subsystem Service (LSASS) process to extract cleartext passwords or NTLM hashes. While its usage is standard for system administrators and developers, the execution of this binary in an environment where it is not pre-approved or expected serves as a high-fidelity indicator of potential credential theft activity.

## Impact

Successful abuse of Procdump by an adversary can lead to the exfiltration of sensitive credentials from system memory. This facilitates lateral movement, privilege escalation, and persistent access within a compromised Windows environment.

## Recommendation

Deploy the provided Sigma rule to monitor for any execution of the Procdump utility. Establish an allowlist of authorized administrative or development workstations where Procdump is permitted, and alert on any instance where the tool is executed from unauthorized directories or by non-privileged accounts.
