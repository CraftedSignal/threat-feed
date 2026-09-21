---
title: Detection of Credential Dumping via LSASS Memory Access
slug: 2026-09-lsass-credential-dumping
description: This detection logic identifies credential dumping attempts by monitoring for unauthorized processes requesting PROCESS_VM_READ access to the lsass.exe process memory using Sysmon EventID 10.
date: "2026-09-21T19:09:54Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Microsoft
products:
  - Local Security Authority Subsystem Service (LSASS)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The following analytic detects attempts to read LSASS memory, indicative of credential dumping.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/
  - https://attack.mitre.org/techniques/T1003/001/
rules:
  - title: Detect Credential Dumping through LSASS access
    description: Detects unauthorized processes reading LSASS memory using Sysmon EventID 10 with PROCESS_VM_READ access.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sysmon EventID 10 monitoring for lsass.exe
      owner: Detection Engineering
      due: 48h
      evidence: Required log source for detecting credential dumping via LSASS.
  hunt_leads:
    - lead: Search for processes with PROCESS_VM_READ access to LSASS not signed by Microsoft.
      technique_id: T1003.001
      data_needed:
        - Sysmon EventID 10
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Standard behavior of credential dumping tools.
---

The Local Security Authority Subsystem Service (LSASS) is a core Windows process responsible for enforcing security policies and managing user credentials. Because it stores sensitive information in memory, including plaintext passwords and NTLM hashes, it is a primary target for attackers seeking to move laterally or elevate privileges within a compromised environment.

This threat brief outlines a detection strategy for identifying unauthorized attempts to access LSASS memory. Attackers utilize various techniques and tools - often associated with adversary playbooks like BlackSuit, Lokibot, or Scattered Lapsus$ - to perform memory dumping. By monitoring for specific process access masks via Sysmon, defenders can identify suspicious tools attempting to read the memory space of lsass.exe. This capability is critical for uncovering credential theft activities during the post-exploitation phase, providing visibility into internal reconnaissance and persistence mechanisms before attackers exfiltrate data or deploy ransomware.

## Impact

Successful dumping of LSASS memory allows adversaries to acquire domain credentials, leading to full network compromise, unauthorized access to sensitive systems, and potential data exfiltration or ransomware deployment. This technique is observed across a wide range of cyber-criminal and state-sponsored activity.

## Recommendation

* Deploy Sysmon and enable EventID 10 (ProcessAccess) specifically for monitoring the lsass.exe process.
* Implement the provided detection logic to flag processes requesting 'PROCESS_VM_READ' access to LSASS memory.
* Tune the detection by baseline auditing of legitimate administrative or security tools that perform expected operations on LSASS, creating an allowlist for known benign binary paths.
* Integrate detection alerts into a centralized SIEM to initiate an incident response process for suspected credential theft.
