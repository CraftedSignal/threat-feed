---
title: Detection of RDP Configuration Tampering via Reg.exe
slug: 2026-09-rdp-registry-tampering
description: Adversaries frequently target Windows Registry keys related to Terminal Services to enable remote access, bypass session restrictions, or weaken security layers during lateral movement and persistence.
date: "2026-09-03T12:41:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - lateral-movement
  - defense-impairment
  - windows
  - rdp
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Adversaries modify registry keys to enable RDP for persistence.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.001
    technique_name: Remote Desktop Protocol
    evidence: Attackers enable RDP to facilitate lateral movement.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_reg_rdp_keys_tamper.yml
  - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
  - https://www.trendmicro.com/en_us/research/25/i/unmasking-the-gentlemen-ransomware.html
rules:
  - title: Potential Tampering With RDP Related Registry Keys Via Reg.EXE
    description: Detects the execution of reg.exe for enabling or disabling the RDP service on the host by tampering with 'CurrentControlSet\Control\Terminal Server' registry values.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - lateral-movement
      - persistence
    techniques:
      - T1021.001
      - T1112
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
    - action: Deploy the provided Sigma rule for reg.exe activity.
      owner: Detection Engineering
      due: 48h
      evidence: SigmaHQ registry tampering detection logic.
  hunt_leads:
    - lead: Search for reg.exe activity modifying Terminal Server registry keys.
      technique_id: T1112
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known technique used by ransomware affiliates.
  mitigation_plan:
    - priority: medium_term
      action: Restrict registry edit permissions for non-administrative service accounts.
      owner: IT Operations
      addresses: T1112
      evidence: General security hardening practices.
---

Adversaries often use the built-in Windows utility 'reg.exe' to manipulate Remote Desktop Protocol (RDP) settings as part of post-exploitation activity. By modifying specific registry keys under 'HKLM\System\CurrentControlSet\Control\Terminal Server', threat actors can enable unauthorized remote access, disable security layers to lower defense barriers, or configure concurrent session settings to facilitate persistent remote presence. This technique has been observed across various ransomware and malware campaigns, including Qakbot, Phobos, and Gentlemen ransomware. Monitoring for these modifications is critical for detecting lateral movement and unauthorized persistence establishment within an enterprise environment.

## Attack Chain

1. Attacker gains initial access or escalation of privilege on a Windows endpoint.
2. Attacker identifies target RDP configuration parameters within the registry.
3. Attacker executes 'reg.exe' via command line or automated script.
4. Attacker uses 'reg.exe add' to modify specific values under 'CurrentControlSet\Control\Terminal Server'.
5. Attacker specifies '/f' to force the registry overwrite without manual confirmation.
6. Configuration changes take effect, enabling RDP or weakening authentication/encryption security layers.
7. Attacker utilizes the altered configuration to initiate a remote session or maintain persistent access.

## Impact

Successful tampering allows unauthorized remote access, bypasses intended security controls like Network Level Authentication (NLA) or TLS requirements, and assists in lateral movement. This can lead to total system compromise, exfiltration of sensitive data, and widespread ransomware deployment across the internal network.

## Recommendation

Prioritize the implementation of process-creation logging to identify suspicious use of the 'reg.exe' utility. 
- Deploy the provided Sigma rule to monitor for unauthorized modifications to Terminal Server registry keys.
- Establish an audit policy to alert on any modification of keys under 'HKLM\System\CurrentControlSet\Control\Terminal Server' by non-administrative service accounts or unauthorized processes.
- Review and baseline legitimate RDP configurations to differentiate between standard IT management tasks and malicious tampering attempts.
