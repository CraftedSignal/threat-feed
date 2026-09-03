---
title: Detection of Mimikatz Credential Dumping Tool Execution
slug: 2026-09-mimikatz-execution
description: Adversaries utilize the Mimikatz post-exploitation framework to dump credentials and perform authentication abuse by executing specific command-line modules in Windows environments.
date: "2026-09-03T12:39:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - post-exploitation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The rule identifies command-line patterns used for credential extraction via Mimikatz.
    confidence_band: high
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
  - https://tools.thehacker.recipes/mimikatz/modules
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml
rules:
  - title: HackTool - Mimikatz Execution
    description: Detects known Mimikatz command-line arguments indicating credential access attempts.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003.001
      - T1003.002
      - T1003.004
      - T1003.005
      - T1003.006
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to production SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides high-fidelity detection for known credential access tool
  hunt_leads:
    - lead: Search historic process creation logs for Mimikatz command-line patterns
      technique_id: T1003
      data_needed:
        - Process command line
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Tool execution is a high-signal indicator of compromise
---

Mimikatz is a widely utilized post-exploitation tool primarily designed for credential access within Windows environments. It enables attackers to extract plaintext passwords, hashes, Kerberos tickets, and other authentication material from the Local Security Authority Subsystem Service (LSASS) process. Attackers typically deploy Mimikatz after achieving initial access and gaining administrative privileges. The tool's modular architecture allows for various operations, including privilege escalation, token manipulation, and persistent credential harvesting. Defenders should monitor for specific command-line arguments and module invocations that identify Mimikatz usage, as these represent high-fidelity indicators of credential access attempts.

## Attack Chain

1. Attacker achieves initial execution on a target endpoint via phishing or exploit.
2. Attacker performs local privilege escalation to gain SYSTEM or Administrator rights.
3. Attacker drops or executes the Mimikatz binary or loads it into memory via reflective injection.
4. Attacker executes specific modules (e.g., sekurlsa::logonpasswords) to extract credentials from LSASS.
5. Attacker utilizes stolen credentials for lateral movement across the network.
6. Attacker exfiltrates collected authentication data to a command-and-control server.

## Impact

Successful execution of Mimikatz allows adversaries to capture sensitive credentials, leading to full network compromise, unauthorized access to internal resources, and potential data exfiltration. Impact is typically severe, requiring credential resets across the enterprise and forensic investigation of lateral movement.

## Recommendation

1. Deploy the provided Sigma rule to detect Mimikatz-specific command-line arguments in process creation logs.
2. Enable Sysmon Event ID 1 (Process Creation) to capture detailed CommandLine information across all workstations and servers.
3. Restrict administrative privileges to limit the feasibility of credential dumping attempts.
4. Implement memory protection solutions and harden LSASS to mitigate unauthorized access.
