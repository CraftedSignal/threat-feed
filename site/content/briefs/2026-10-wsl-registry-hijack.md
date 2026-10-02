---
title: Potential Hijacking of Windows Subsystem for Linux via Registry Modification
slug: 2026-10-wsl-registry-hijack
description: Adversaries can gain persistence and perform proxy execution by modifying the WSL InstallLocation registry key to redirect binary execution to malicious payloads.
date: "2026-10-02T10:12:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - registry
  - wsl
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Attackers can modify this registry key to redirect the execution flow of legitimate WSL processes.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Attackers can modify this registry key to redirect the execution flow of legitimate WSL processes (wsl.exe or bash.exe) to a malicious payload, acting as a proxy execution and defense evasion technique.
    confidence_band: high
rules:
  - title: Detect Potential WSL InstallLocation Registry Key Modification
    description: Detects modifications to the Windows Subsystem for Linux (WSL) InstallLocation registry key, which can be used for proxy execution or persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM and monitor for hits on WSL registry keys.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides technical logic for registry key modification.
  hunt_leads:
    - lead: Search historical registry modification logs for changes to the Lxss\MSI path.
      technique_id: T1112
      data_needed:
        - Registry Set (Event ID 13)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Registry keys are persistent and can be searched retrospectively.
---

Research indicates that the Windows Subsystem for Linux (WSL) configuration can be abused by attackers to achieve stealthy execution and persistence. By modifying the 'InstallLocation' registry key associated with WSL, an actor can point the system to a custom or malicious directory. When a user subsequently invokes 'wsl.exe' or 'bash.exe', the system executes the payload located at the path defined in the hijacked registry key instead of the legitimate WSL environment. This technique provides a mechanism for defense evasion by leveraging trusted system binaries to execute malicious code, potentially bypassing security controls that rely on process allowlisting or signature-based detection. This method has been documented in various security research reports as a vector for stealthy operations and long-term system persistence on Windows endpoints.

## Attack Chain

1. Attacker gains initial access or code execution on the target Windows system.
2. Attacker identifies the WSL 'InstallLocation' registry key path under 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss'.
3. Attacker drops a malicious binary or script designed to masquerade as the legitimate WSL environment.
4. Attacker modifies the 'InstallLocation' registry value to point to the directory containing the malicious payload.
5. The next time the user or an automated task executes 'wsl.exe' or 'bash.exe', the system loads the malicious files instead of the legitimate WSL components.
6. The malicious payload executes within the context of the WSL process, achieving the attacker's objective (persistence, exfiltration, or further command execution).

## Impact

Successful exploitation allows attackers to maintain stealthy persistence and execute malicious code under the guise of legitimate system processes. This can lead to unauthorized access to sensitive data, internal network reconnaissance, and the deployment of additional malware, impacting the integrity and confidentiality of the host system.

## Recommendation

- Deploy the provided Sigma rule to monitor for unauthorized modifications to the WSL 'InstallLocation' registry key.
- Establish a baseline of expected 'InstallLocation' paths within the environment to facilitate more precise alerting.
- Review registry monitoring logs (Event ID 13) for unexpected processes modifying keys under 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss'.
- Restrict administrative privileges on endpoints to prevent unauthorized registry modifications.
