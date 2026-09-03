---
title: Suspicious PowerShell Get-Process LSASS Execution
slug: 2026-09-powershell-lsass-getprocess
description: Detection of suspicious PowerShell activity involving Get-Process calls targeting the Local Security Authority Subsystem Service (LSASS) process, a common precursor to credential dumping.
date: "2026-09-03T12:36:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - powershell
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_getprocess_lsass.yml
  - https://web.archive.org/web/20220205033028/https://twitter.com/PythonResponder/status/1385064506049630211
rules:
  - title: Detect Suspicious Get-Process LSASS Call
    description: Detects the use of Get-Process targeting the LSASS process within PowerShell Script Blocks, often indicative of credential access reconnaissance.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging across domain-joined Windows endpoints
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into PowerShell script execution
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Detects reconnaissance of LSASS process
  hunt_leads:
    - lead: Search for instances of Get-Process targeting LSASS in historical logs
      technique_id: T1003.001
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Attacker reconnaissance pattern
  mitigation_plan:
    - priority: medium_term
      action: Restrict access to LSASS process memory via Attack Surface Reduction (ASR) rules
      owner: Endpoint Security
      addresses: T1003.001
      evidence: Reduces impact of credential dumping
---

This brief addresses a common technique used by threat actors to identify or interact with the Local Security Authority Subsystem Service (LSASS) using PowerShell. By executing 'Get-Process lsass' within a script block, attackers can verify the running status and PID of the LSASS process as a precursor to credential access attempts, such as memory dumping or injection. Monitoring for this specific pattern is critical for identifying early-stage reconnaissance activities within a Windows environment. Because legitimate administrative or certificate-related tasks may occasionally interact with process information, detection tuning is required to account for known benign internal tooling.

## Attack Chain

1. Initial access is established on a Windows endpoint via phishing, exploit, or other means.
2. Attacker initiates PowerShell process (powershell.exe or pwsh.exe).
3. Attacker executes reconnaissance scripts to identify security-sensitive processes.
4. Attacker runs 'Get-Process lsass' to confirm target process availability and PID.
5. Attacker attempts to elevate privileges to gain necessary access rights for process memory interaction.
6. Attacker leverages tools like Mimikatz or procdump to dump LSASS process memory.
7. Attacker exfiltrates memory dump for offline credential extraction.

## Impact

Successful interaction with the LSASS process often leads to credential theft, including plaintext passwords, NTLM hashes, and Kerberos tickets. This allows adversaries to escalate privileges, move laterally through the network, and maintain persistence. In high-value environments, this may lead to full domain compromise and significant data exfiltration.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) to capture the executed script content.
- Deploy the provided Sigma rule to detect 'Get-Process lsass' activity within script block logs.
- Tune the detection logic by comparing it against known administrative certificate management scripts or legacy monitoring tools in your environment.
- Investigate any hits returned by the detection, focusing on the parent process and user context.
