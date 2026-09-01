---
title: Suspicious Usage of Unblock-File PowerShell Cmdlet
slug: 2026-09-suspicious-unblock-file
description: The abuse of the Unblock-File cmdlet is used by attackers to bypass Mark-of-the-Web (MotW) protections on downloaded files, facilitating the execution of malicious payloads.
date: "2026-09-01T11:06:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - powershell
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    evidence: Remove the Zone.Identifier alternate data stream which identifies the file as downloaded from the internet.
    confidence_band: high
rules:
  - title: Detect Suspicious Unblock-File Usage
    description: Detects the use of the Unblock-File cmdlet to remove the Zone.Identifier alternate data stream from files.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1553.005
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) on all workstations.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into Unblock-File cmdlet execution.
  hunt_leads:
    - lead: Search for instances of Unblock-File in historic Script Block logs.
      technique_id: T1553.005
      data_needed:
        - ScriptBlockText from Event ID 4104
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Abuse of this cmdlet is a common defense evasion technique.
---

The Unblock-File PowerShell cmdlet is a legitimate administrative tool used to remove the Zone.Identifier alternate data stream (ADS) from files downloaded from the internet. When a file is downloaded on Windows, the operating system attaches this stream to flag the file as potentially untrusted, which subsequently triggers security prompts or blocks execution of macros and scripts. Attackers frequently abuse this cmdlet to programmatically remove these protections from malicious payloads, such as droppers or scripts, to ensure they execute without user intervention or security warnings. Defenders should monitor for the use of this command in scripts, as its execution on non-standard files or in suspicious contexts is a common indicator of defense evasion.

## Attack Chain

1. Attacker delivers a malicious payload (e.g., LNK file or script) to the target host via phishing or web drive-by.
2. The file is saved to the disk and receives a 'Zone.Identifier' alternate data stream identifying it as untrusted.
3. The attacker executes a secondary script or payload wrapper on the host.
4. The script identifies the downloaded file path.
5. The attacker invokes the Unblock-File cmdlet targeting the malicious file.
6. The PowerShell engine removes the Zone.Identifier ADS from the file system.
7. The operating system no longer treats the file as originating from the internet.
8. The attacker executes the now-trusted payload to achieve persistent access or secondary stage download.

## Impact

Successful abuse of this cmdlet allows attackers to bypass Windows security features designed to prevent the execution of untrusted code. This leads to the silent execution of malware, increased probability of successful macro-based attacks, and the evasion of host-based security warnings, potentially resulting in full system compromise.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture full command execution strings.
2. Deploy the provided Sigma rule to detect the execution of Unblock-File.
3. Baseline the usage of Unblock-File in your environment to identify legitimate automated deployment scripts and suppress them in the detection logic.
4. Implement strict AppLocker or Windows Defender Application Control (WDAC) policies to restrict the execution of scripts that have been unblocked in unauthorized locations.
