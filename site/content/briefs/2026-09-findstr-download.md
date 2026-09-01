---
title: Remote File Download Using Findstr.exe
slug: 2026-09-findstr-download
description: Attackers can leverage the findstr.exe utility to download or read content from remote SMB shares using specific command-line arguments, potentially facilitating file exfiltration or second-stage payload delivery.
date: "2026-09-01T12:19:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - file-transfer
  - stealth
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This specific set of CLI flags would allow findstr to download the content of the file located on the remote share.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Findstr/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_findstr_download.yml
rules:
  - title: Detect Remote File Download Via Findstr.exe
    description: Detects the use of findstr.exe with flags -v and -l in conjunction with a remote UNC path, a technique used to read or download content from remote shares.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
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
    - action: Deploy the Sigma rule to the SIEM to alert on suspicious findstr command-line patterns.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for historical process creation events involving findstr.exe with UNC paths.
      technique_id: T1105
      data_needed:
        - Process command line
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation identifies this as an active abuse vector.
---

The Windows native binary 'findstr.exe' is intended for searching strings within files. However, security researchers have identified that the tool can be abused to read the content of files located on remote network shares. By combining the '-v' (print only lines that do not contain a match) and '-l' (use search strings literally) flags with a UNC path to a remote share, an attacker can force the utility to access and display the contents of a target file. This technique allows for the exfiltration of sensitive data or the staging of malicious scripts from remote infrastructure. Defenders should monitor for unexpected invocations of 'findstr.exe' that reference UNC paths and include these specific flags, as this behavior is highly atypical for standard administrative or operational tasks.

## Attack Chain

1. Attacker establishes an external SMB share or compromises a reachable internal file share.
2. Attacker prepares a malicious payload or sensitive document on the reachable share.
3. Attacker gains initial access to the target Windows endpoint.
4. Attacker identifies the target file on the remote share via UNC path (e.g., \\\\10.0.0.5\\share\\file.txt).
5. Attacker executes 'findstr.exe' with the '-v', '-l', and a placeholder pattern to force a read of the remote file.
6. The system process initiates an SMB connection to the attacker-controlled share.
7. 'findstr.exe' reads the remote file content and prints it to the command-line output.
8. Attacker captures the output or redirects it to a local file for further use.

## Impact

This technique can lead to the unauthorized disclosure of sensitive files stored on network shares or the retrieval of secondary stage malicious tools. It serves as a stealthy method to bypass standard file transfer utilities that might be blocked or more closely monitored by security software.

## Recommendation

* Deploy the included Sigma rule to monitor for suspicious 'findstr.exe' executions.
* Establish baseline monitoring for 'findstr.exe' usage; investigate any instances involving UNC paths (starting with '\\\\') as these are anomalous in most enterprise environments.
* Ensure Sysmon or equivalent process-creation logging (Event ID 1) is enabled to capture command-line arguments.
