---
title: BITS Job Notify Command Persistence
slug: 2024-01-bits-persistence
description: Adversaries can abuse the Background Intelligent Transfer Service (BITS) SetNotifyCmdLine method to execute arbitrary commands for persistence by configuring a BITS job to execute a program after a transfer completes or enters a specific state.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - bits
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1197
    technique_name: BITS Jobs
references:
  - https://pentestlab.blog/2019/10/30/persistence-bits-jobs/
  - https://docs.microsoft.com/en-us/windows/win32/api/bits1_5/nf-bits1_5-ibackgroundcopyjob2-setnotifycmdline
  - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-setnotifycmdline
  - https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-2
rules:
  - title: Suspicious Process Created by BITS Service
    description: Detects suspicious processes spawned by svchost.exe with BITS arguments, excluding known legitimate executables.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1197
    data_sources:
      - process_creation
      - windows
  - title: BITSAdmin SetNotifyCmdLine Usage
    description: Detects the use of bitsadmin to set a notification command line, potentially for malicious persistence.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1197
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Background Intelligent Transfer Service (BITS) is a Windows service used for asynchronous, prioritized, and throttled file transfers. Attackers can abuse BITS to achieve persistence by using the `SetNotifyCmdLine` method to execute a program after a job completes or enters a specified state. This involves creating a BITS job and configuring a notification command line that runs when the job finishes transferring data or reaches a specific state. This technique allows adversaries to execute arbitrary commands or payloads, maintaining persistence on the compromised system. The targeted systems are Windows-based, and the impact can range from malware execution to establishing a persistent backdoor.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means (e.g., phishing, exploiting a vulnerability).
2. The attacker creates a new BITS job using the `bitsadmin` command-line tool or the BITS COM API.
3. The attacker configures the BITS job to transfer a small, benign file (e.g., a text file from a web server) to trigger the job completion event.
4. The attacker uses the `SetNotifyCmdLine` method (via `bitsadmin` or the COM API) to specify a malicious command or executable to run upon job completion or a state change. For example, `bitsadmin /SetNotifyCmdLine <job_id> cmd.exe /c powershell.exe -exec bypass -f C:\temp\evil.ps1`.
5. The attacker starts the BITS job, initiating the file transfer.
6. Once the file transfer completes, the BITS service executes the configured malicious command via `svchost.exe`.
7. The malicious command executes a PowerShell script or other payload, achieving persistence or other malicious objectives.
8. The attacker maintains persistent access to the system, even after reboots or user logoffs, as the BITS job remains configured to execute the malicious command.

## Impact

Successful exploitation allows attackers to establish persistence on the compromised Windows system. This can lead to a variety of malicious activities, including unauthorized access to sensitive data, deployment of ransomware, or use of the system as part of a botnet. The impact can vary depending on the payload executed by the BITS job. While the number of victims is not specified, this technique can affect any Windows system where the attacker has sufficient privileges to create and configure BITS jobs.

## Recommendation

*   Monitor process creation events for processes spawned by `svchost.exe` with arguments containing "BITS" and a command-line indicative of malicious activity. Deploy the Sigma rule "Persistence via BITS Job Notify Cmdline" and tune exclusions for legitimate software.
*   Inspect the command line arguments of processes spawned by `svchost.exe` for unusual commands, scripts, or payloads that might indicate malicious use of BITS, as outlined in the investigation guide.
*   Regularly review and audit existing BITS jobs on systems to identify and remove any unauthorized or suspicious jobs.
*   Implement endpoint protection policies to prevent unauthorized use of BITS for persistence, ensuring that only trusted applications can create or modify BITS jobs.
*   Enable Sysmon process creation logging to capture detailed information about process execution, including parent-child relationships and command-line arguments, enabling the detection of malicious BITS activity.
