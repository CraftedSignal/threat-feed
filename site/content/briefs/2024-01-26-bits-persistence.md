---
title: Persistence via BITS Job Notify Cmdline
slug: 2024-01-26-bits-persistence
description: Adversaries can achieve persistence by abusing the Background Intelligent Transfer Service (BITS) SetNotifyCmdLine method to execute a program after a job finishes, leading to arbitrary code execution and system compromise.
date: "2024-01-26T10:00:00Z"
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
  - Elastic
products:
  - Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
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
  - title: Detect Suspicious BITS Job Creation
    description: Detects the creation of BITS jobs with suspicious command lines, indicative of potential persistence attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1197
    data_sources:
      - process_creation
      - windows
  - title: BITS Job Notify Cmdline Execution
    description: Detects processes launched via BITS SetNotifyCmdline.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1197
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Background Intelligent Transfer Service (BITS) is a Windows service used for asynchronous, prioritized, and throttled file transfers. Attackers can abuse BITS to establish persistence by using the `SetNotifyCmdLine` method to execute a program after a BITS job completes or enters a specific state. This technique allows adversaries to run arbitrary code with elevated privileges, bypassing traditional security measures. The detection rule identifies suspicious processes initiated by BITS, excluding known legitimate executables like `WerFaultSecure.exe`, `WerFault.exe`, `wermgr.exe`, and `directxdatabaseupdater.exe`. This behavior can be employed to maintain access to a compromised system, even after a reboot or user logout. Defenders need to monitor BITS activity for unusual command-line executions to detect and prevent potential persistence attempts.

## Attack Chain

1. An attacker gains initial access to a system through other means (e.g., phishing, exploitation of a vulnerability).
2. The attacker uses the BITSAdmin tool or PowerShell cmdlets to create a new BITS job.
3. The attacker configures the BITS job to download a malicious payload or execute a malicious script.
4. The attacker utilizes the `SetNotifyCmdLine` method to set a command that will be executed upon job completion or a specified state change.
5. The BITS service executes the specified command, which can be a script interpreter (e.g., `powershell.exe`, `cmd.exe`) or a malicious executable.
6. The malicious command downloads or executes further payloads, establishing persistence on the system.
7. The attacker maintains persistent access, allowing them to execute commands, steal data, or perform other malicious activities.

## Impact

Successful exploitation allows attackers to maintain persistent access to compromised systems. This can lead to data theft, further malware deployment, or complete system compromise. The BITS service runs with elevated privileges, so any command executed via `SetNotifyCmdLine` will also run with those privileges. This persistence mechanism is difficult to detect because BITS is a legitimate Windows service, and its activity can be easily masked as normal system operations.

## Recommendation

*   Monitor process creation events for processes spawned by `svchost.exe` with arguments containing "BITS" but not in the exclusion list (WerFaultSecure.exe, WerFault.exe, wermgr.exe, directxdatabaseupdater.exe) using the "Persistence via BITS Job Notify Cmdline" rule.
*   Implement the Sigma rule "Detect Suspicious BITS Job Creation" to identify unusual BITS job creation activities.
*   Review BITS job configurations on systems to identify and remove any unauthorized or suspicious jobs.
*   Enable Sysmon process creation logging to capture detailed information about process execution, including parent-child relationships and command-line arguments.
