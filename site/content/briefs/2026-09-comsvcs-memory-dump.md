---
title: Credential Access via Process Memory Dumping using comsvcs.dll
slug: 2026-09-comsvcs-memory-dump
description: Adversaries utilize the legitimate Windows component comsvcs.dll via rundll32.exe to perform unauthorized process memory dumps, typically targeting the LSASS process to extract credentials.
date: "2026-09-03T12:44:01Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The technique is a common method for dumping LSASS memory to extract credentials.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Leveraging rundll32.exe allows execution of arbitrary DLL exports under a legitimate process.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml
  - https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
rules:
  - title: Detect Suspicious Process Memory Dump via Comsvcs.DLL
    description: Detects the use of rundll32.exe to invoke comsvcs.dll for process memory dumping, often used for credential harvesting
    platform: sigma
    severity: high
    tactics:
      - credential-access
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
    - action: Deploy the provided Sigma rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Detection logic provided in the brief.
  hunt_leads:
    - lead: Search historical logs for rundll32.exe command lines containing 'comsvcs' and 'full'.
      technique_id: T1003.001
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This command line pattern is a direct indicator of the memory dump technique.
---

Adversaries frequently abuse the native Windows library 'comsvcs.dll' to dump the memory of sensitive processes, most notably 'lsass.exe'. By leveraging the 'MiniDumpW' function exported by this library via 'rundll32.exe', attackers can bypass traditional file-based detection mechanisms. This technique is well-documented in offensive security research and is commonly integrated into post-exploitation frameworks like 'lsassy'. The attack typically involves invoking rundll32 with specific ordinals (such as 24) or function names, allowing the attacker to write the contents of a target process's memory to a file on disk. This activity is a hallmark of credential harvesting, as the resulting dump file can be analyzed offline using tools like Mimikatz or Pypykatz to recover cleartext credentials, NTLM hashes, or Kerberos tickets. Detecting this requires monitoring command-line arguments for specific function calls and library references associated with memory dumping.

## Attack Chain

1. Attacker gains initial access or code execution on the target Windows system.
2. Attacker identifies the target process (e.g., 'lsass.exe') and its PID.
3. Attacker elevates privileges to 'SeDebugPrivilege' to permit memory access.
4. Attacker invokes 'rundll32.exe' to load 'comsvcs.dll'.
5. Attacker calls the 'MiniDumpW' export or relevant ordinal (e.g., 24) with arguments to create a dump file.
6. The memory dump is written to a user-specified path (e.g., 'C:\\Windows\\Temp\\dump.bin').
7. Attacker exfiltrates the dump file for offline credential extraction.

## Impact

The primary impact of this technique is the compromise of sensitive credentials stored within process memory. Successful exploitation frequently leads to privilege escalation and lateral movement across the internal network, as obtained credentials are often used to access other systems or domain controllers.

## Recommendation

1. Deploy the provided Sigma rule to monitor 'process_creation' events for suspicious 'rundll32.exe' command-line patterns.
2. Baseline the legitimate use of 'comsvcs.dll' in your environment; while rare, system-level tasks should be evaluated to reduce false positives.
3. Implement strict monitoring for access to 'lsass.exe' process memory, focusing on privileged calls.
4. Ensure 'SeDebugPrivilege' assignment is audited and restricted to authorized administrative users only.
