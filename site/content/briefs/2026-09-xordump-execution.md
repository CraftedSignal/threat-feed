---
title: Detection of XORDump Credential Dumping Activity
slug: 2026-09-xordump-execution
description: XORDump is a utility used by attackers to dump process memory, specifically targeting lsass.exe to facilitate credential theft.
date: "2026-09-01T12:20:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - stealth
  - hacktool
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The rule detects the use of XORDump to dump lsass.exe memory.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Detection is tagged for T1036 as XORDump may be used to masquerade or manipulate system processes.
    confidence_band: med
references:
  - https://github.com/audibleblink/xordump
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_hktl_xordump.yml
rules:
  - title: Detect XORDump Process Execution
    description: Detects the execution of XORDump or usage of its specific command-line parameters for process memory dumping
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - stealth
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to SIEM
      owner: Detection Engineering
      due: 24h
      evidence: Required for detection of known credential dumping tool
  mitigation_plan:
    - priority: medium_term
      action: Restrict local administrative privileges and implement EDR blocking for known credential dumping utilities
      owner: IT Operations
      addresses: T1003.001
      evidence: Industry standard mitigation for credential dumping
---

XORDump is a specialized hacktool designed to extract process memory contents, primarily utilized by adversaries during the credential access phase of an intrusion. The tool leverages specific modules and techniques to interact with sensitive system processes, most notably the Local Security Authority Subsystem Service (lsass.exe). By invoking specific command-line switches and utilizing Windows API-related modules like comsvcs, dbghelp, or dbgcore, XORDump enables attackers to bypass standard memory protection mechanisms to harvest credentials. This activity is a high-signal indicator of post-exploitation behavior, specifically targeting memory-resident secrets to enable lateral movement or privilege escalation within a compromised Windows environment. Defensive teams should monitor process creation events for any invocation of xordump.exe or the use of its distinctive command-line parameters.

## Attack Chain

1. Attacker gains initial access to the target host via phishing or exploit.
2. Attacker performs local enumeration to identify high-privilege processes.
3. Attacker drops the XORDump binary onto the target system file system.
4. Attacker executes xordump.exe with arguments pointing to lsass.exe for memory extraction.
5. XORDump loads system modules like comsvcs.dll to facilitate the dump process.
6. The dumped memory containing hashed or plaintext credentials is written to a local file.
7. Attacker exfiltrates the dumped memory file or parses it locally to extract credentials.

## Impact

Successful execution of XORDump allows attackers to obtain sensitive credentials from memory. This impact often results in account compromise, unauthorized lateral movement across the network, and potential full domain dominance if privileged service accounts or domain administrator credentials are harvested.

## Recommendation

- Deploy the provided Sigma rule to detect the execution of XORDump or the use of its specific command-line arguments.
- Enable Sysmon process creation logging (Event ID 1) to capture Commandline and Image path telemetry.
- Investigate any process creating memory dumps of lsass.exe, as this behavior is rarely associated with legitimate administrative tasks.
