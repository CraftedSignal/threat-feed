---
title: Credential Access via WerFault LSASS Memory Dumping
slug: 2026-09-werfault-lsass-access
description: Adversaries leverage the WerFault.exe process to facilitate unauthorized access to LSASS memory, enabling the extraction of credentials from protected system processes.
date: "2026-09-24T13:13:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - process-injection
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects process LSASS memory dump using Mimikatz, NanoDump, Invoke-Mimikatz, Procdump or Taskmgr based on the CallTrace pointing to ntdll.dll, dbghelp.dll or dbgcore.dll
    confidence_band: high
rules:
  - title: Detect Credential Dumping Attempt Via WerFault
    description: Detects process LSASS memory dump attempt where WerFault.exe requests high-level access to lsass.exe
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_access
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the WerFault LSASS access Sigma rule
      owner: Detection Engineering
      due: 48h
      evidence: SigmaHQ research indicates this is a common TTP for credential dumping
  hunt_leads:
    - lead: Search for historical Event ID 10 events involving WerFault and LSASS
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 10 logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known technique for bypassing standard process monitoring
---

Security research and telemetry analysis indicate that adversaries are abusing the Windows Error Reporting process (WerFault.exe) to facilitate credential dumping attacks. By masquerading as or invoking legitimate error reporting workflows, attackers gain high-privilege access to the Local Security Authority Subsystem Service (LSASS) process. This technique allows for the creation of memory dumps that contain sensitive authentication material, such as NTLM hashes or plaintext credentials. Tools such as Mimikatz, NanoDump, and various PowerShell-based execution frameworks have been observed utilizing this path to bypass common monitoring. Defenders should focus on process access requests originating from WerFault.exe that target lsass.exe with full access rights.

## Attack Chain

1. Attacker establishes initial access on the endpoint using a high-privilege or system-level account.
2. Attacker prepares a memory dumping utility (e.g., NanoDump or Invoke-Mimikatz).
3. Attacker triggers a memory dump operation directed at the lsass.exe process.
4. Attacker forces WerFault.exe to initialize or interact with the target process to mask the dumping activity.
5. The dumping tool leverages Windows APIs (e.g., dbghelp.dll or dbgcore.dll) to read LSASS memory.
6. The memory dump file is generated and stored locally in a temporary directory.
7. Attacker retrieves the memory dump file via C2 channels for offline credential extraction.

## Impact

Successful exploitation results in the compromise of domain or local credentials stored in LSASS. This allows attackers to escalate privileges within the environment, move laterally, and maintain long-term persistence through credential re-use.

## Recommendation

Deploy detection rules to monitor process access events between WerFault.exe and lsass.exe. Focus on granted access masks that indicate full control (0x1FFFFF).

- Enable Sysmon or Windows Event Log (Event ID 10) to monitor process access requests.
- Implement the provided Sigma rule in the SIEM to flag suspicious process access behavior.
- Investigate any instances where WerFault.exe initiates a high-access handle to LSASS, as this is rarely necessary for legitimate error reporting.
