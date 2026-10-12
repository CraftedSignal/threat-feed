---
title: Suspicious Rundll32 Execution with StartW Parameters
slug: 2026-10-suspicious-rundll32-startw
description: Detection of rundll32.exe executing with 'Start' or 'StartW' function parameters, a common technique used by Cobalt Strike payloads to achieve arbitrary code execution and persistence.
date: "2026-10-12T17:59:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cobalt-strike
  - defense-evasion
  - execution
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The following analytic identifies the execution of rundll32.exe with the DLL function names Start and StartW, commonly associated with Cobalt Strike payloads.
    confidence_band: high
rules:
  - title: Detect Suspicious Rundll32 StartW Parameters
    description: Detects the execution of rundll32.exe with the DLL function names Start or StartW, commonly used by Cobalt Strike payloads.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.011
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
    - action: Deploy Sigma rule to SIEM/EDR.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides analytic logic for rundll32 StartW detection.
  hunt_leads:
    - lead: Search for historical rundll32 command lines matching Start/StartW.
      technique_id: T1218.011
      data_needed:
        - Endpoint process command-line logs.
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source indicates this is a high-confidence TTP for Cobalt Strike.
---

This threat brief focuses on the suspicious use of the Windows binary 'rundll32.exe' to execute specific exported functions named 'Start' or 'StartW'. This activity is a well-documented indicator of Cobalt Strike beacon activity and other malicious payloads. By leveraging the 'rundll32.exe' utility, attackers can side-load malicious DLLs, bypassing basic security controls to run arbitrary code. This technique is frequently utilized during the later stages of an intrusion to establish persistence, elevate privileges, or perform lateral movement. Security operations teams should monitor process command-line arguments across the environment to identify instances of 'rundll32.exe' being invoked with these specific function names, as they are rarely used by legitimate system processes.

## Attack Chain

1. Attacker delivers a malicious DLL to a victim's host via phishing or post-compromise lateral movement.
2. Attacker writes the malicious DLL to a staging directory (e.g., C:\ProgramData\ or user-writable temporary folders).
3. Attacker uses 'rundll32.exe' to load the malicious DLL and execute a specific exported function.
4. 'rundll32.exe' is executed with the command line argument "rundll32.exe &lt;path_to_malicious_dll>,Start" or "StartW".
5. The OS loader maps the malicious DLL into the 'rundll32.exe' process memory space.
6. The exported 'Start' or 'StartW' function is invoked, triggering the embedded shellcode or payload.
7. The payload establishes a C2 connection or performs further malicious actions (e.g., credential theft, persistence).

## Impact

Successful exploitation of this technique allows an attacker to execute arbitrary code with the permissions of the host process. This facilitates full system compromise, including privilege escalation, data exfiltration, and the deployment of additional malicious tools such as ransomware, as evidenced by its association with Cobalt Strike, Trickbot, and various ransomware families.

## Recommendation

1. Deploy the provided Sigma rule to your EDR or SIEM to flag 'rundll32.exe' command lines containing 'Start' or 'StartW'.
2. Enable Sysmon Event ID 1 (Process Creation) or Windows Security Event ID 4688 with command-line auditing enabled to ensure full visibility into process execution.
3. Investigate process-parent relationships; legitimate 'rundll32.exe' execution rarely originates from unusual user-writable directories or shell-spawned processes.
4. Use the provided drilldown searches in Splunk to identify related risk events and lateral movement indicators associated with the host.
