---
title: NetSupport Manager Execution from Unusual Path
slug: 2024-01-netsupport-unusual-path
description: This rule detects the execution of NetSupport remote access software from non-default paths, potentially indicating an adversary abusing NetSupport Manager for malicious remote control.
date: "2024-01-03T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command_and_control
  - remote_access_tool
  - netsupport
vendors:
  - NetSupport
products:
  - NetSupport Manager
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://www.netsupportsoftware.com/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_rmm_netsupport_susp_path.toml
rules:
  - title: Detect NetSupport Client32 Execution from Unusual Path
    description: Detects execution of NetSupport client32.exe from unusual paths, indicating potential abuse for remote access.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect NetSupport Client32 Parent Process from Unusual Path
    description: Detects execution of NetSupport client32.exe as a parent from unusual paths, indicating potential abuse for remote access.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies the execution of NetSupport Manager, a remote access tool, from non-standard installation paths on Windows systems. Adversaries may abuse legitimate remote access software like NetSupport to gain unauthorized control over victim machines, bypassing traditional security controls. The rule focuses on detecting instances of `client32.exe` (or its parent process) running from locations such as user profiles or the ProgramData directory, which deviates from typical installations. This activity is flagged as suspicious because legitimate software is usually installed in dedicated directories under Program Files or Program Files (x86). The detection logic is designed to be broad, catching renamed or moved copies of the legitimate binary used for malicious purposes. This activity was observed beginning 2025/08/20 and updated 2026/04/07.

## Attack Chain

1. An adversary gains initial access to the system through a separate vector (e.g., phishing, exploitation).
2. The adversary copies or moves the `client32.exe` binary to a non-standard location, such as `C:\Users\<username>\` or `C:\ProgramData\`.
3. The adversary executes `client32.exe` from the unusual path.
4. NetSupport Manager establishes a remote connection to a command and control server.
5. The adversary uses NetSupport Manager to perform reconnaissance activities on the compromised host.
6. The adversary leverages NetSupport Manager to execute malicious commands.
7. The adversary uses the established connection to move laterally to other systems within the network.
8. The adversary achieves their objective, such as data exfiltration or ransomware deployment.

## Impact

Successful exploitation can lead to complete remote control of the compromised system. This could result in data theft, malware installation, lateral movement within the network, and disruption of services. The impact is significant as NetSupport Manager provides extensive remote administration capabilities to the attacker. Without proper mitigation, attackers can gain complete control over the affected machines, leading to significant damage.

## Recommendation

*   Enable Sysmon process-creation logging to activate the rule `NetSupport Manager Execution from an Unusual Path` and ensure proper logging from the endpoint.
*   Inspect process ancestry of detected `client32.exe` instances for suspicious parent processes (e.g., script interpreters or archive utilities) as suggested in the rule's note section.
*   Deploy the Sigma rule `Detect NetSupport Client32 Execution from Unusual Path` to your SIEM and tune for your environment.
*   Monitor network connections originating from `client32.exe` for unusual destination IPs and ports, as described in the rule's triage and analysis.
