---
title: MSIExec Spawning Discovery Commands
slug: 2024-01-msiexec-discovery
description: Detection of msiexec.exe spawning discovery commands indicating potential reconnaissance activity by attackers for system information gathering and lateral movement.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - msiexec
  - discovery
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md
rules:
  - title: MSIExec Spawning Discovery Commands
    description: Detects MSIExec spawning discovery commands.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: MSIExec Spawning Discovery Tools via PowerShell
    description: Detects MSIExec using PowerShell to execute discovery tools.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying suspicious behavior where `msiexec.exe`, a legitimate Windows utility for installing, uninstalling, and configuring software, is used to spawn multiple discovery commands. This activity is often associated with attackers attempting to gather system information, enumerate the network, and identify potential targets for lateral movement. The technique is typically observed post-compromise, after initial access has been achieved through other means. This behavior matters to defenders as it is a key indicator of malicious activity and potential privilege escalation or data exfiltration attempts. The detection leverages Endpoint Detection and Response (EDR) data, specifically process creation events, to identify instances where `msiexec.exe` is the parent process of common discovery tools.

## Attack Chain

1. An attacker gains initial access to the system through a vulnerability, phishing, or other means.
2. The attacker leverages `msiexec.exe` to execute discovery commands.
3. `msiexec.exe` spawns processes such as `ipconfig.exe`, `net.exe`, `systeminfo.exe`, or `wmic.exe` to gather network configuration, user information, and system details.
4. The attacker uses commands within `cmd.exe` or `powershell.exe` to execute the discovery commands. For example, `cmd.exe /c ipconfig /all` or `powershell.exe Get-NetIPConfiguration`.
5. The attacker filters the output of these commands to identify valuable information such as domain names, user accounts, and system architecture.
6. The attacker uses the gathered information to identify potential targets for lateral movement and privilege escalation.
7. The attacker attempts to move laterally to other systems using stolen credentials or exploits.

## Impact

Successful exploitation of this technique can lead to a comprehensive understanding of the compromised environment. Attackers can leverage gathered information to escalate privileges, move laterally to other systems, and ultimately exfiltrate sensitive data or deploy ransomware. The impact could range from a single compromised workstation to a complete network breach, depending on the scope of the attacker's activity.

## Recommendation

*   Enable process monitoring and command-line logging on all endpoints to capture the necessary data for detection.
*   Deploy the Sigma rule `MSIExec Spawning Discovery Commands` to your SIEM and tune it to your environment.
*   Investigate any instances of `msiexec.exe` spawning multiple discovery commands, as this behavior is unusual in normal system operations.
*   Implement least privilege principles to limit the impact of compromised accounts and prevent lateral movement.
