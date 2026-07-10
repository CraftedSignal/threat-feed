---
title: Suspicious Shell Execution via Velociraptor
slug: 2024-01-velociraptor-shell-execution
description: Attackers are abusing the Velociraptor endpoint visibility and response tool to execute shell commands (cmd, PowerShell, rundll32) on compromised Windows systems, blending in with legitimate system processes.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - velociraptor
  - command-and-control
  - windows
vendors:
  - SolarWinds
products:
  - SolarWinds Web Help Desk
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.huntress.com/blog/active-exploitation-solarwinds-web-help-desk-cve-2025-26399
  - https://attack.mitre.org/techniques/T1219/
rules:
  - title: Suspicious Shell Execution via Velociraptor
    description: Detects shell executions (cmd, PowerShell, rundll32) spawned by Velociraptor.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Velociraptor Executing Cmd with Suspicious Arguments
    description: Detects Velociraptor spawning cmd.exe with command line arguments indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.003
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Velociraptor is a legitimate open-source endpoint visibility and response tool. Threat actors are abusing Velociraptor by installing it on compromised Windows systems and using it to execute shell commands (cmd, PowerShell, rundll32), effectively hiding their malicious activity within normal system processes. This allows attackers to perform various actions on the compromised host, such as data exfiltration, lateral movement, and credential access, while evading traditional detection methods. The activity was observed in relation to exploitation of CVE-2025-26399, a vulnerability in SolarWinds Web Help Desk. Defenders need to differentiate between legitimate and malicious use of Velociraptor to prevent further compromise.

## Attack Chain

1. Initial access is gained through exploitation of a vulnerability (e.g., CVE-2025-26399 in SolarWinds Web Help Desk).
2. Velociraptor is installed on the compromised Windows host, potentially using a script or other automated method.
3. The attacker configures Velociraptor with malicious artifacts or uses it to execute arbitrary commands.
4. Velociraptor spawns a shell process (cmd.exe, powershell.exe, or rundll32.exe) to execute the attacker's commands.
5. The shell process executes malicious commands, such as downloading additional tools, performing reconnaissance, or exfiltrating data.
6. The attacker uses the shell to perform lateral movement to other systems within the network.
7. The attacker escalates privileges using further commands executed via Velociraptor's spawned shells.
8. The final objective is achieved, such as data theft, system disruption, or ransomware deployment.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on compromised Windows systems, leading to data theft, system compromise, and potential lateral movement within the network. The use of Velociraptor makes detection challenging, as the activity blends in with legitimate system administration tasks. The scope of impact depends on the level of access gained and the attacker's objectives. While specific victim numbers are unknown, observed use alongside CVE-2025-26399 suggests widespread potential.

## Recommendation

*   Enable Sysmon process creation logging to capture the execution of shell processes and their command lines, allowing for detection of malicious activity (Data Source: Sysmon).
*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious shell executions spawned by Velociraptor, and tune for your specific environment.
*   Investigate any instances of Velociraptor installations from unusual paths (e.g., temp directories) to identify potentially unauthorized deployments (see Overview).
*   Monitor network connections originating from Velociraptor processes for suspicious destinations or unusual protocols, indicating potential data exfiltration or C2 communication.
*   Patch CVE-2025-26399 on affected SolarWinds Web Help Desk instances (see References).
