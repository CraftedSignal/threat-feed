---
title: Windows Subsystem for Linux Enabled via Dism Utility
slug: 2024-01-wsl-dism-enable
description: Adversaries may enable Windows Subsystem for Linux (WSL) via the Dism utility to evade detection by running Linux tools on Windows.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - wsl
vendors:
  - Microsoft
products:
  - Windows
  - Windows Subsystem for Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://blog.f-secure.com/hunting-for-windows-subsystem-for-linux/
rules:
  - title: Detect WSL Enablement via DISM
    description: Detects attempts to enable Windows Subsystem for Linux (WSL) using the Dism utility.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect WSL Enablement via DISM (PE Original Filename)
    description: Detects attempts to enable Windows Subsystem for Linux (WSL) using the Dism utility by checking the PE Original Filename.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may enable and utilize the Windows Subsystem for Linux (WSL) to evade detection. WSL allows execution of Linux binaries on Windows systems without the overhead of a virtual machine. By enabling WSL via the Dism utility, adversaries can introduce Linux-based tools and scripts into the Windows environment, potentially bypassing standard Windows security controls. The Elastic detection rule identifies attempts to enable WSL by monitoring for the execution of `Dism.exe` and inspecting the command line for the presence of `"Microsoft-Windows-Subsystem-Linux"`. This technique allows attackers to blend in with legitimate system administration activities, making malicious actions more difficult to detect. The rule was last updated on 2026/04/07.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means (e.g., phishing, exploit).
2. The attacker executes `Dism.exe` with elevated privileges.
3. The command line includes the argument to enable the Windows Subsystem for Linux feature: `"Microsoft-Windows-Subsystem-Linux"`.
4. Dism installs the necessary WSL components.
5. The attacker installs a Linux distribution within the WSL environment (e.g., Ubuntu, Kali).
6. The attacker deploys Linux-based tools and scripts within the WSL environment for reconnaissance, lateral movement, or exploitation.
7. The attacker uses these tools to perform malicious activities, such as scanning the network, exploiting vulnerabilities, or exfiltrating data.
8. The attacker maintains persistence by scheduling tasks or modifying startup scripts within the WSL environment.

## Impact

Successful exploitation can lead to a compromised Windows host that is more difficult to detect and remediate. Attackers can leverage Linux-based tools to bypass Windows security controls, potentially leading to data theft, system compromise, or further lateral movement within the network. The lack of visibility into WSL activities can extend dwell time and increase the overall impact of the attack.

## Recommendation

*   Deploy the Sigma rule "Detect WSL Enablement via DISM" to your SIEM and tune for your environment.
*   Enable Sysmon process creation logging to capture the necessary `Dism.exe` execution events to activate the Sigma rules above.
*   Monitor process execution logs for instances of `Dism.exe` with the `"Microsoft-Windows-Subsystem-Linux"` argument.
