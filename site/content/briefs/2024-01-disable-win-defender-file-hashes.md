---
title: Windows Defender File Hash Computation Disabled via Registry Modification
slug: 2024-01-disable-win-defender-file-hashes
description: Attackers may disable Windows Defender's ability to compute file hashes by modifying the EnableFileHashComputation registry value, impairing its malware detection capabilities.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - windows-defender
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Detect Windows Defender File Hash Disable via Registry
    description: Detects modifications to the Windows registry that disable Windows Defender's file hash computation by setting the EnableFileHashComputation value to 0.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Process Modifying Windows Defender Registry Key
    description: Detects processes that are modifying the Windows Defender registry key related to file hash computation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can disable Windows Defender's ability to detect and scan for malware by modifying specific registry settings. This involves setting the `EnableFileHashComputation` value to 0 within the Windows Defender registry path. Disabling this feature significantly impairs Windows Defender's capabilities, allowing attackers to bypass security measures and potentially execute undetected malware. This technique is particularly relevant as attackers continuously seek ways to evade traditional endpoint detection and response (EDR) systems. Disabling file hash computation hinders Defender's ability to identify malicious files based on their known hash values, making it harder to detect and prevent malware execution. This registry modification is a critical behavior to monitor, as it can be an early indicator of a compromised system or an attempted defense evasion tactic.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the target system, possibly through phishing, exploitation of vulnerabilities, or compromised credentials.
2.  **Privilege Escalation (if needed):** The attacker escalates privileges to gain the necessary permissions to modify the Windows Registry.
3.  **Identify Target Registry Key:** The attacker identifies the specific registry key responsible for controlling Windows Defender's file hash computation: `HKLM\SOFTWARE\Microsoft\Windows Defender\MpEngine\EnableFileHashComputation`.
4.  **Modify Registry Value:** The attacker modifies the `EnableFileHashComputation` registry value to 0. This can be achieved through various tools, including `reg.exe`, PowerShell, or other scripting languages.
5.  **Verify Modification:** The attacker verifies that the registry value has been successfully modified.
6.  **Execute Malicious Code:** With file hash computation disabled, the attacker executes malicious code that would otherwise be detected by Windows Defender.
7.  **Maintain Persistence:** The attacker establishes persistence to maintain access to the compromised system.
8.  **Lateral Movement:** The attacker moves laterally to other systems on the network, repeating the process if necessary.

## Impact

Disabling Windows Defender's file hash computation can significantly impact an organization's security posture. If successful, attackers can execute malware undetected, leading to data breaches, system compromise, and financial losses. The impact is amplified if attackers can disable this feature across multiple systems within the network. This technique is a critical component of defense evasion, as it allows malicious actors to operate with impunity on compromised systems.

## Recommendation

*   Deploy the Sigma rule `Detect Windows Defender File Hash Disable via Registry` to your SIEM and tune for your environment to detect the modification of the `EnableFileHashComputation` registry value.
*   Enable Sysmon Event ID 13 to ensure registry modification events are logged for the Sigma rule to function correctly.
*   Investigate any alerts triggered by the Sigma rule to determine the legitimacy of the registry modification and identify potential malicious activity.
*   Implement strict access controls to prevent unauthorized modifications to the Windows Registry.
*   Monitor for unexpected or unauthorized use of command-line tools like `reg.exe` and PowerShell to detect potential attempts to modify the registry.
*   Block the domains and URLs listed in the references to prevent downloading malicious tools.
