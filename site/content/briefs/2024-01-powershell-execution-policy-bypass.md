---
title: PowerShell Execution Policy Bypass Detection
slug: 2024-01-powershell-execution-policy-bypass
description: The analytic detects PowerShell processes using command-line parameters to bypass the execution policy, often used by attackers to run malicious scripts undetected, leading to potential code execution, data exfiltration, or persistence.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - powershell
  - execution-policy-bypass
  - execution
vendors:
  - Microsoft
products:
  - PowerShell
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
rules:
  - title: Malicious PowerShell Execution Policy Bypass
    description: Detects PowerShell processes initiated with parameters that bypass the execution policy.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious PowerShell Process with Shortened Execution Policy Bypass
    description: Detects PowerShell processes initiated with shortened parameters to bypass the execution policy.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies PowerShell processes initiated with parameters designed to bypass the local execution policy, such as `-ex` or `bypass`. Attackers frequently employ this tactic to execute malicious scripts without triggering security restrictions. Bypassing the execution policy allows unauthorized scripts to run, potentially leading to arbitrary code execution, system compromise, data exfiltration, or establishing persistent access within the targeted environment. The detection uses data from Endpoint Detection and Response (EDR) agents to analyze process command lines and identify instances where execution policies are circumvented. This technique is observed across various threat actors and malware families, including those detailed in DHS Report TA18-074A, Volt Typhoon, HAFNIUM, AsyncRAT, and MuddyWater campaigns, highlighting the broad utility and persistent relevance of this bypass.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access via an unknown method, potentially through phishing or exploiting a vulnerability.
2.  **Privilege Escalation (if needed):** The attacker attempts to elevate privileges using exploits or misconfigurations.
3.  **PowerShell Invocation:** The attacker invokes PowerShell.exe to run malicious commands or scripts.
4.  **Execution Policy Bypass:** The attacker uses command-line parameters such as `-ExecutionPolicy Bypass`, `-ep Bypass`, or `-ex Bypass` to circumvent local execution policy restrictions.
5.  **Malicious Script Execution:** The PowerShell script downloads and executes a payload or performs malicious actions directly in memory.
6.  **Credential Access:** The attacker leverages PowerShell to access credentials stored on the system or within the Active Directory environment, using tools like PowerSploit's `Invoke-Mimikatz.ps1`.
7.  **Lateral Movement:** Using compromised credentials, the attacker moves laterally to other systems on the network via SMB/Windows Admin Shares.
8.  **Persistence/Data Exfiltration:** Depending on the objective, the attacker establishes persistence through scheduled tasks or registry modifications, exfiltrates sensitive data, or deploys ransomware.

## Impact

A successful PowerShell execution policy bypass can result in complete system compromise. Observed impacts range from data theft to ransomware deployment, potentially affecting entire organizations. The consequences of this attack include the execution of arbitrary code, unauthorized access to sensitive data, and the establishment of persistent backdoors. The wide adoption of PowerShell in enterprise environments makes this a critical attack vector, allowing attackers to leverage legitimate tools for malicious purposes. Specific campaigns like Volt Typhoon have used similar techniques to target US critical infrastructure.

## Recommendation

*   Deploy the Sigma rule `Malicious PowerShell Execution Policy Bypass` to your SIEM to detect instances of this behavior and tune for your environment.
*   Review and restrict PowerShell execution policies within your environment to limit the ability of attackers to bypass these security controls (reference: detection description).
*   Investigate any instances where PowerShell is invoked with bypass parameters, even if the script appears legitimate at first glance (reference: `known_false_positives` section).
*   Enable Sysmon EventID 1 and Windows Event Log Security 4688 to ensure complete command-line auditing for PowerShell processes (reference: `data_source` section).
*   Map your EDR logs to the Endpoint data model to ensure compatibility with this and other endpoint-focused detections (reference: `how_to_implement` section).
