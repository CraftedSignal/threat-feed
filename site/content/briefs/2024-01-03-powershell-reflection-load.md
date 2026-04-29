---
title: PowerShell Loading .NET Assemblies via Reflection
slug: 2024-01-03-powershell-reflection-load
description: This analytic detects PowerShell scripts leveraging .NET reflection to load assemblies into memory, a technique commonly used by threat actors to bypass defenses and execute malicious code.
date: "2024-01-03T10:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - powershell
  - reflection
  - dotnet
  - memory-injection
  - attack.execution
  - attack.t1059.001
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
  - https://docs.microsoft.com/en-us/dotnet/api/system.reflection.assembly?view=net-5.0
  - https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
  - https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
  - https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/
rules:
  - title: PowerShell Assembly LoadFrom via Reflection
    description: Detects PowerShell scripts using LoadFrom to load .NET assemblies via reflection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Assembly Load via Reflection
    description: Detects PowerShell scripts using Assembly.Load to load .NET assemblies via reflection.
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

This threat brief addresses the use of PowerShell to load .NET assemblies into memory using reflection, a technique frequently observed in advanced attacks. Threat actors, including those employing frameworks like Empire and Cobalt Strike, utilize this method to execute code directly in memory, evading traditional file-based security controls. The detection strategy focuses on PowerShell Script Block Logging (EventCode=4104), which captures the full commands executed, enabling analysis for specific reflection-related keywords. This behavior is a strong indicator of potential malicious activity, as it allows for unauthorized code execution, privilege escalation, and persistent access. Defenders should prioritize detection and response to such events to mitigate the risk of compromise. The technique allows attackers to bypass traditional defenses, execute code in memory, and potentially establish persistence within the targeted environment.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the system, possibly through phishing or exploiting a vulnerability.
2.  PowerShell Execution: The attacker executes PowerShell, often obfuscated or encoded, to avoid detection.
3.  Reflection Assembly Loading: The PowerShell script uses reflection techniques, such as `[System.Reflection.Assembly]::Load()`, to load a .NET assembly directly into memory.
4.  Bypassing Security Controls: The in-memory execution bypasses traditional security controls that scan files on disk.
5.  Malicious Code Execution: The loaded assembly contains malicious code, which could be a payload for lateral movement, data exfiltration, or other malicious activities.
6.  Privilege Escalation: The malicious code may attempt to escalate privileges to gain higher-level access to the system.
7.  Persistence: The attacker establishes persistence by creating scheduled tasks or modifying registry keys.
8.  Lateral Movement: The attacker uses the compromised system as a springboard to move laterally within the network, compromising additional systems.

## Impact

Successful exploitation can lead to unauthorized code execution, privilege escalation, and persistent access within the environment. By loading .NET assemblies directly into memory, attackers can bypass traditional file-based security controls, making detection more challenging. This technique is often employed in advanced attacks, potentially affecting numerous systems across the network, leading to significant data breaches and system compromise. While specific victim counts are not available, the impact is considered high due to the potential for widespread damage and data loss.

## Recommendation

*   Enable PowerShell Script Block Logging (EventCode=4104) on all endpoints to capture the full commands executed, as referenced in the description.
*   Deploy the provided Sigma rules to your SIEM to detect PowerShell scripts loading .NET assemblies into memory via reflection.
*   Investigate and remediate any alerts generated by the Sigma rules, prioritizing systems with high-value data or critical functions.
*   Regularly review and update PowerShell execution policies to restrict the execution of unsigned or untrusted scripts.
*   Monitor PowerShell logs for suspicious activity, such as the use of reflection techniques to load assemblies from unusual locations.
*   Consult the references provided, specifically the Microsoft .NET API documentation and the Palantir article on event tracing, to deepen your understanding of the attack techniques and potential mitigations.
