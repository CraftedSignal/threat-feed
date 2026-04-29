---
title: PowerShell Execution via Environment Variables
slug: 2024-01-powershell-env-var-execution
description: Adversaries use PowerShell to execute malicious code stored in environment variables, leveraging Invoke-Expression or its aliases to bypass static analysis and execute payloads dynamically, as seen in malware loaders and stagers like the VIP Keylogger.
date: "2024-01-03T10:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - powershell
  - environment-variable
  - invoke-expression
  - execution
vendors:
  - Microsoft
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://docs.microsoft.com/en-us/dotnet/api/system.reflection.assembly?view=net-5.0
  - https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba.
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
  - https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
  - https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/
rules:
  - title: PowerShell Invoke-Expression with Environment Variable
    description: Detects PowerShell scripts that use Invoke-Expression or its alias iex in conjunction with environment variables, indicating potential dynamic code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: PowerShell ScriptBlock Logging - Environment Variable and Invoke-Expression
    description: Detects PowerShell Script Block Logging events (4104) where environment variables are used in conjunction with Invoke-Expression, a technique often used to hide malicious code.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - powershell_script
      - windows
rules_count: 2
---

Attackers are increasingly leveraging PowerShell to execute malicious code embedded within environment variables. This method involves storing commands or encoded content in environment variables and then using `Invoke-Expression` (or its alias `iex`) to dynamically construct and execute code at runtime. This tactic is employed to evade traditional static analysis techniques and conceal the true intent of the executed code. Observed in malware loaders and stagers, including those associated with the VIP Keylogger campaign, this technique is a significant threat. Defenders should be aware of this trend and implement appropriate detection mechanisms. The focus is on identifying PowerShell scripts that combine environment variable access (`$env:`) with `Invoke-Expression` or its aliases, based on PowerShell Script Block Logging (Event ID 4104).

## Attack Chain

1.  The attacker gains initial access to the system, possibly through phishing or exploiting a software vulnerability.
2.  PowerShell is invoked, either directly or indirectly, via a script or another process.
3.  The attacker sets an environment variable containing malicious code or a command. This might involve using `[Environment]::SetEnvironmentVariable`.
4.  A PowerShell script is executed that reads the content of the environment variable using `$env:`.
5.  The content read from the environment variable is passed to `Invoke-Expression` or its alias `iex`.
6.  `Invoke-Expression` dynamically executes the code, effectively bypassing static analysis.
7.  The executed code downloads and executes a secondary payload, such as a keylogger or a remote access tool.
8.  The attacker achieves their objective, such as stealing credentials or establishing persistent access.

## Impact

Successful exploitation can lead to the execution of arbitrary code on the compromised system, allowing attackers to install malware, steal sensitive data, or establish a persistent foothold. The VIP Keylogger campaign, for example, demonstrates how this technique can be used to harvest user credentials. Due to the obfuscated nature of this attack, it is difficult to detect and remediate, often leading to extended dwell time for the attacker. Compromised systems can be further used as a launchpad for attacks against other systems within the network.

## Recommendation

*   Enable PowerShell Script Block Logging (Event ID 4104) on all Windows systems to capture the de-obfuscated script blocks before execution.
*   Deploy the provided Sigma rules to your SIEM to detect PowerShell scripts that access environment variables and use `Invoke-Expression` or its aliases. Tune these rules to your environment to reduce false positives.
*   Investigate any alerts generated by these rules to determine if malicious activity is occurring.
*   Monitor PowerShell execution for suspicious environment variable access and dynamic code execution.
*   Implement application control to prevent the execution of unauthorized PowerShell scripts.
*   Review and harden PowerShell execution policies to limit the attack surface.
