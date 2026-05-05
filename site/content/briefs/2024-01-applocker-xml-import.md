---
title: Suspicious AppLocker XML Policy Import via PowerShell
slug: 2024-01-applocker-xml-import
description: Detection of PowerShell commands used to import AppLocker XML policies, potentially indicating an attempt to bypass security controls, as observed with Azorult malware.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - applocker
  - defense-evasion
  - powershell
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_impair_defense_add_xml_applocker_rules.yml
rules:
  - title: Detect AppLocker Policy Import via PowerShell
    description: Detects the use of PowerShell to import AppLocker XML policies, a technique used to weaken endpoint defenses.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect AppLocker Policy Import via Cmd
    description: Detects the use of cmd.exe to execute powershell commands to import AppLocker XML policies
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on detecting the suspicious use of PowerShell to import AppLocker XML policies. Attackers may leverage this technique to impair defenses by modifying AppLocker policies to allow malicious executables or scripts to run, bypassing existing security measures. The observed behavior involves the use of "Import-Module Applocker" and "Set-AppLockerPolicy" commands combined with the "-XMLPolicy" parameter. This activity has been linked to malware such as Azorult, where adversaries attempt to weaken endpoint security to facilitate further compromise. Defenders should prioritize monitoring for this behavior, as successful manipulation of AppLocker policies can lead to significant security breaches and persistent access for malicious actors.

## Attack Chain

1.  The attacker gains initial access to the system (details of initial access are not provided in the source).
2.  The attacker executes PowerShell.exe.
3.  The attacker imports the AppLocker module using `Import-Module Applocker`.
4.  The attacker uses the `Set-AppLockerPolicy` cmdlet with the `-XMLPolicy` parameter to specify a path to a malicious AppLocker XML policy file.
5.  The malicious AppLocker policy is applied, potentially whitelisting attacker-controlled files or paths.
6.  The attacker executes previously blocked malicious code, leveraging the modified AppLocker policy.
7.  The attacker achieves persistence and further compromises the system.

## Impact

Successful execution of this attack allows adversaries to impair endpoint defenses by modifying AppLocker policies. This can lead to the execution of malware that would otherwise be blocked. The observed behavior has been linked to the Azorult malware family. The compromise of endpoint security can allow for persistence, data exfiltration, and further lateral movement within the network.

## Recommendation

*   Deploy the Sigma rule `Detect AppLocker Policy Import via PowerShell` to your SIEM to detect suspicious AppLocker policy modifications.
*   Enable Sysmon Event ID 1 and Windows Event Log Security 4688 to provide the necessary process creation and command-line auditing for the Sigma rule.
*   Investigate any instances where `Import-Module Applocker` and `Set-AppLockerPolicy` are used together, especially when the `-XMLPolicy` parameter is present.
*   Review existing AppLocker policies for unexpected or unauthorized modifications.
