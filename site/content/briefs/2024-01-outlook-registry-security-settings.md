---
title: Outlook Security Settings Registry Modification
slug: 2024-01-outlook-registry-security-settings
description: Attackers modify Outlook security settings via registry changes to enable malicious mail rules and bypass security controls, potentially leading to persistence and data compromise.
date: "2024-01-03T18:15:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - registry_modification
  - outlook
  - email
vendors:
  - Microsoft
products:
  - Microsoft Outlook
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1137/T1137.md
  - https://learn.microsoft.com/en-us/outlook/troubleshoot/security/information-about-email-security-settings
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_security_settings.yml
rules:
  - title: Outlook Security Settings Modification via Process
    description: Detects changes to Outlook security settings in the registry made by suspicious processes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Modifying Outlook Security Registry Keys
    description: This rule detects suspicious processes modifying Outlook security-related registry keys, indicating potential attempts to weaken security controls.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers are known to modify Outlook security settings by directly manipulating registry values. This tactic allows them to bypass built-in security controls and enable potentially malicious functionalities such as running unsafe mail client rules. This circumvention of security measures can be leveraged for various malicious purposes, including persistence, data exfiltration, and further compromise of the victim's system. The specific registry keys targeted reside under `\SOFTWARE\Microsoft\Office\Outlook\Security\`. This technique has been observed in various attack scenarios and poses a significant risk to organizations relying on Outlook for email communication. The modification of these registry settings may be performed by various means, ranging from manually executed commands to automated scripts deployed as part of a larger attack campaign.

## Attack Chain

1. An attacker gains initial access to the system through methods such as phishing or exploiting vulnerabilities.
2. The attacker establishes persistence on the compromised system.
3. The attacker identifies the specific registry keys controlling Outlook security settings, located under `\SOFTWARE\Microsoft\Office\Outlook\Security\`.
4. The attacker uses a command-line tool or script (e.g., `reg.exe`, PowerShell) to modify the registry values related to Outlook security settings.
5. Specifically, values are modified to enable the execution of "unsafe" mail client rules, potentially allowing arbitrary code execution via crafted emails.
6. The attacker crafts a malicious email designed to trigger the newly enabled, unsafe mail rules.
7. Upon receiving the email, Outlook processes the rules, executing the attacker's payload.
8. The attacker achieves code execution, enabling further malicious activities, such as data exfiltration or lateral movement within the network.

## Impact

Successful modification of Outlook security settings allows attackers to execute arbitrary code within the context of the user account running Outlook. This can lead to the compromise of sensitive information contained within emails, the installation of malware, and further propagation of the attack throughout the organization. The scope of the impact depends on the privileges of the user account and the attacker's objectives, potentially affecting all users within an organization if the attacker gains domain administrator access.

## Recommendation

*   Deploy the Sigma rule "Outlook Security Settings Updated - Registry" to your SIEM to detect unauthorized modifications to Outlook security-related registry keys (logsource: registry_set/windows).
*   Monitor process creation events for suspicious processes (e.g., `reg.exe`, `powershell.exe`) modifying registry keys under `\SOFTWARE\Microsoft\Office\Outlook\Security\` (Sigma rule below, logsource: process_creation/windows).
*   Implement strict application control policies to prevent unauthorized execution of scripts and executables that could be used to modify registry settings.
