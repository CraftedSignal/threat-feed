---
title: Potential Disabling of Windows Defender Antivirus via Registry Modification
slug: 2024-01-27-disable-defender-registry
description: An attacker might attempt to disable Windows Defender Antivirus by modifying specific registry keys, potentially leading to a system vulnerable to malware and other threats.
date: "2024-01-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windowsdefender
  - registry
  - antivirus
  - disable
  - malware
vendors:
  - Microsoft
products:
  - Windows Defender Antivirus
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/disable_defender_antivirus_registry.yml
rules:
  - title: Detect Windows Defender Disabled via Registry Modification
    description: Detects attempts to disable Windows Defender Antivirus by modifying specific registry keys.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Process Modifying Windows Defender Registry Keys
    description: Detects processes attempting to modify Windows Defender related registry keys
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

This brief addresses the potential disabling of Windows Defender Antivirus through modification of specific registry keys. While the provided source material is simply a link to a Splunk detection rule and a GitHub repository, it is important to consider that attackers often attempt to disable or tamper with endpoint detection and response (EDR) solutions to evade detection. This technique involves manipulating registry settings that control the behavior of Windows Defender, potentially rendering the system unprotected against malware. Since the source is a detection rule focused on registry changes related to disabling Defender, we can infer that this behavior has been observed and is considered a security risk. Disabling Defender via registry modifications can be done manually or via automated scripts and tools, allowing attackers to operate undetected.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the system through various means (e.g., phishing, exploiting a vulnerability, or compromised credentials).
2.  **Privilege Escalation (if needed):** The attacker may need to escalate privileges to modify the registry keys. Tools like `PowerShell` or `cmd.exe` with administrative rights are used.
3.  **Identify Target Registry Keys:** The attacker identifies the specific registry keys that control Windows Defender's real-time protection and other security features. These keys are typically located under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`.
4.  **Modify Registry Keys:** The attacker uses tools like `reg.exe` or `PowerShell` to modify the identified registry keys. They might set values to disable real-time monitoring, cloud-delivered protection, or other security features.
5.  **Verify Changes:** The attacker verifies that the registry modifications have taken effect and that Windows Defender's real-time protection is disabled.
6.  **Deploy Malware:** With Defender disabled, the attacker deploys malware or performs other malicious activities without being detected by the antivirus.
7.  **Lateral Movement & Data Exfiltration/Encryption:** The attacker moves laterally within the network, exfiltrates sensitive data, or deploys ransomware to encrypt systems.
8.  **Impact:** The attacker achieves their objective, which may include data theft, financial gain, or disruption of services.

## Impact

Successful disabling of Windows Defender Antivirus can have significant consequences. It renders the affected system vulnerable to malware infections, data breaches, and other security incidents. This can lead to financial losses, reputational damage, and legal liabilities. Organizations in all sectors are at risk, but those handling sensitive data or critical infrastructure are particularly vulnerable. A successful attack can result in widespread system compromise and significant disruption of business operations.

## Recommendation

*   Deploy the Sigma rule provided below to your SIEM to detect suspicious registry modifications related to disabling Windows Defender (see `rules`).
*   Enable Sysmon registry event logging to capture the necessary events for the Sigma rule to function correctly (see `rules`).
*   Monitor process creation events for unusual processes (e.g., `cmd.exe`, `powershell.exe`) modifying registry keys related to Windows Defender (see `rules`).
*   Regularly review and audit registry settings related to Windows Defender to ensure they have not been tampered with.
