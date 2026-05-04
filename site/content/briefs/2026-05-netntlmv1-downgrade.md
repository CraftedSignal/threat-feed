---
title: Potential NetNTLMv1 Downgrade Attack via Registry Modification
slug: 2026-05-netntlmv1-downgrade
description: This brief details a registry modification attack that downgrades the system to NTLMv1 authentication, enabling NetNTLMv1 downgrade attacks, typically performed with local administrator privileges on Windows systems.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - ntlm
  - registry-modification
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - Elastic Endgame
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
  - https://attack.mitre.org/techniques/T1112/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/010/
rules:
  - title: Potential NetNTLMv1 Downgrade Attack
    description: Detects registry modification to force the system to fall back to NTLMv1 for authentication.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
      - T1562.010
    data_sources:
      - registry_set
      - windows
  - title: Potential NetNTLMv1 Downgrade Attack - PowerShell
    description: Detects PowerShell usage to modify the LmCompatibilityLevel registry key to force NTLMv1 downgrade.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
      - T1562.010
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule detects a specific defense evasion technique where an attacker modifies the Windows registry to force a system to use the less secure NTLMv1 authentication protocol. This is known as a NetNTLMv1 downgrade attack. The registry modification involves changing the `LmCompatibilityLevel` value, which controls the authentication level. Attackers with local administrator privileges can perform this modification to weaken the authentication mechanism, making it easier to intercept and crack credentials. The rule is designed to detect this activity by monitoring registry events from various sources, including Elastic Defend, Microsoft Defender XDR, SentinelOne Cloud Funnel, Sysmon, and Crowdstrike. It is important to monitor for this activity as it can lead to credential theft and further compromise of the system.

## Attack Chain

1.  The attacker gains local administrator privileges on a Windows system.
2.  The attacker uses a registry editor or command-line tool (e.g., `reg.exe`, PowerShell) to modify the `LmCompatibilityLevel` value in the registry.
3.  The attacker navigates to one of the following registry paths: `HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` or `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.
4.  The attacker sets the `LmCompatibilityLevel` value to "0", "1", or "2" (or their hexadecimal equivalents "0x00000000", "0x00000001", "0x00000002"). These values force the system to use NTLMv1.
5.  The system now uses NTLMv1 for authentication attempts.
6.  The attacker initiates a man-in-the-middle attack to capture NTLMv1 authentication traffic using tools like Responder or Inveigh.
7.  The captured NTLMv1 hashes are cracked using brute-force or dictionary attacks, revealing the user's credentials.
8.  The attacker uses the compromised credentials to gain unauthorized access to network resources or other systems.

## Impact

A successful NetNTLMv1 downgrade attack can lead to the compromise of user credentials, enabling attackers to move laterally within the network, access sensitive data, and potentially escalate privileges. The impact can range from data breaches to complete system compromise, depending on the attacker's objectives and the compromised user's privileges.

## Recommendation

*   Deploy the Sigma rule "Potential NetNTLMv1 Downgrade Attack" to detect registry modifications setting `LmCompatibilityLevel` to insecure values (0, 1, 2) within the specified registry paths.
*   Enable Sysmon registry event logging to ensure the necessary data is available for the Sigma rule to function correctly.
*   Review registry event logs for unauthorized modifications of `LmCompatibilityLevel` to confirm legitimate administrative actions.
*   Implement strict access control policies to limit local administrator privileges and reduce the attack surface.
*   Monitor the references URL for updates on recommended security configurations related to NTLM authentication.
