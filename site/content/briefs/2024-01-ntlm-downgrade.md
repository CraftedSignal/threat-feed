---
title: Potential NetNTLMv1 Downgrade Attack via Registry Modification
slug: 2024-01-ntlm-downgrade
description: Attackers modify the Windows registry to weaken NTLM authentication, forcing a downgrade to the less secure NTLMv1 protocol, potentially leading to credential compromise.
date: "2024-01-26T17:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ntlm
  - downgrade
  - registry
  - defense-evasion
  - credential-access
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
rules:
  - title: Detect NTLM Compatibility Level Downgrade via Registry
    description: Detects modifications to the LmCompatibilityLevel registry key, which can indicate an attempt to downgrade NTLM authentication.
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
  - title: Detect NTLM Compatibility Level Downgrade via Registry (Winlogon)
    description: Detects modifications to the LmCompatibilityLevel registry key under Winlogon, which can indicate an attempt to downgrade NTLM authentication.
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
rules_count: 2
---

This threat involves the modification of the Windows registry to force a fallback to the outdated and less secure NTLMv1 authentication protocol. Attackers with local administrator privileges can modify the `LmCompatibilityLevel` registry value, effectively weakening the system's authentication mechanisms. This is often referred to as a "NetNTLMv1 downgrade attack." The modification allows attackers to potentially capture and crack NTLMv1 hashes, leading to credential compromise. This technique is a form of defense evasion that aims to bypass more robust security measures and gain unauthorized access. Defenders should monitor registry modifications related to NTLM settings and investigate any suspicious changes.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to the system, typically requiring local administrator privileges.
2. **Privilege Escalation (If Necessary):** If the attacker does not already have local administrator privileges, they may attempt to escalate privileges using various techniques.
3. **Registry Modification:** The attacker modifies the `LmCompatibilityLevel` registry value located in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` or `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`.
4. **NTLM Downgrade:** By setting the `LmCompatibilityLevel` value to `0`, `1`, or `2` (or their hexadecimal equivalents), the system is configured to allow or require the use of NTLMv1.
5. **Network Sniffing/Interception:** The attacker may then use network sniffing tools to capture NTLMv1 authentication traffic.
6. **Credential Theft:** The captured NTLMv1 hashes are then cracked using offline cracking tools, potentially revealing user credentials.
7. **Lateral Movement:** With compromised credentials, the attacker can then attempt to move laterally within the network to access other systems and resources.

## Impact

A successful NetNTLMv1 downgrade attack can lead to the compromise of user credentials, allowing attackers to gain unauthorized access to sensitive data and systems. This can result in data breaches, financial loss, and reputational damage. The impact is heightened if domain administrator accounts are compromised, potentially granting the attacker control over the entire domain. Organizations with lax NTLM configuration policies are particularly vulnerable.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect suspicious registry modifications related to NTLM settings.
*   Regularly audit the `LmCompatibilityLevel` registry value across your Windows systems to ensure it is set to a secure value (3 or higher).
*   Implement multi-factor authentication (MFA) to mitigate the impact of credential compromise.
*   Enable Sysmon registry event logging to activate the rules below.
*   Block the execution of unauthorized programs modifying registry keys via endpoint detection and response (EDR) solutions.
*   Educate users about the risks of weak authentication protocols and the importance of strong passwords.
